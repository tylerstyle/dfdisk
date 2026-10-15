//! The one acquisition pipeline (§4, D3, R7). Engines only acquire bytes and
//! measure facts; the session validates, identifies, checks safety and the
//! destination, write-protects, records the audit trail, flushes, orchestrates
//! verification, classifies and writes the reports.
//!
//! Order of [`run`] (R7; numbers are the steps of §4):
//! - 1 validate the request (case fields, digests, options, file name length)
//! - 2 identify the source (sysfs/udev probe), refuse an empty one (size 0
//!   or unknown), and compare it with the device the examiner selected and
//!   with `--expect-*`
//! - 3 source safety: dfnix registry by pinned major:minor, system disk,
//!   active swap (R8) and mounts in the source tree, holders, O_EXCL open
//!   held for the whole run (R1)
//! - 4 destination checks, the engine's external tools can be run (I3), then
//!   the first write: output directory and report reservation (R11)
//! - 7 audit "started" (refuses on dfnix if it cannot be written)
//! - 5 write protection, 6 capacity probe (R6) and SMART before (§8)
//! - 8 engine acquire, 9 identity re-check, 10 fsync + cache eviction (an
//!   image file that cannot be fsynced fails the verification)
//! - 11 engine verify and optional second source read, 12 classify
//! - 13 SMART after (rescue), 14 reports, 15 audit "finished" (on every path
//!   after "started"), 16 per-boot audit export
//!
//! Everything that touches the host goes through [`SessionHost`], so tests
//! drive every refusal and outcome with fake probes and a fake engine.
//!
//! `run` returns `Ok(report)` for every outcome once anything was written
//! (Aborted, Incomplete, ... included); `Err` only for refusals and usage
//! errors before the first write, failures that left no output, or a verdict
//! whose report could not be written (the error carries its digests, the
//! audit "finished" record everything the report would have said).

mod check;
mod host;
#[cfg(test)]
mod tests;

pub use self::check::{CheckProblem, CheckReport};
pub use self::host::{find_on_path, parse_proc_swaps, HostSystem, SessionHost, SwapEntry};
pub use crate::engines::progress::ProgressSink;
pub use crate::models::config::EngineKind;
pub use crate::signals::StopFlags;

use crate::discovery::safety::system_reasons_for;
use crate::discovery::writeprotect;
use crate::engines::audit::{self, FinishedGuard, StartedRecord};
use crate::engines::error::{AcquisitionError, ErrorKind};
use crate::engines::preflight::{self, DestinationFacts, DestinationRules, OutputGuard};
use crate::engines::process::StopControl;
use crate::engines::{ddrescue_map, ewf, raw, rescue};
use crate::models::capacity::CapacityInfo;
use crate::models::case::CaseMetadata;
use crate::models::config::{
    AcquisitionConfig, EffectiveConfig, EngineSettings, HashSelection, SmartPolicy,
};
use crate::models::device::{BlockDevice, SmartSnapshot};
use crate::models::identity::{SerialSource, SourceIdentity};
use crate::models::info_report::{
    compare_digest_sets, sync_dir, AuditInfo, AuditStatus, FileDigest, ForensicInfoReport,
    HashResults, IdentityCheck, PiecewiseInfo, ReportFiles, SessionInfo, VerificationInfo,
    INFO_JSON_SUFFIX, INFO_SUFFIX, RESERVE_SUFFIX,
};
use crate::models::outcome::{AcquisitionFacts, ReadErrorTable, VerificationResult};
use crate::models::protection::{RegistryPresence, WriteProtection};
use crate::models::provenance::{ClockInfo, ProvenanceRecorder};
use crate::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use dfcore::sysfs::{parse_dev_num, DevNum};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// An acquisition as the examiner requested it.
#[derive(Debug, Clone)]
pub struct AcquisitionRequest {
    /// The device as selected (scan snapshot); the probe must match it
    pub device: BlockDevice,
    pub case: CaseMetadata,
    pub config: AcquisitionConfig,
    /// Mount points the caller unmounted for this acquisition (audited,
    /// §10), recorded in the report's write protection
    pub unmounted_by_dfdisk: Vec<String>,
}

impl AcquisitionRequest {
    pub fn new(device: BlockDevice, case: CaseMetadata, config: AcquisitionConfig) -> Self {
        Self {
            device,
            case,
            config,
            unmounted_by_dfdisk: Vec::new(),
        }
    }

    pub fn engine(&self) -> EngineKind {
        self.config.engine()
    }
}

/// Everything an engine may read (§4). Engines get `&EngineContext`; they
/// write only `<output_dir>/<base_name>.*` files and report through
/// `progress`, `provenance` and their [`EngineOutput`].
#[derive(Debug)]
pub struct EngineContext {
    pub request: AcquisitionRequest,
    pub engine: EngineKind,
    /// `{case}_{ea}_{evidence}_{serial}`; every output is `<base_name>.<suffix>`
    pub base_name: String,
    pub output_dir: PathBuf,
    /// Path external tools read the source through (R3): the by-diskseq
    /// link when it resolves to the pinned major:minor, else the device path
    pub tool_source_path: String,
    /// The source opened O_RDONLY|O_EXCL, held for the whole run (R1). The
    /// RAW engine reads through a dup ([`dup_source`](Self::dup_source)) with
    /// positioned reads; external tools open `tool_source_path` themselves
    pub source_fd: Option<File>,
    /// Identity probed at the start
    pub identity: SourceIdentity,
    /// The settings the report shows (engines may refine their part through
    /// [`EngineOutput::settings`])
    pub effective: EffectiveConfig,
    /// Digests to compute (E01: MD5 always)
    pub selection: HashSelection,
    pub progress: ProgressSink,
    /// Graceful stop: stop the tool, keep outputs, return `aborted: true`
    pub abort: Arc<AtomicBool>,
    /// Immediate stop (second Ctrl+C): kill external tools at once
    pub force: Arc<AtomicBool>,
    /// Records every command (through `engines::process`) and tool version
    pub provenance: ProvenanceRecorder,
}

impl EngineContext {
    /// A context for `request` (engine tests and tools that run an engine
    /// without the session): effective config, digest selection and output
    /// directory from the request, the source path as tool path, no held
    /// descriptor, a disconnected progress sink, fresh stop flags.
    pub fn new(
        request: AcquisitionRequest,
        identity: SourceIdentity,
        base_name: impl Into<String>,
    ) -> Self {
        let engine = request.engine();
        Self {
            effective: EffectiveConfig::build(&request.config, Some(&identity)),
            selection: HashSelection::for_engine(&request.config),
            output_dir: request.config.output_dir.clone(),
            tool_source_path: identity.path.clone(),
            engine,
            base_name: base_name.into(),
            source_fd: None,
            identity,
            request,
            progress: ProgressSink::disconnected(),
            abort: Arc::new(AtomicBool::new(false)),
            force: Arc::new(AtomicBool::new(false)),
            provenance: ProvenanceRecorder::new(),
        }
    }

    pub fn config(&self) -> &AcquisitionConfig {
        &self.request.config
    }

    pub fn case(&self) -> &CaseMetadata {
        &self.request.case
    }

    /// Size of the source when the run started.
    pub fn expected_bytes(&self) -> u64 {
        self.identity.size_bytes
    }

    /// Logical sector size of the source (at least 512).
    pub fn sector_size(&self) -> u32 {
        self.identity.logical_sector_size.max(512)
    }

    /// `<output_dir>/<base_name><suffix>`, e.g. `output_path(".raw")`.
    pub fn output_path(&self, suffix: &str) -> PathBuf {
        self.output_dir
            .join(format!("{}{}", self.base_name, suffix))
    }

    /// A duplicate of the held source descriptor (shares the file offset:
    /// use positioned reads or seek explicitly).
    pub fn dup_source(&self) -> io::Result<File> {
        match &self.source_fd {
            Some(f) => f.try_clone(),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no source descriptor is held for this run",
            )),
        }
    }

    pub fn is_aborted(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }

    pub fn is_forced(&self) -> bool {
        self.force.load(Ordering::SeqCst)
    }

    /// Abort and force as the process runner's stop control.
    pub fn stop_control(&self) -> StopControl {
        StopControl::abort(self.abort.clone()).with_force(self.force.clone())
    }
}

/// What an engine measured (§4); the session derives the verdict from it.
#[derive(Debug, Clone, Default)]
pub struct EngineOutput {
    /// Bytes of the source represented in the image (read or substituted)
    pub bytes_acquired: u64,
    /// Source size the engine worked with (0: the session uses the probed size)
    pub expected_bytes: u64,
    /// Exact unreadable ranges (sector size 0: the session uses the logical
    /// sector size of the source)
    pub read_errors: ReadErrorTable,
    /// Why the acquisition did not cover the whole source
    pub stop_reason: Option<String>,
    /// Stopped by the examiner or a signal
    pub aborted: bool,
    /// Digests computed while reading the source stream (none for ddrescue)
    pub acquisition_hashes: HashResults,
    /// Image files (segments, the RAW image)
    pub image_files: Vec<PathBuf>,
    /// Auxiliary files the engine wrote (map, tool log, pieces file); the
    /// session hashes and lists them
    pub auxiliary_files: Vec<PathBuf>,
    pub piecewise: Option<PiecewiseInfo>,
    /// Report notes
    pub notes: Vec<String>,
    /// Replaces the engine part of the effective config (e.g. RAW `source_io`)
    pub settings: Option<EngineSettings>,
    /// Earlier sessions of a resumed rescue
    pub resume_sessions: Vec<SessionInfo>,
}

/// Run the engine of `ctx.engine` (dispatch by [`EngineKind`]).
pub async fn acquire(ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
    match ctx.engine {
        EngineKind::Ewf => ewf::acquire(ctx).await,
        EngineKind::Raw => raw::acquire(ctx).await,
        EngineKind::Rescue => rescue::acquire(ctx).await,
    }
}

/// Verify the written image of `out` (after the session's flush and cache
/// eviction): the comparison with the acquisition digests, and the image
/// digests.
pub async fn verify(ctx: &EngineContext, out: &EngineOutput) -> (VerificationResult, HashResults) {
    match ctx.engine {
        EngineKind::Ewf => ewf::verify(ctx, out).await,
        EngineKind::Raw => raw::verify(ctx, out).await,
        EngineKind::Rescue => rescue::verify(ctx, out).await,
    }
}

/// Second read of the first `bytes` of the source through the held
/// descriptor (`--verify-source`), with the selected digests.
pub async fn reread_source(
    ctx: &EngineContext,
    bytes: u64,
) -> Result<HashResults, AcquisitionError> {
    let fd = ctx.dup_source().map_err(|e| {
        AcquisitionError::failed(format!("cannot read the source a second time: {e}"))
    })?;
    let selection = ctx.selection;
    let abort = ctx.abort.clone();
    let sink = ctx.progress.clone();
    let t0 = Instant::now();
    tokio::task::spawn_blocking(move || {
        raw::hash_source(&fd, bytes, selection, &abort, |done| {
            let secs = t0.elapsed().as_secs_f64();
            let speed = if secs > 0.0 { done as f64 / secs } else { 0.0 };
            sink.phase_progress(done, bytes, speed);
        })
    })
    .await
    .map_err(|e| AcquisitionError::failed(format!("the second source read stopped: {e}")))?
}

/// Run an acquisition on this host (§4). `abort` stops it gracefully; the
/// report is still written. CLI and TUI with an
/// [`AbortController`](crate::signals::AbortController) use [`run_with`].
pub async fn run(
    request: AcquisitionRequest,
    progress_tx: mpsc::Sender<ProgressTelemetry>,
    abort: Arc<AtomicBool>,
) -> Result<ForensicInfoReport, AcquisitionError> {
    run_with(
        &HostSystem,
        request,
        progress_tx,
        StopFlags::from_abort(abort),
    )
    .await
}

/// Dry run of steps 1-6 on this host: writes nothing, sets nothing.
pub async fn check(request: AcquisitionRequest) -> CheckReport {
    check_with(&HostSystem, request).await
}

/// [`run`] against any host, with abort and force flags.
pub async fn run_with(
    host: &dyn SessionHost,
    request: AcquisitionRequest,
    progress_tx: mpsc::Sender<ProgressTelemetry>,
    stop: StopFlags,
) -> Result<ForensicInfoReport, AcquisitionError> {
    let sink = ProgressSink::new(progress_tx);
    let result = run_inner(host, request, &sink, &stop).await;
    match &result {
        Ok(report) => {
            sink.finish(
                AcquisitionStatus::Completed,
                Some(report.outcome),
                format!(
                    "{} (exit code {})",
                    report.outcome.label(),
                    report.exit_code
                ),
            )
            .await
        }
        Err(e) => {
            let status = if e.kind == ErrorKind::Aborted {
                AcquisitionStatus::Aborted
            } else {
                AcquisitionStatus::Failed(e.message.clone())
            };
            sink.finish(status, None, format!("{}: {}", e.kind.label(), e.message))
                .await
        }
    }
    result
}

/// [`check`] against any host.
pub async fn check_with(host: &dyn SessionHost, request: AcquisitionRequest) -> CheckReport {
    check::run_check(host, request).await
}

// ---------------------------------------------------------------------------
// Steps 1-4
// ---------------------------------------------------------------------------

/// Step 1 result.
#[derive(Debug, Clone)]
struct Validated {
    engine: EngineKind,
    selection: HashSelection,
    base_name: String,
}

/// Step 1: the request is complete and consistent (usage errors, exit 2).
fn validate(request: &AcquisitionRequest) -> Result<Validated, AcquisitionError> {
    if request.device.path.trim().is_empty() {
        return Err(AcquisitionError::usage("no source device was selected"));
    }
    if request.config.output_dir.as_os_str().is_empty() {
        return Err(AcquisitionError::usage("no output directory was given"));
    }
    request.config.validate().map_err(AcquisitionError::usage)?;
    // E01 holds whole 512-byte sectors only (the identity check pins this
    // size); so does the E01 that --rescue-to-e01 makes of a rescue, and its
    // refusal must come before anything is written (I2)
    match request.engine() {
        EngineKind::Ewf => {
            ewf::check_source_size(request.device.size_bytes).map_err(AcquisitionError::usage)?
        }
        EngineKind::Rescue if request.config.rescue_to_e01 => {
            ewf::check_source_size(request.device.size_bytes)
                .map_err(|e| AcquisitionError::usage(format!("--rescue-to-e01: {e}")))?
        }
        _ => {}
    }
    let base_name = request
        .case
        .base_filename_checked(&request.device.display_serial())
        .map_err(AcquisitionError::usage)?;
    Ok(Validated {
        engine: request.engine(),
        selection: HashSelection::for_engine(&request.config),
        base_name,
    })
}

/// The external programs a run of `config` starts: E01 ewfacquire, ewfinfo
/// and ewfverify; rescue ddrescue (and, with --rescue-to-e01, the libewf
/// programs of the conversion); RAW none.
pub fn required_tools(config: &AcquisitionConfig) -> Vec<&'static str> {
    const LIBEWF: [&str; 3] = ["ewfacquire", "ewfinfo", "ewfverify"];
    match config.engine() {
        EngineKind::Ewf => LIBEWF.to_vec(),
        EngineKind::Rescue if config.rescue_to_e01 => {
            std::iter::once(rescue::DDRESCUE).chain(LIBEWF).collect()
        }
        EngineKind::Rescue => vec![rescue::DDRESCUE],
        EngineKind::Raw => Vec::new(),
    }
}

/// The programs of [`required_tools`] that are not found on PATH.
fn missing_tools(host: &dyn SessionHost, config: &AcquisitionConfig) -> Vec<&'static str> {
    required_tools(config)
        .into_iter()
        .filter(|t| host.find_tool(t).is_none())
        .collect()
}

/// Step 4 (I3): every external program of the engine can be run, so a
/// missing tool fails the run before anything is written, sent to the
/// source or recorded as started (FAILED, exit 4; `check` lists it too).
fn check_tools(host: &dyn SessionHost, config: &AcquisitionConfig) -> Result<(), AcquisitionError> {
    tools_error(config, &missing_tools(host, config))
}

/// The error for the `missing` programs of `config`'s engine (none: Ok).
fn tools_error(config: &AcquisitionConfig, missing: &[&str]) -> Result<(), AcquisitionError> {
    if missing.is_empty() {
        return Ok(());
    }
    let required = required_tools(config);
    Err(AcquisitionError::failed(format!(
        "{} runs {}, but {} {} not installed (not found as an executable on PATH); install ewf-tools and gddrescue (Debian/Ubuntu) or libewf and ddrescue (Nix). Nothing was written and nothing was sent to the source",
        if config.engine() == EngineKind::Rescue && config.rescue_to_e01 {
            "the rescue with --rescue-to-e01".to_string()
        } else {
            format!("the {} engine", config.engine().label())
        },
        required.join(", "),
        missing.join(", "),
        if missing.len() == 1 { "is" } else { "are" }
    )))
}

/// Step 2: probe the source and require it to be the selected device (and
/// the expected one). Returns the identity and the statements for the report.
fn identify(
    host: &dyn SessionHost,
    request: &AcquisitionRequest,
) -> Result<(SourceIdentity, Vec<String>), AcquisitionError> {
    let path = &request.device.path;
    let identity = host.probe_identity(path).map_err(|e| {
        AcquisitionError::refused(format!("the source {path} cannot be identified: {e}"))
    })?;
    // An empty source (no medium in a card reader, a size the kernel could
    // not read) would be "acquired" as an empty, verified image
    if identity.size_bytes == 0 {
        return Err(AcquisitionError::refused(format!(
            "the source {} reports a size of 0 bytes: no medium is present or its size is unknown, so there is nothing to acquire",
            identity.path
        )));
    }
    identity
        .same_attachment(&request.device.device_identity())
        .map_err(AcquisitionError::refused)?;
    identity
        .check_expectations(&request.config.expect)
        .map_err(AcquisitionError::refused)?;
    let mut details = vec![format!(
        "probed at the start: {} ({}), {} bytes, serial {}{}",
        identity.path,
        identity
            .maj_min
            .as_deref()
            .map(|m| format!("major:minor {m}"))
            .unwrap_or_else(|| identity.kind.label()),
        identity.size_bytes,
        identity.serial_with_provenance(),
        identity
            .diskseq
            .map(|s| format!(", diskseq {s}"))
            .unwrap_or_default()
    )];
    details.push("the probe matches the device selected by the examiner".into());
    if !request.config.expect.is_empty() {
        details.push("the probe matches the expected identity (--expect-*)".into());
    }
    Ok((identity, details))
}

/// Step 3 result: what was found, and every refusal (in check order).
#[derive(Debug, Clone)]
struct Safety {
    registry: RegistryPresence,
    write_protection: WriteProtection,
    notes: Vec<String>,
    errors: Vec<AcquisitionError>,
}

/// Step 3 without the exclusive open: registry by pinned device number,
/// system disk, active swap (R8), mounts and holders in the source tree.
fn source_safety(
    host: &dyn SessionHost,
    request: &AcquisitionRequest,
    identity: &SourceIdentity,
) -> Safety {
    let config = &request.config;
    let mut errors = Vec::new();

    let registry = host.registry();
    let presence = match &registry {
        Ok(Some(_)) => RegistryPresence::Present,
        Ok(None) => RegistryPresence::Absent,
        Err(reason) => RegistryPresence::Unreadable {
            reason: reason.clone(),
        },
    };
    if let Err(reason) = &registry {
        errors.push(AcquisitionError::refused(format!(
            "the dfnix protected-device registry exists but cannot be read ({reason}); refusing (fail closed)"
        )));
    }

    let sys = host.sysfs();
    if identity.is_block_device() {
        let pinned = identity.maj_min.as_deref().and_then(parse_dev_num);
        if pinned.is_none() {
            errors.push(AcquisitionError::refused(format!(
                "{} has no major:minor; it cannot be checked against the system disks",
                identity.path
            )));
        }
        match host.lsblk() {
            Err(e) => errors.push(AcquisitionError::refused(format!(
                "cannot list the block devices to check the source against the system disks and the dfnix registry: {e}"
            ))),
            Ok(flat) => {
                let reg = registry.as_ref().ok().and_then(Option::as_ref);
                if let Err(e) =
                    dfcore::protected::check_against(reg, &flat, &identity.canonical_path, pinned)
                {
                    errors.push(AcquisitionError::from(e));
                }
                let reasons = system_reasons_for(&flat, &identity.canonical_path, pinned);
                if !reasons.is_empty() {
                    errors.push(AcquisitionError::refused(format!(
                        "{} is on a disk of the running system ({}); dfdisk never acquires the system it runs on",
                        identity.path,
                        reasons.join("; ")
                    )));
                }
            }
        }
        match host.swaps() {
            Err(e) => errors.push(AcquisitionError::refused(format!(
                "cannot read the active swap areas: {e}"
            ))),
            Ok(swaps) => {
                let tree = writeprotect::source_tree(&sys, identity);
                let devs: Vec<DevNum> = tree.iter().filter_map(|n| sys.dev_of(n)).collect();
                for s in swaps
                    .iter()
                    .filter(|s| s.dev.is_some_and(|d| devs.contains(&d)))
                {
                    errors.push(AcquisitionError::refused(format!(
                        "active swap on the source: {} ({}). dfdisk never runs swapoff itself (it may be this host's own swap); disable that swap area and retry",
                        s.path, s.kind
                    )));
                }
            }
        }
    }

    let write_protection = match host.mountinfo() {
        Ok(mountinfo) => writeprotect::capture_in(
            &sys,
            identity,
            &mountinfo,
            presence.clone(),
            config.write_protect,
        ),
        Err(e) => {
            errors.push(AcquisitionError::refused(format!(
                "cannot read the mount table to check the source for mounts: {e}"
            )));
            WriteProtection {
                policy: config.write_protect,
                dfnix_registry: presence.clone(),
                ..Default::default()
            }
        }
    };
    if !write_protection.mounts_before.is_empty() {
        errors.push(AcquisitionError::refused(format!(
            "the source is mounted ({}); unmount it first (dfdisk unmount, audited). dfdisk never acquires a mounted source",
            write_protection.mounts_before.join(", ")
        )));
    }
    // A holder keeps the source open and may write to it: dm, LVM, md,
    // bcache and LUKS claim it exclusively (the exclusive open would refuse
    // it anyway), a loop device over it does not (L3). There is no override
    if !write_protection.holders.is_empty() {
        errors.push(AcquisitionError::refused(format!(
            "devices are stacked on the source ({}): device-mapper, LVM, md, LUKS or loop devices keep it open and may write to it. Close them first (for example cryptsetup close, vgchange -an, mdadm --stop, losetup -d), then acquire again",
            write_protection.holders.join(", ")
        )));
    }
    Safety {
        registry: presence,
        write_protection,
        notes: Vec::new(),
        errors,
    }
}

/// Step 4 result.
#[derive(Debug, Clone)]
struct Destination {
    facts: DestinationFacts,
    notes: Vec<String>,
    /// Files of an interrupted rescue a resume keeps
    resume_kept: Vec<PathBuf>,
}

/// Step 4 without writing: every destination rule.
fn destination_checks(
    host: &dyn SessionHost,
    request: &AcquisitionRequest,
    identity: &SourceIdentity,
    engine: EngineKind,
    base_name: &str,
) -> Result<Destination, AcquisitionError> {
    let config = &request.config;
    let dir = &config.output_dir;
    let facts = host.destination(dir).map_err(|e| {
        AcquisitionError::refused(format!(
            "cannot inspect the destination {}: {e}",
            dir.display()
        ))
    })?;
    let resume = engine == EngineKind::Rescue && config.resume;
    let mut rules = DestinationRules::new(config, identity.size_bytes);
    let mut resume_identity = Vec::new();
    if resume {
        rules.resumed_image_bytes = preflight::check_resume_files(dir, base_name)?;
        // The map and image must belong to this source (identity at the first start)
        resume_identity = rescue::check_resume_identity(dir, base_name, identity)?;
    }
    let mut notes = vec![format!("destination: {}", facts.summary())];
    notes.extend(resume_identity);
    notes.extend(preflight::evaluate(&rules, &facts)?);
    if identity.is_block_device() {
        if let Some(source) = identity.maj_min.as_deref().and_then(parse_dev_num) {
            preflight::check_not_on_source(
                &host.sysfs().topology(),
                source,
                &identity.path,
                facts.backing_dev(),
                &dir.display().to_string(),
            )?;
        }
    }
    let resume_kept = preflight::check_existing_outputs(
        dir,
        base_name,
        resume,
        Some(Path::new(&identity.canonical_path)),
    )?;
    if resume {
        notes.push(format!(
            "resumed rescue: {} file(s) of the interrupted rescue are continued or kept",
            resume_kept.len()
        ));
    }
    Ok(Destination {
        facts,
        notes,
        resume_kept,
    })
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// Everything known after steps 1-4 and the audit "started" record.
struct Prepared {
    v: Validated,
    identity: SourceIdentity,
    identity_details: Vec<String>,
    safety: Safety,
    destination: Destination,
    effective: EffectiveConfig,
    tool_source_path: String,
    log: PathBuf,
    audit: AuditInfo,
    clock: ClockInfo,
    t0: Instant,
}

async fn run_inner(
    host: &dyn SessionHost,
    request: AcquisitionRequest,
    sink: &ProgressSink,
    stop: &StopFlags,
) -> Result<ForensicInfoReport, AcquisitionError> {
    let t0 = Instant::now();
    let clock = host.clock().await;
    sink.phase(
        AcquisitionStatus::Preparing,
        "Checking the request, the source and the destination",
    );

    // 1-4: nothing is written before all of them passed
    let v = validate(&request)?;
    let PreStart {
        identity,
        identity_details,
        safety,
        source_fd,
        destination,
        effective,
        tool_source_path,
        mut output,
    } = match pre_start(host, &request, &v, sink, stop) {
        Ok(p) => p,
        Err((e, device)) => {
            // A refused attempt is in the audit log; nothing else is written
            if e.kind == ErrorKind::Refused {
                if let Err(reason) = audit::refused(&host.audit_log(), *device, v.engine, &e) {
                    sink.warn(format!(
                        "the refusal was not recorded in the audit log: {reason}"
                    ));
                }
            }
            return Err(e);
        }
    };
    let dir = request.config.output_dir.clone();

    // 7 (R7): recorded before anything is sent to the source
    let log = host.audit_log();
    let audit_info = audit::started(
        &log,
        &StartedRecord {
            engine: v.engine,
            identity: &identity,
            case: &request.case,
            effective: &effective,
            output_dir: &dir,
            base_name: &v.base_name,
            tool_source_path: &tool_source_path,
            destination: Some(&destination.facts),
            registry: &safety.registry,
        },
    )?;
    if let AuditStatus::NotWritten { reason } = &audit_info.status {
        sink.warn(format!("audit log not written: {reason}"));
    }
    let guard = FinishedGuard::new(
        &log,
        identity.device_identity(),
        v.engine,
        audit_info.anchor.clone(),
        sink.clone(),
    );

    let prepared = Prepared {
        v,
        identity,
        identity_details,
        safety,
        destination,
        effective,
        tool_source_path,
        log: log.clone(),
        audit: audit_info,
        clock,
        t0,
    };
    match acquire_phase(host, request, prepared, source_fd, sink, stop, &mut output).await {
        Ok((report, Err(e))) => {
            // A verdict without a report: the finished record keeps what the
            // report would have said (digests, read errors, files), and the
            // error message carries the digests to the examiner (T3)
            output.keep();
            let _ = guard.report_not_written(&report, &e);
            Err(e)
        }
        Ok((report, Ok(files))) => {
            output.keep();
            let _ = guard.report(&report, &files);
            // 16: the case directory's copy now includes the finished record
            if let Some(expected) = &report.audit.export_file {
                match host.export_audit(&log, &dir) {
                    Ok(path) if path.to_string_lossy() == expected.as_str() => {}
                    Ok(path) => sink.warn(format!(
                        "the audit log was copied to {} instead of {expected}",
                        path.display()
                    )),
                    Err(e) => sink.warn(format!(
                        "the audit log copy {expected} was not updated with the finished record: {e}"
                    )),
                }
            }
            Ok(report)
        }
        Err(e) => {
            if output_written(&dir, output.base(), &[]) {
                output.keep();
            }
            let _ = guard.error(&e);
            Err(e)
        }
    }
}

/// Steps 2-4 and the first write.
struct PreStart {
    identity: SourceIdentity,
    identity_details: Vec<String>,
    safety: Safety,
    source_fd: File,
    destination: Destination,
    effective: EffectiveConfig,
    tool_source_path: String,
    output: OutputGuard,
}

/// Steps 2-4, then the output directory and reservation. An error comes with
/// the identity to record it under (probed, else as selected).
fn pre_start(
    host: &dyn SessionHost,
    request: &AcquisitionRequest,
    v: &Validated,
    sink: &ProgressSink,
    stop: &StopFlags,
) -> Result<PreStart, (AcquisitionError, Box<dfcore::lsblk::DeviceIdentity>)> {
    let (identity, identity_details) =
        identify(host, request).map_err(|e| (e, Box::new(request.device.device_identity())))?;
    let as_probed = |e: AcquisitionError| (e, Box::new(identity.device_identity()));
    sink.log(format!(
        "Source: {} {} ({} bytes), serial {}",
        identity.path,
        identity.display_name(),
        identity.size_bytes,
        identity.serial_with_provenance()
    ));
    let safety = source_safety(host, request, &identity);
    if let Some(e) = safety.errors.first() {
        return Err(as_probed(e.clone()));
    }
    let source_fd = host.open_source(&identity).map_err(as_probed)?;
    let destination =
        destination_checks(host, request, &identity, v.engine, &v.base_name).map_err(as_probed)?;
    // I3: a missing tool fails before the first write and before "started"
    // (after the refusals, which are the more important answer)
    check_tools(host, &request.config).map_err(as_probed)?;
    let effective = EffectiveConfig::build(&request.config, Some(&identity));
    let tool_source_path = host.tool_source_path(&identity);
    if stop.is_aborted() {
        return Err(as_probed(AcquisitionError::aborted(
            "aborted before anything was written",
        )));
    }
    let resume = v.engine == EngineKind::Rescue && request.config.resume;
    let output = preflight::prepare_output(&request.config.output_dir, &v.base_name, resume)
        .map_err(as_probed)?;
    Ok(PreStart {
        identity,
        identity_details,
        safety,
        source_fd,
        destination,
        effective,
        tool_source_path,
        output,
    })
}

/// Whether `dir` holds an output of `base` other than the reservation and
/// the files in `except`.
fn output_written(dir: &Path, base: &str, except: &[PathBuf]) -> bool {
    !new_outputs(dir, base, except).is_empty()
}

/// Outputs of `base` in `dir` except the reservation and `except`.
fn new_outputs(dir: &Path, base: &str, except: &[PathBuf]) -> Vec<PathBuf> {
    preflight::existing_outputs(dir, base)
        .into_iter()
        .filter(|p| {
            let reserve = p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().to_lowercase().ends_with(RESERVE_SUFFIX));
            !reserve && !except.contains(p)
        })
        .collect()
}

/// Whether `path` is an image file `engine` writes (R-1): `<base>.raw` for
/// RAW and rescue, EWF segments (`.E01`, ..., `.EAA`, ..., `.FAA`, ...) for
/// E01. Reports, kept session reports, maps, identity records, tool logs,
/// pieces and SMART files are never images.
fn is_image_file(engine: EngineKind, base: &str, path: &Path) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    match engine {
        EngineKind::Raw | EngineKind::Rescue => name == format!("{base}{}", rescue::IMAGE_SUFFIX),
        EngineKind::Ewf => {
            ewf::is_ewf_segment(base, &name)
                && name
                    .get(base.len() + 1..)
                    .and_then(|ext| ext.bytes().next())
                    .is_some_and(|b| b.is_ascii_alphabetic())
        }
    }
}

/// The engine failed (`Err`). A refusal stands as it is (the engine decided
/// the run must not happen; nothing it kept is a result). Otherwise, when it
/// wrote anything, the run still gets a report (stop reason = the error, or
/// aborted) that lists the image files of this engine as images and every
/// other file it left (map, identity record, tool log, kept reports) as
/// auxiliary files; when it wrote nothing, the error stands.
fn engine_error_output(
    ctx: &EngineContext,
    err: AcquisitionError,
    preexisting: &[PathBuf],
    session_files: &[PathBuf],
) -> Result<EngineOutput, AcquisitionError> {
    if err.kind == ErrorKind::Refused {
        return Err(err);
    }
    let written = new_outputs(&ctx.output_dir, &ctx.base_name, preexisting);
    if written.is_empty() {
        return Err(err);
    }
    let aborted = err.kind == ErrorKind::Aborted || ctx.is_aborted();
    // The reports about to be written are not files of the engine
    let reports = [
        format!("{}{INFO_SUFFIX}", ctx.base_name),
        format!("{}{INFO_JSON_SUFFIX}", ctx.base_name),
    ];
    let (image_files, auxiliary_files): (Vec<PathBuf>, Vec<PathBuf>) = written
        .into_iter()
        .filter(|p| !session_files.contains(p))
        .chain(preexisting.iter().cloned())
        .filter(|p| {
            p.file_name()
                .is_none_or(|n| !reports.iter().any(|r| n.to_string_lossy() == r.as_str()))
        })
        .partition(|p| is_image_file(ctx.engine, &ctx.base_name, p));
    let mut out = EngineOutput {
        expected_bytes: ctx.expected_bytes(),
        read_errors: ReadErrorTable::new(ctx.sector_size(), "engine stopped with an error"),
        aborted,
        image_files,
        auxiliary_files,
        ..Default::default()
    };
    if !aborted {
        out.stop_reason = Some(format!(
            "the {} engine failed: {}",
            ctx.engine.label(),
            err.message
        ));
    }
    out.notes.push(format!(
        "the engine ended with an error ({}): {}; the files it left are kept and listed, and the number of bytes acquired is not known (0 is recorded)",
        err.kind.label(),
        err.message
    ));
    if out.image_files.is_empty() {
        out.notes
            .push("the engine left no image file; only its other files are listed".into());
    }
    Ok(out)
}

/// Bytes of the source a resumed rescue had already rescued before this
/// session (from the map and image it continues; read or bad sectors that
/// are in the image), `None` when the map cannot be read.
fn rescued_before_resume(dir: &Path, base: &str, expected: u64, sector_size: u32) -> Option<u64> {
    let map = ddrescue_map::read(&dir.join(format!("{base}{}", rescue::MAP_SUFFIX))).ok()?;
    let image_len = std::fs::metadata(dir.join(format!("{base}{}", rescue::IMAGE_SUFFIX)))
        .map(|m| m.len())
        .unwrap_or(0);
    Some(map.assess(expected, image_len, sector_size).bytes_acquired)
}

/// Step 9: the source is still the device probed at the start.
fn recheck_identity(
    host: &dyn SessionHost,
    start: &SourceIdentity,
) -> (Option<SourceIdentity>, bool, String) {
    match host.probe_identity(&start.path) {
        Ok(now) => match now.same_attachment_as(start) {
            Ok(()) => (
                Some(now),
                true,
                "probed at the end: the same device attachment".into(),
            ),
            Err(diff) => (Some(now), false, format!("probed at the end: {diff}")),
        },
        Err(e) => (
            None,
            false,
            format!("the source could not be identified at the end (removed or changed?): {e}"),
        ),
    }
}

/// What step 10 did to one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileFlush {
    pub path: PathBuf,
    /// The file could not be opened or fsynced: what it holds may not be on
    /// the destination medium
    pub not_durable: Option<String>,
    /// The page-cache eviction failed: a re-read may be served from memory
    pub not_evicted: Option<String>,
}

/// What step 10 did: per file, and the directory fsync.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub files: Vec<FileFlush>,
    /// The directory could not be fsynced: new entries may not be durable
    pub directory: Option<String>,
}

impl FlushReport {
    /// Every problem, one sentence each, in file order.
    pub fn problems(&self) -> Vec<String> {
        self.files
            .iter()
            .flat_map(|f| f.not_durable.iter().chain(f.not_evicted.iter()))
            .chain(self.directory.iter())
            .cloned()
            .collect()
    }
}

/// Step 10: fsync every file, evict it from the page cache (so verification
/// reads the medium), fsync the directory; what happened to each file.
pub fn flush_files(files: &[PathBuf], dir: &Path) -> FlushReport {
    use std::os::unix::io::AsRawFd;
    let mut report = FlushReport::default();
    for f in files {
        let mut result = FileFlush {
            path: f.clone(),
            ..Default::default()
        };
        match File::open(f) {
            Ok(file) => {
                if let Err(e) = file.sync_all() {
                    result.not_durable = Some(format!("fsync of {} failed: {e}", f.display()));
                }
                // SAFETY: advisory call on a descriptor we own
                let rc = unsafe {
                    libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED)
                };
                if rc != 0 {
                    result.not_evicted = Some(format!(
                        "{} could not be evicted from the page cache: {}",
                        f.display(),
                        io::Error::from_raw_os_error(rc)
                    ));
                }
            }
            Err(e) => {
                result.not_durable =
                    Some(format!("{} cannot be opened to flush it: {e}", f.display()))
            }
        }
        report.files.push(result);
    }
    if let Err(e) = sync_dir(dir) {
        report.directory = Some(e.to_string());
    }
    report
}

/// [`flush_files`] as a list of problems (for callers that only note them).
pub fn flush_and_evict(files: &[PathBuf], dir: &Path) -> Vec<String> {
    flush_files(files, dir).problems()
}

/// What step 10 means for the image files (T1): a file that could not be
/// opened or fsynced, or a directory that could not be fsynced, makes the
/// image not durable (verification fails); an eviction failure means the
/// re-read may have come from memory. Problems of other files are notes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ImageFlush {
    not_durable: Vec<String>,
    not_evicted: Vec<String>,
    notes: Vec<String>,
}

impl ImageFlush {
    fn of(flush: &FlushReport, image_files: &[PathBuf]) -> Self {
        let mut r = ImageFlush::default();
        for f in &flush.files {
            let image = image_files.contains(&f.path);
            if let Some(p) = &f.not_durable {
                if image {
                    r.not_durable.push(p.clone());
                } else {
                    r.notes.push(p.clone());
                }
            }
            if let Some(p) = &f.not_evicted {
                if image {
                    r.not_evicted.push(p.clone());
                } else {
                    r.notes.push(p.clone());
                }
            }
        }
        if let Some(p) = &flush.directory {
            if image_files.is_empty() {
                r.notes.push(p.clone());
            } else {
                r.not_durable
                    .push(format!("{p} (the directory entries of the image)"));
            }
        }
        r
    }

    /// The image verification once the flush is taken into account (only
    /// for a verification that ran; an aborted run stays not verified): an
    /// image that is not durable fails verification, also a rescue image
    /// that had nothing to be compared with; a mismatch stays a mismatch.
    fn apply(&self, image: VerificationResult) -> VerificationResult {
        if self.not_durable.is_empty() {
            return image;
        }
        let flush = format!(
            "the image could not be flushed durably to the destination: {}",
            self.not_durable.join("; ")
        );
        match image {
            VerificationResult::Mismatched { .. } => image,
            // The image's own failure stays named next to the flush's
            VerificationResult::Failed { reason } => VerificationResult::Failed {
                reason: format!("{flush}; {reason}"),
            },
            _ => VerificationResult::Failed { reason: flush },
        }
    }
}

/// Why a second source read has nothing to be compared with: no digest was
/// computed while reading the source (ddrescue) and the image could not be
/// hashed.
pub const NOTHING_TO_COMPARE: &str = "nothing to compare with: no digest was computed while reading the source, and the image could not be hashed";

/// The second read of the source compared with what the acquisition
/// measured, labelled by what was compared (R-4): with acquisition digests,
/// a difference means the source changed or reads unstably; without them
/// (ddrescue), the second read is compared with the image, and a difference
/// means the image differs from the source as read again (a damaged image,
/// or a changed or unstable source). A digest missing on the side it is
/// compared with makes the comparison not possible: the second read itself
/// succeeded (N2).
pub fn compare_second_read(
    selection: HashSelection,
    acquisition: &HashResults,
    image: &HashResults,
    reread: &HashResults,
) -> VerificationResult {
    const METHOD: &str = "second read of the source";
    if acquisition.is_empty() && image.is_empty() {
        return VerificationResult::NotPossible {
            reason: NOTHING_TO_COMPARE.into(),
        };
    }
    let (result, cause) = if acquisition.is_empty() {
        (
            compare_digest_sets(selection, ("image", image), ("second read", reread), METHOD),
            "the image differs from the source as read a second time (a damaged image, or a source that changed or reads unstably)",
        )
    } else {
        (
            compare_digest_sets(
                selection,
                ("acquisition", acquisition),
                ("second read", reread),
                METHOD,
            ),
            "the source changed or reads unstably",
        )
    };
    match result {
        VerificationResult::Mismatched { method, details } => VerificationResult::Mismatched {
            method,
            details: format!("{cause}: {details}"),
        },
        VerificationResult::Failed { reason } => VerificationResult::NotPossible {
            reason: format!("nothing to compare with: {reason}"),
        },
        other => other,
    }
}

/// The image verification combined with the second source read: a
/// differing second read is a mismatch (as [`compare_second_read`] labelled
/// it; a failed image re-read is named with it); an image that failed its
/// verification keeps its own reason, with the second read's result
/// appended (N2); otherwise a second read that failed (`Failed` comes only
/// from the read itself) fails the verification, and a matching second
/// read verifies an acquisition whose engine had no stream digest.
pub fn combine_verification(
    image: VerificationResult,
    source_reread: Option<&VerificationResult>,
) -> VerificationResult {
    let Some(reread) = source_reread else {
        return image;
    };
    match (image, reread) {
        (
            VerificationResult::Failed { reason },
            VerificationResult::Mismatched { method, details },
        ) => VerificationResult::Mismatched {
            method: method.clone(),
            details: format!("{details}; the image verification also failed: {reason}"),
        },
        (_, mismatch @ VerificationResult::Mismatched { .. }) => mismatch.clone(),
        (image @ VerificationResult::Mismatched { .. }, _) => image,
        (VerificationResult::Failed { reason }, reread) => VerificationResult::Failed {
            reason: format!("{reason}; second source read: {}", reread.describe()),
        },
        (image, VerificationResult::NotPossible { .. }) => image,
        (_, VerificationResult::Failed { reason }) => VerificationResult::Failed {
            reason: format!("the second source read failed: {reason}"),
        },
        (VerificationResult::NotPossible { .. }, VerificationResult::Matched { method }) => {
            VerificationResult::Matched {
                method: method.clone(),
            }
        }
        (image, VerificationResult::Matched { .. }) => image,
    }
}

/// How the image was verified, stating only what happened: the reader, and
/// whether the image was fsynced and evicted from the page cache first.
fn verification_method(
    engine: EngineKind,
    result: &VerificationResult,
    ran: bool,
    has_image: bool,
    flush: &ImageFlush,
) -> String {
    if !ran {
        return "none: the acquisition was aborted before the verification".to_string();
    }
    let base = match result {
        VerificationResult::Matched { method } | VerificationResult::Mismatched { method, .. } => {
            method.clone()
        }
        _ => match engine {
            EngineKind::Ewf => "ewfverify".to_string(),
            EngineKind::Raw => "image re-read by dfdisk".to_string(),
            EngineKind::Rescue => "image digests computed by dfdisk".to_string(),
        },
    };
    if !has_image {
        base
    } else if !flush.not_durable.is_empty() {
        format!("{base}; the image could not be fsynced to the destination, so the re-read may not show what the destination holds")
    } else if !flush.not_evicted.is_empty() {
        format!("{base}, after fsync of the image; the image could not be evicted from the page cache, so the re-read may have come from memory")
    } else {
        format!("{base}, after fsync and page-cache eviction of the image")
    }
}

/// `<base>.smart-<when>.json`, or `-2`, `-3`, ... when a resumed rescue
/// already has one.
fn smart_json_path(dir: &Path, base: &str, when: &str) -> PathBuf {
    let first = dir.join(format!("{base}.smart-{when}.json"));
    if !first.exists() {
        return first;
    }
    (2..1000)
        .map(|n| dir.join(format!("{base}.smart-{when}-{n}.json")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

async fn smart_snapshot(
    host: &dyn SessionHost,
    identity: &SourceIdentity,
    policy: SmartPolicy,
    json: PathBuf,
    stop: &StopFlags,
    recorder: &ProvenanceRecorder,
) -> Option<SmartSnapshot> {
    if policy == SmartPolicy::Off || !identity.is_block_device() {
        return None;
    }
    host.smart(
        identity,
        policy,
        Some(&json),
        &stop.stop_control(),
        recorder,
    )
    .await
}

/// Steps 5-14.
async fn acquire_phase(
    host: &dyn SessionHost,
    request: AcquisitionRequest,
    p: Prepared,
    source_fd: File,
    sink: &ProgressSink,
    stop: &StopFlags,
    output: &mut OutputGuard,
) -> Result<(ForensicInfoReport, Result<ReportFiles, AcquisitionError>), AcquisitionError> {
    let Prepared {
        v,
        identity,
        identity_details,
        safety,
        destination,
        effective,
        tool_source_path,
        log,
        audit: mut audit_info,
        mut clock,
        t0,
    } = p;
    let config = request.config.clone();
    let dir = config.output_dir.clone();
    let recorder = ProvenanceRecorder::new();
    let mut notes: Vec<String> = destination.notes.clone();
    notes.extend(safety.notes.iter().cloned());
    let mut session_files: Vec<PathBuf> = Vec::new();

    // 5: write protection
    let mut wp = safety.write_protection.clone();
    wp.exclusive_open = identity.is_block_device();
    wp.unmounted_by_dfdisk = request.unmounted_by_dfdisk.clone();
    host.enforce_write_protection(&identity, &mut wp)
        .map_err(AcquisitionError::refused)?;
    sink.log(format!("Write protection: {}", wp.summary()));

    // 6: capacity (R6) and SMART before
    let capacity = if identity.is_block_device() {
        host.capacity(&identity, &stop.stop_control(), &recorder)
            .await
    } else {
        CapacityInfo::not_probed(identity.size_bytes, "the source is a regular file")
    };
    if capacity.hidden_area() == Some(true) {
        let statements = capacity.hidden_area_statements().join("; ");
        if config.refuse_hidden_areas {
            return Err(AcquisitionError::refused(format!(
                "the disk of the source hides sectors from the operating system ({statements}); refused by --refuse-hidden-areas. dfdisk never changes HPA or DCO"
            )));
        }
        sink.warn(format!(
            "HIDDEN AREA: {statements}. These sectors are not part of the image; dfdisk never changes HPA or DCO"
        ));
        notes.push(format!(
            "HIDDEN AREA on the disk of the source: {statements}. The hidden sectors are not part of this image"
        ));
    }
    let start_identity = identity.clone();
    let mut identity = identity;
    let smart_before = smart_snapshot(
        host,
        &identity,
        config.smart,
        smart_json_path(&dir, &v.base_name, "before"),
        stop,
        &recorder,
    )
    .await;
    if let Some(s) = &smart_before {
        if let Some(f) = &s.json_file {
            session_files.push(PathBuf::from(f));
        }
        if let Some(serial) = &s.device_serial {
            identity.add_serial_candidate(serial, SerialSource::SmartctlIdentify);
            if identity.serial != start_identity.serial {
                notes.push(format!(
                    "the drive reported serial {} through IDENTIFY; the file names use {}, the serial of the device as selected",
                    identity.serial.as_deref().unwrap_or("(none)"),
                    request.device.display_serial()
                ));
            }
        }
    }

    // R-7: what earlier sessions of a resumed rescue had rescued, so the
    // average speed counts only this session's bytes
    let resumed_from = (v.engine == EngineKind::Rescue && config.resume).then(|| {
        rescued_before_resume(
            &dir,
            &v.base_name,
            identity.size_bytes,
            identity.logical_sector_size.max(512),
        )
    });

    // 8: the engine
    let ctx = EngineContext {
        request: request.clone(),
        engine: v.engine,
        base_name: v.base_name.clone(),
        output_dir: dir.clone(),
        tool_source_path,
        source_fd: Some(source_fd),
        identity,
        effective: effective.clone(),
        selection: v.selection,
        progress: sink.clone(),
        abort: stop.abort.clone(),
        force: stop.force.clone(),
        provenance: recorder.clone(),
    };
    sink.phase(
        AcquisitionStatus::Acquiring,
        format!("Acquiring with {}", v.engine.label()),
    );
    let mut out = match host.acquire(&ctx).await {
        Ok(out) => out,
        Err(e) => engine_error_output(&ctx, e, &destination.resume_kept, &session_files)?,
    };
    if out.expected_bytes == 0 {
        out.expected_bytes = ctx.expected_bytes();
    }
    if out.read_errors.sector_size == 0 {
        out.read_errors.sector_size = ctx.sector_size();
    }
    if stop.is_aborted() {
        out.aborted = true;
    }

    // 9: still the same device?
    let (identity_at_end, end_ok, end_detail) = recheck_identity(host, &start_identity);
    if !end_ok {
        sink.warn(end_detail.clone());
    }

    // 10: flush and evict
    sink.phase(
        AcquisitionStatus::Flushing,
        "Flushing the image to the destination and evicting it from the page cache",
    );
    let mut written: Vec<PathBuf> = out.image_files.clone();
    written.extend(out.auxiliary_files.iter().cloned());
    written.extend(session_files.iter().cloned());
    let flush = ImageFlush::of(&host.flush(&written, &dir), &out.image_files);
    for problem in flush.not_durable.iter().chain(&flush.not_evicted) {
        sink.warn(problem.clone());
    }
    for problem in &flush.notes {
        sink.warn(problem.clone());
        notes.push(problem.clone());
    }

    // 11: verification and the optional second source read
    let verify_ran = !out.aborted;
    let (image_result, image_hashes) = if out.aborted {
        (
            VerificationResult::NotPossible {
                reason: "the acquisition was aborted; the image was not verified".into(),
            },
            HashResults::default(),
        )
    } else {
        sink.phase(AcquisitionStatus::Verifying, "Verifying the written image");
        host.verify(&ctx, &out).await
    };
    let image_result = if verify_ran {
        flush.apply(image_result)
    } else {
        image_result
    };
    if stop.is_aborted() {
        out.aborted = true;
    }
    let source_reread = if !config.verify_source {
        None
    } else if out.aborted {
        Some(VerificationResult::NotPossible {
            reason: "aborted before the second source read".into(),
        })
    } else if !out.read_errors.is_empty() {
        Some(VerificationResult::NotPossible {
            reason: "the source has unreadable sectors; a second read cannot reproduce the acquisition stream".into(),
        })
    } else if !end_ok {
        Some(VerificationResult::NotPossible {
            reason: "the source changed or disappeared during the acquisition".into(),
        })
    } else if out.acquisition_hashes.is_empty() && image_hashes.is_empty() {
        // N2: a second read would have nothing to be compared with; the
        // source (perhaps a failing drive) is not read again for nothing
        Some(VerificationResult::NotPossible {
            reason: format!("{NOTHING_TO_COMPARE}, so the source was not read a second time"),
        })
    } else {
        sink.phase(
            AcquisitionStatus::SourceReread,
            "Reading the source a second time (--verify-source)",
        );
        match host.reread_source(&ctx, out.bytes_acquired).await {
            Ok(reread) => Some(compare_second_read(
                v.selection,
                &out.acquisition_hashes,
                &image_hashes,
                &reread,
            )),
            Err(e) if e.kind == ErrorKind::Aborted || stop.is_aborted() => {
                out.aborted = true;
                Some(VerificationResult::NotPossible {
                    reason: "the second source read was aborted".into(),
                })
            }
            Err(e) => Some(VerificationResult::Failed { reason: e.message }),
        }
    };
    let method = verification_method(
        v.engine,
        &image_result,
        verify_ran,
        !out.image_files.is_empty(),
        &flush,
    );
    let image_verification = image_result.clone();
    let verification = combine_verification(image_result, source_reread.as_ref());

    // 13: SMART after a rescue
    let smart_after = if v.engine == EngineKind::Rescue && !stop.is_forced() {
        let snap = smart_snapshot(
            host,
            &ctx.identity,
            config.smart,
            smart_json_path(&dir, &v.base_name, "after"),
            stop,
            &recorder,
        )
        .await;
        if let Some(f) = snap.as_ref().and_then(|s| s.json_file.as_ref()) {
            let f = PathBuf::from(f);
            for problem in flush_and_evict(std::slice::from_ref(&f), &dir) {
                notes.push(problem);
            }
            session_files.push(f);
        }
        snap
    } else {
        None
    };

    // 12 + 14: the report
    sink.phase(AcquisitionStatus::Finalizing, "Writing the reports");
    let mut report =
        ForensicInfoReport::new(v.engine, &request.case, ctx.identity.clone(), effective);
    if let Some(settings) = out.settings.take() {
        report.effective_config.settings = settings;
    }
    report.output_dir = dir.to_string_lossy().into_owned();
    report.base_name = v.base_name.clone();
    report.started_at = clock.start_utc;
    let elapsed = t0.elapsed();
    clock.finish(elapsed);
    report.ended_at = clock.end_utc.unwrap_or_else(chrono::Utc::now);
    report.elapsed_seconds = elapsed.as_secs();
    let session_bytes = match resumed_from {
        None => out.bytes_acquired,
        Some(Some(before)) => {
            let added = out.bytes_acquired.saturating_sub(before);
            notes.push(format!(
                "resumed rescue: the average speed counts the {added} bytes this session added to the image over this session's time; earlier sessions had rescued {before} bytes"
            ));
            added
        }
        Some(None) => {
            notes.push(
                "resumed rescue: the bytes earlier sessions rescued are not known (the map could not be read at the start), so the average speed counts every byte in the image over this session's time"
                    .into(),
            );
            out.bytes_acquired
        }
    };
    report.average_speed_bytes_sec = if elapsed.as_secs_f64() > 0.0 {
        session_bytes as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    report.clock = clock;
    report.identity_at_end = identity_at_end;
    let mut details = identity_details;
    details.push(end_detail);
    report.identity_check = IdentityCheck {
        start_ok: true,
        end_ok: Some(end_ok),
        details,
    };
    report.capacity = Some(capacity);
    report.write_protection = Some(wp);
    report.smart_before = smart_before;
    report.smart_after = smart_after;
    report.acquisition_hashes = out.acquisition_hashes.clone();
    report.image_hashes = image_hashes;
    report.verification = VerificationInfo {
        result: verification.clone(),
        method,
        source_reread,
        image: Some(image_verification),
    };
    report.piecewise = out.piecewise.clone();
    report.image_files = out
        .image_files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    for f in out.auxiliary_files.iter().chain(session_files.iter()) {
        match FileDigest::compute(f) {
            Ok(d) => report.auxiliary_files.push(d),
            Err(e) => notes.push(format!("{} could not be hashed: {e}", f.display())),
        }
    }
    let mut provenance = host.provenance();
    recorder.fill(&mut provenance);
    let unversioned: Vec<String> = provenance
        .commands
        .iter()
        .filter_map(|c| c.argv.first())
        .map(|a| {
            Path::new(a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| a.clone())
        })
        .filter(|n| !provenance.tools.contains_key(n))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !unversioned.is_empty() {
        provenance
            .tools
            .extend(host.tool_versions(unversioned).await);
    }
    report.provenance = provenance;
    report.resume_sessions = std::mem::take(&mut out.resume_sessions);
    notes.extend(out.notes.iter().cloned());

    // 16 (first half): the copy of the log in the case directory, named in the report
    if audit_info.status == AuditStatus::Written {
        match host.export_audit(&log, &dir) {
            Ok(path) => audit_info.export_file = Some(path.to_string_lossy().into_owned()),
            Err(e) => notes.push(format!(
                "the audit log was not copied to the case directory: {e}"
            )),
        }
    }
    report.audit = audit_info;
    report.notes = notes;

    // 12: the verdict, from the facts only
    report.apply_facts(&AcquisitionFacts {
        expected_bytes: out.expected_bytes,
        bytes_acquired: out.bytes_acquired,
        read_errors: out.read_errors.clone(),
        stop_reason: out.stop_reason.clone(),
        aborted: out.aborted,
        verification,
        identity_changed: !end_ok,
    });

    output.keep();
    let files = report.write_reports(&dir, &v.base_name).map_err(|e| {
        AcquisitionError::failed(format!(
            "the acquisition ended {} (exit code {}), but its report could not be written to {}: {e}. {} Image files: {}.",
            report.outcome.label(),
            report.exit_code,
            dir.display(),
            report.digest_summary(),
            if report.image_files.is_empty() {
                "(none)".to_string()
            } else {
                report.image_files.join(", ")
            }
        ))
    });
    if let Ok(files) = &files {
        sink.log(format!("Report written: {}", files.text.display()));
    }
    Ok((report, files))
}
