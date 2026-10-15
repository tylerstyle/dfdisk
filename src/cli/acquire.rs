//! `dfdisk acquire` and `dfdisk check` (§15): the flags become an
//! [`AcquisitionRequest`], the session runs it (every safety check lives
//! there, not here), and the CLI prints progress and the report. With
//! `--rescue-to-e01` the rescued image is converted afterwards.

use crate::cli::args::{
    AcquireArgs, AcquisitionOptions, CaseArgs, CheckArgs, CliCompression, CliDigest,
    CliImageFormat, CliOnReadError, CliSmart, CliSplitSize, CliWriteProtect,
};
use crate::cli::console::{Console, ProgressPrinter};
use crate::cli::drive::{drive, next_signal, Activity};
use crate::cli::resolve::{resolve_argument, select_device, ResolvedSource};
use crate::cli::size::{describe_bytes, PieceSize};
use crate::discovery::{identity, safety, writeprotect, DeviceScanner};
use crate::engines::converter;
use crate::engines::session::{self, AcquisitionRequest, HostSystem, SessionHost};
use crate::engines::AcquisitionError;
use crate::models::case::CaseMetadata;
use crate::models::config::{
    AcquisitionConfig, CompressionLevel, EngineKind, ExpectIdentity, OnReadError, SmartPolicy,
    SplitSize, WriteProtectPolicy,
};
use crate::models::conversion::{ConversionReport, ConversionRequest, ConversionTarget};
use crate::models::device::BlockDevice;
use crate::models::identity::SourceKind;
use crate::models::info_report::{ForensicInfoReport, INFO_JSON_SUFFIX, INFO_SUFFIX};
use crate::models::outcome::{exit_code, Outcome, RangeKind};
use crate::signals::{AbortController, SignalAction, SignalListener};
use serde_json::json;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Capacity of the progress channel between an operation and the printer.
const PROGRESS_CHANNEL: usize = 256;

/// Most read-error ranges listed in the E01 notes of `--rescue-to-e01` (the
/// rescue report lists all of them).
const MAX_NOTE_RANGES: usize = 20;

/// Directory below the output directory that receives the E01 of
/// `--rescue-to-e01`, so its files and report never collide with the rescue's.
pub const RESCUE_E01_SUBDIR: &str = "e01";

/// Exit codes from most to least severe: what a run with two verdicts
/// (`--rescue-to-e01`, `verify --pieces`) exits with.
pub const SEVERITY_ORDER: [i32; 10] = [
    exit_code::INTERNAL_ERROR,
    exit_code::USAGE,
    exit_code::ABORTED,
    exit_code::MISMATCH,
    exit_code::FAILED,
    exit_code::REFUSED,
    exit_code::INCOMPLETE,
    exit_code::READ_ERRORS,
    exit_code::UNVERIFIED,
    exit_code::VERIFIED,
];

/// The more severe of two exit codes (see [`SEVERITY_ORDER`]; unknown codes
/// count as internal errors).
pub fn more_severe(a: i32, b: i32) -> i32 {
    let rank = |c: i32| SEVERITY_ORDER.iter().position(|&s| s == c).unwrap_or(0);
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// The case fields exactly as given: nothing is filled in (the EA defaults
/// to "01" by numbering convention, in the model).
pub fn case_from_args(a: &CaseArgs) -> CaseMetadata {
    let opt = |v: &Option<String>| v.clone().unwrap_or_default();
    CaseMetadata {
        case_number: a.case.clone(),
        location_ea: opt(&a.ea),
        evidence_number: a.evidence.clone(),
        authority: opt(&a.authority),
        examiner: a.examiner.clone(),
        description: opt(&a.description),
        notes: opt(&a.notes),
        seal_number: opt(&a.seal),
        seizure_time: opt(&a.seized_at),
        seizure_location: opt(&a.seized_location),
    }
}

/// The engine the options select (rescue wins over the format).
pub fn engine_of(o: &AcquisitionOptions) -> EngineKind {
    if o.rescue {
        EngineKind::Rescue
    } else {
        match o.format.unwrap_or(CliImageFormat::E01) {
            CliImageFormat::E01 => EngineKind::Ewf,
            CliImageFormat::Raw => EngineKind::Raw,
        }
    }
}

pub fn compression_of(c: Option<CliCompression>) -> CompressionLevel {
    match c {
        Some(CliCompression::None) => CompressionLevel::None,
        Some(CliCompression::Fast) | None => CompressionLevel::Fast,
        Some(CliCompression::Best) => CompressionLevel::Best,
    }
}

pub fn split_of(s: Option<CliSplitSize>) -> SplitSize {
    match s {
        Some(CliSplitSize::None) => SplitSize::None,
        Some(CliSplitSize::TwoGb) | None => SplitSize::TwoGb,
        Some(CliSplitSize::FourGb) => SplitSize::FourGb,
    }
}

/// The acquisition configuration of the options. A flag given explicitly for
/// an engine it does not apply to is a usage error (a report never shows a
/// setting that was not applied). The remaining consistency rules are
/// [`AcquisitionConfig::validate`]'s; this does not call it.
pub fn config_from_options(o: &AcquisitionOptions) -> Result<AcquisitionConfig, AcquisitionError> {
    let engine = engine_of(o);
    let mut errors: Vec<&str> = Vec::new();
    if o.rescue && o.format == Some(CliImageFormat::E01) {
        errors.push("--rescue writes a RAW image with GNU ddrescue; add --rescue-to-e01 for an E01 copy instead of --format e01");
    }
    let e01_target = engine == EngineKind::Ewf || (engine == EngineKind::Rescue && o.rescue_to_e01);
    if !e01_target && o.compression.is_some() {
        errors.push("--compression applies to E01 images only (and to --rescue-to-e01)");
    }
    if !e01_target && o.split.is_some() {
        errors.push(
            "--split applies to E01 images only (and to --rescue-to-e01); RAW images are one file",
        );
    }
    if engine == EngineKind::Raw && o.retries.is_some() {
        errors.push("--retries applies to E01 and rescue acquisitions; the RAW engine reads every sector and handles unreadable ones by --on-read-error");
    }
    if engine != EngineKind::Raw && o.on_read_error.is_some() {
        errors.push("--on-read-error applies to the RAW engine only (ewfacquire and ddrescue always zero-fill unreadable sectors)");
    }
    if engine != EngineKind::Raw && o.piece_size.is_some() {
        errors.push("--piece-size applies to the RAW engine only");
    }
    if !errors.is_empty() {
        return Err(AcquisitionError::usage(format!(
            "Inconsistent options: {}",
            errors.join("; ")
        )));
    }
    let output_dir = std::path::absolute(&o.output_dir).map_err(|e| {
        AcquisitionError::usage(format!(
            "invalid output directory {}: {e}",
            o.output_dir.display()
        ))
    })?;
    let mut c = AcquisitionConfig::for_engine(engine, output_dir);
    if engine == EngineKind::Ewf {
        c.compression = compression_of(o.compression);
        c.split_size = split_of(o.split);
    }
    c.calc_md5 = o.digests.contains(&CliDigest::Md5);
    c.calc_sha1 = o.digests.contains(&CliDigest::Sha1);
    c.calc_sha256 = o.digests.contains(&CliDigest::Sha256);
    if let Some(r) = o.retries {
        c.error_retries = r;
    }
    c.ewf_error_granularity = o.error_granularity;
    c.on_read_error = match o.on_read_error {
        Some(CliOnReadError::ZeroFill) => OnReadError::ZeroFill,
        Some(CliOnReadError::Stop) | None => OnReadError::Stop,
    };
    if let Some(PieceSize(p)) = o.piece_size {
        c.piece_size = p;
    }
    c.verify_source = o.verify_source;
    c.smart = match o.smart {
        CliSmart::Off => SmartPolicy::Off,
        CliSmart::Basic => SmartPolicy::Basic,
        CliSmart::Full => SmartPolicy::Full,
    };
    c.write_protect = match o.write_protect {
        CliWriteProtect::Auto => WriteProtectPolicy::Auto,
        CliWriteProtect::Off => WriteProtectPolicy::Off,
    };
    c.allow_holders = o.allow_holders;
    c.allow_tmpfs = o.allow_tmpfs;
    c.allow_low_space = o.allow_low_space;
    c.refuse_hidden_areas = o.refuse_hidden_areas;
    c.expect = ExpectIdentity {
        serial: o.expect_serial.clone(),
        wwn: o.expect_wwn.clone(),
        size: o.expect_size,
    };
    c.resume = o.resume;
    c.rescue_to_e01 = o.rescue_to_e01;
    Ok(c)
}

/// Every usage rule an acquisition is subject to, before anything touches
/// the system: options, required case fields, file-name length.
pub fn validate_acquisition(
    config: &AcquisitionConfig,
    case: &CaseMetadata,
) -> Result<(), AcquisitionError> {
    config.validate().map_err(AcquisitionError::usage)?;
    case.validate_required().map_err(AcquisitionError::usage)?;
    Ok(())
}

/// Lines describing the selected source and the plan (human text).
pub fn selection_lines(
    device: &BlockDevice,
    source: &ResolvedSource,
    config: &AcquisitionConfig,
    base_name: &str,
) -> Vec<String> {
    let mut lines = vec![format!("[+] Source      : {}", device.path)];
    if source.path() != Path::new(&device.path) {
        lines.push(format!("    given as    : {}", source.path().display()));
    }
    if device.kind != SourceKind::RegularFile {
        lines.push(format!(
            "    device      : {} ({}), serial {}",
            device.display_name(),
            device.kind.label(),
            device.serial.as_deref().unwrap_or("(none reported)")
        ));
        if let Some(mm) = &device.maj_min {
            lines.push(format!("    major:minor : {mm}"));
        }
    } else {
        lines.push(format!("    kind        : {}", device.kind.label()));
    }
    lines.push(format!(
        "    size        : {}",
        describe_bytes(device.size_bytes)
    ));
    lines.push(format!("[+] Engine      : {}", config.engine().label()));
    lines.push(format!("[+] Destination : {}", config.output_dir.display()));
    lines.push(format!("    base name   : {base_name}"));
    lines
}

/// Settings of the E01 a `--rescue-to-e01` conversion writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E01Settings {
    pub compression: CompressionLevel,
    pub split_size: SplitSize,
}

impl E01Settings {
    pub fn from_options(o: &AcquisitionOptions) -> Self {
        Self {
            compression: compression_of(o.compression),
            split_size: split_of(o.split),
        }
    }
}

/// How [`execute_acquisition`] prints and what it does afterwards.
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    pub verbose: bool,
    /// E01 settings for `--rescue-to-e01`
    pub e01: E01Settings,
}

/// `dfdisk acquire`.
pub async fn handle_acquire(
    args: AcquireArgs,
    controller: &AbortController,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> Result<i32, AcquisitionError> {
    // Arguments first: nothing on the system is touched for a usage error
    let config = AcquisitionConfig {
        auto_unmount: args.auto_unmount,
        ..config_from_options(&args.options)?
    };
    let case = case_from_args(&args.case);
    validate_acquisition(&config, &case)?;
    let source = resolve_argument(&args.device)?;
    let device = select_device(&source, DeviceScanner::scan_devices)?;
    let base_name = case
        .base_filename_checked(&device.display_serial())
        .map_err(AcquisitionError::usage)?;
    for line in selection_lines(&device, &source, &config, &base_name) {
        console.say(&line);
    }
    if controller.is_aborted() {
        return Err(AcquisitionError::aborted(
            "aborted before the acquisition started; nothing was written",
        ));
    }

    let mut unmounted = Vec::new();
    if args.auto_unmount {
        if matches!(source, ResolvedSource::File { .. }) {
            console.note("[*] --auto-unmount: the source is a regular file; nothing to unmount");
        } else {
            unmounted = auto_unmount(&device, console).await?;
        }
    }
    let mut request = AcquisitionRequest::new(device, case, config);
    request.unmounted_by_dfdisk = unmounted;
    let options = RunOptions {
        verbose: args.verbose,
        e01: E01Settings::from_options(&args.options),
    };
    execute_acquisition(&HostSystem, request, options, controller, listener, console).await
}

/// `--auto-unmount`: the audited unmount of `dfdisk unmount`, only when
/// something of the source is mounted. Returns the mount points unmounted.
async fn auto_unmount(
    device: &BlockDevice,
    console: &Console,
) -> Result<Vec<String>, AcquisitionError> {
    let path = device.path.clone();
    let id = tokio::task::spawn_blocking(move || identity::probe(&path))
        .await
        .map_err(|e| AcquisitionError::failed(format!("the device probe stopped: {e}")))?
        .map_err(|e| {
            AcquisitionError::refused(format!(
                "{} cannot be identified for unmounting: {e}",
                device.path
            ))
        })?;
    let mounted = {
        let id = id.clone();
        tokio::task::spawn_blocking(move || {
            writeprotect::capture(&id, WriteProtectPolicy::Off).mounts_before
        })
        .await
        .map_err(|e| AcquisitionError::failed(format!("the mount check stopped: {e}")))?
    };
    if mounted.is_empty() {
        console.say("[+] --auto-unmount: nothing of the source is mounted");
        return Ok(Vec::new());
    }
    console.say(&format!(
        "[*] --auto-unmount: unmounting {} (audited)",
        mounted.join(", ")
    ));
    let result = tokio::task::spawn_blocking(move || safety::unmount_source_tree(&id))
        .await
        .map_err(|e| AcquisitionError::failed(format!("the unmount stopped: {e}")))??;
    for m in &result.unmounted {
        console.say(&format!("[+] unmounted {m}"));
    }
    if !result.holders.is_empty() {
        console.note(&format!(
            "[!] devices stacked on the source stay open (not closed by dfdisk): {}",
            result.holders.join(", ")
        ));
    }
    Ok(result.unmounted)
}

/// Run `request` on `host` with the controller's stop flags, print progress
/// and the report, and orchestrate `--rescue-to-e01`. Returns the exit code
/// of the outcome; `Err` when no acquisition ran (refused, usage, failed,
/// aborted before the first write).
pub async fn execute_acquisition(
    host: &dyn SessionHost,
    request: AcquisitionRequest,
    options: RunOptions,
    controller: &AbortController,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> Result<i32, AcquisitionError> {
    let rescue_to_e01 = request.config.rescue_to_e01 && request.engine() == EngineKind::Rescue;
    let case = request.case.clone();
    let (tx, rx) = mpsc::channel(PROGRESS_CHANNEL);
    let mut printer = ProgressPrinter::new(console, options.verbose);
    console.note("[*] Starting the acquisition (Ctrl+C stops it gracefully)");
    let report = drive(
        session::run_with(host, request, tx, controller.stop_flags()),
        rx,
        listener,
        console,
        &mut printer,
        Activity::Acquisition,
    )
    .await?;

    let mut code = report.exit_code;
    if !rescue_to_e01 {
        print_report(console, &report);
        return Ok(code);
    }

    // --rescue-to-e01: the rescue report is final (its digest is in the audit
    // "finished" record); the conversion references it.
    if !console.json() {
        print_report(console, &report);
    }
    let conversion = match plan_conversion(&report, &case, options.e01) {
        Err(reason) => ConversionStep::Skipped(reason),
        Ok(_) if controller.is_aborted() => {
            ConversionStep::Skipped("the run was aborted; the image was not converted".into())
        }
        Ok(req) => {
            console.note(&format!(
                "[*] --rescue-to-e01: converting {} to E01 in {}",
                req.source.display(),
                req.output_dir.display()
            ));
            let (tx, rx) = mpsc::channel(PROGRESS_CHANNEL);
            let mut printer = ProgressPrinter::new(console, options.verbose);
            match drive(
                converter::convert(req, tx, controller.stop_flags()),
                rx,
                listener,
                console,
                &mut printer,
                Activity::Conversion,
            )
            .await
            {
                Ok(r) => ConversionStep::Done(Box::new(r)),
                Err(e) => ConversionStep::Failed(e),
            }
        }
    };
    code = more_severe(code, conversion.exit_code());
    print_conversion_step(console, &report, &conversion, code);
    Ok(code)
}

/// What happened to the conversion of `--rescue-to-e01`.
#[derive(Debug)]
pub enum ConversionStep {
    Skipped(String),
    Done(Box<ConversionReport>),
    Failed(AcquisitionError),
}

impl ConversionStep {
    /// Exit code of the conversion step (a skipped conversion adds nothing:
    /// the rescue's own verdict already says why).
    pub fn exit_code(&self) -> i32 {
        match self {
            ConversionStep::Skipped(_) => exit_code::VERIFIED,
            ConversionStep::Done(r) => r.exit_code(),
            ConversionStep::Failed(e) => e.exit_code(),
        }
    }
}

/// The report on stdout: the text report and the verdict, or with `--json`
/// exactly the `<base>.info.json` document.
pub fn print_report(console: &Console, report: &ForensicInfoReport) {
    if console.json() {
        console.data(&report.to_json());
        for line in report.verdict_lines() {
            console.note(&format!("[{}] {line}", verdict_mark(report.outcome)));
        }
        return;
    }
    console.data(&report.render_text());
    let dir = Path::new(&report.output_dir);
    console.data(&format!(
        "Report: {}\n        {}",
        dir.join(format!("{}{INFO_SUFFIX}", report.base_name))
            .display(),
        dir.join(format!("{}{INFO_JSON_SUFFIX}", report.base_name))
            .display()
    ));
    for line in report.verdict_lines() {
        console.data(&format!("[{}] {line}", verdict_mark(report.outcome)));
    }
}

fn verdict_mark(outcome: Outcome) -> &'static str {
    if outcome == Outcome::Verified {
        "+"
    } else {
        "!"
    }
}

/// The conversion `--rescue-to-e01` runs after `report`, or why it does
/// not: only a complete rescue (VERIFIED, COMPLETE NOT VERIFIED, COMPLETED
/// WITH READ ERRORS) is converted.
pub fn plan_conversion(
    report: &ForensicInfoReport,
    case: &CaseMetadata,
    e01: E01Settings,
) -> Result<ConversionRequest, String> {
    match report.outcome {
        Outcome::Verified | Outcome::CompleteUnverified | Outcome::CompletedWithReadErrors => {}
        Outcome::Incomplete => {
            return Err(format!(
                "the rescue is {} (exit code {}); an incomplete image is not converted. Resume the rescue (--rescue --resume), then convert it with dfdisk convert",
                report.outcome.label(),
                report.exit_code
            ))
        }
        other => {
            return Err(format!(
                "the rescue ended {} (exit code {}); its image is not converted",
                other.label(),
                report.exit_code
            ))
        }
    }
    let image = report
        .image_files
        .first()
        .ok_or_else(|| "the rescue report lists no image file".to_string())?;
    let dir = PathBuf::from(&report.output_dir);
    let report_json = dir.join(format!("{}{INFO_JSON_SUFFIX}", report.base_name));
    Ok(ConversionRequest {
        source: PathBuf::from(image),
        target: ConversionTarget::E01,
        output_dir: dir.join(RESCUE_E01_SUBDIR),
        case: Some(case.clone()),
        compression: e01.compression,
        split_size: e01.split_size,
        notes: rescue_notes(report, &report_json),
        source_report: Some(report_json),
    })
}

/// The E01 notes of a converted rescue: where it came from, the rescue's
/// verdict and its read-error table (summary and the first ranges).
pub fn rescue_notes(report: &ForensicInfoReport, report_json: &Path) -> Vec<String> {
    let name = |p: &Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.display().to_string())
    };
    let image = report
        .image_files
        .first()
        .map(|i| name(Path::new(i)))
        .unwrap_or_default();
    let mut notes = vec![
        format!(
            "Converted from the GNU ddrescue rescue image {image}; rescue report {}",
            name(report_json)
        ),
        format!(
            "Rescue verdict: {} (exit code {})",
            report.outcome.label(),
            report.exit_code
        ),
    ];
    let table = &report.read_errors;
    match table.summary(RangeKind::Substituted) {
        None => notes.push(format!(
            "Read errors of the rescue ({}): none",
            if table.source.is_empty() {
                "ddrescue mapfile"
            } else {
                table.source.as_str()
            }
        )),
        Some(summary) => {
            notes.push(format!(
                "Read errors of the rescue ({}): {summary} were unreadable and are zero-filled in this image",
                table.source
            ));
            let sector = u64::from(table.effective_sector_size());
            let ranges: Vec<String> = table
                .ranges
                .iter()
                .filter(|r| r.kind == RangeKind::Substituted)
                .map(|r| {
                    format!(
                        "{}-{}",
                        r.offset / sector,
                        (r.end().saturating_sub(1)) / sector
                    )
                })
                .collect();
            let shown = ranges.len().min(MAX_NOTE_RANGES);
            let mut line = format!(
                "Zero-filled sectors ({} bytes each): {}",
                sector,
                ranges[..shown].join(", ")
            );
            if ranges.len() > shown {
                line.push_str(&format!(
                    " and {} more ranges (see {})",
                    ranges.len() - shown,
                    name(report_json)
                ));
            }
            notes.push(line);
        }
    }
    notes
}

fn print_conversion_step(
    console: &Console,
    report: &ForensicInfoReport,
    step: &ConversionStep,
    code: i32,
) {
    if console.json() {
        let acquisition: serde_json::Value =
            serde_json::from_str(&report.to_json()).unwrap_or(serde_json::Value::Null);
        let (conversion, error, skipped) = match step {
            ConversionStep::Done(r) => (
                serde_json::to_value(r.as_ref()).unwrap_or(serde_json::Value::Null),
                serde_json::Value::Null,
                serde_json::Value::Null,
            ),
            ConversionStep::Failed(e) => (
                serde_json::Value::Null,
                error_json(e)["error"].clone(),
                serde_json::Value::Null,
            ),
            ConversionStep::Skipped(reason) => (
                serde_json::Value::Null,
                serde_json::Value::Null,
                json!(reason),
            ),
        };
        let doc = json!({
            "acquisition": acquisition,
            "conversion": conversion,
            "conversion_error": error,
            "conversion_skipped": skipped,
            "exit_code": code,
        });
        console.data(&serde_json::to_string_pretty(&doc).unwrap_or_default());
    }
    let lines: Vec<String> = match step {
        ConversionStep::Skipped(reason) => {
            vec![format!("[!] --rescue-to-e01: no conversion: {reason}")]
        }
        ConversionStep::Failed(e) => vec![format!(
            "[!] --rescue-to-e01: the conversion did not run ({}): {}",
            e.kind.label(),
            e.message
        )],
        ConversionStep::Done(r) => {
            let mut l = vec![format!(
                "[{}] --rescue-to-e01: E01 conversion {} (exit code {})",
                verdict_mark(r.outcome),
                r.outcome.label(),
                r.exit_code()
            )];
            for f in &r.output_files {
                l.push(format!("    image  : {}", f.display()));
            }
            l.push(format!("    report : {}", r.report_file.display()));
            l.push(format!("             {}", r.report_json_file.display()));
            l
        }
    };
    for line in lines {
        if console.json() {
            console.note(&line);
        } else {
            console.data(&line);
        }
    }
    if !console.json() {
        console.data(&format!("Exit code (rescue and conversion): {code}"));
    }
}

/// `{"error": {"kind", "exit_code", "message"}}` for `--json` output.
pub fn error_json(e: &AcquisitionError) -> serde_json::Value {
    json!({
        "error": {
            "kind": e.kind,
            "exit_code": e.exit_code(),
            "message": e.message,
        }
    })
}

/// `dfdisk check`: the dry run (§4, §15). Usage errors of the options are
/// reported by the check itself, like every other problem.
pub async fn handle_check(
    args: CheckArgs,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> Result<i32, AcquisitionError> {
    let config = config_from_options(&args.options)?;
    let case = case_from_args(&args.case);
    let source = resolve_argument(&args.device)?;
    let device = select_device(&source, DeviceScanner::scan_devices)?;
    let request = AcquisitionRequest::new(device, case, config);
    console.note(&format!(
        "[*] Checking {} (nothing is written or changed)",
        request.device.path
    ));
    let check = session::check_with(&HostSystem, request);
    tokio::pin!(check);
    let report = loop {
        tokio::select! {
            r = &mut check => break r,
            (kind, action) = next_signal(listener) => {
                if matches!(action, SignalAction::Abort | SignalAction::Force) {
                    // Dropping the check stops its probes (their process
                    // groups are killed); it wrote nothing
                    return Err(AcquisitionError::aborted(format!(
                        "the check was interrupted by {}",
                        kind.name()
                    )));
                }
            }
        }
    };
    if console.json() {
        console.data(&serde_json::to_string_pretty(&report).map_err(|e| {
            AcquisitionError::failed(format!("cannot serialise the check report: {e}"))
        })?);
    } else {
        console.data(&report.render_text());
    }
    Ok(report.exit_code())
}
