//! Rescue engine (§13 Rescue, review H4, R12): GNU ddrescue copies what it
//! can read into `<base>.raw` and records every area in its map `<base>.map`.
//!
//! What the report says comes from the map only ([`ddrescue_map`]):
//! - `+` finished: in the image as read;
//! - `-` bad sector: zeros in the image, listed as `Substituted`. ddrescue
//!   never writes a bad sector, but a session killed before it saved its map
//!   can leave data there that the map does not list as rescued; after every
//!   ddrescue run dfdisk writes zeros over the bad-sector areas inside the
//!   image (and fsyncs it), so the statement holds. The sectors that held
//!   anything else are first copied to `<base>.zeroed-N.bin` with their
//!   places in `<base>.zeroed-N.tsv` (N: the rescue session, or one past
//!   the highest such file an earlier session left without its report;
//!   never overwritten), so nothing a session read is destroyed. When the
//!   zeros cannot be written, those areas are `Unread`: the image may hold
//!   other data there;
//! - `?` non-tried, `*` non-trimmed, `/` non-scraped: `Unread`; the rescue is
//!   incomplete until it is run again (resumed).
//!
//! The image is extended to the size of the source (`set_len`) only when the
//! map covers the whole source and every block is finished or bad: ddrescue
//! does not write unreadable sectors at the end of a device, so a finished
//! image can be shorter than the source. An unfinished image is never padded.
//!
//! ddrescue runs through [`process`] (both streams, `LC_ALL=C`, own process
//! group); an abort sends SIGINT, on which ddrescue saves its map, with 30 s
//! of grace before SIGTERM and SIGKILL. Progress comes from ddrescue's
//! "pct rescued" line, the live bad-sector count from the map ddrescue saves
//! while it runs.
//!
//! Resume (`config.resume`): the first start writes `<base>.identity.json`
//! (the probed identity of the source). A resume requires that record and the
//! same device (WWN / serial, or the same attachment for a device without
//! either) of the same size ([`check_resume_identity`], which the session also
//! runs before anything is written), keeps the previous report as
//! `<base>.info.session-N` (+ `<base>.info.session-N.json`), lists every
//! earlier session, states whether the map changed since the last report,
//! and passes `-I` so ddrescue checks the size of the source against the map.
//!
//! Verification: ddrescue computes no digest while reading. [`verify`]
//! hashes the image after the session's flush and cache eviction and returns
//! `NotPossible`; only a matching second read of the source
//! (`--verify-source`, run by the session through `raw::hash_source`) makes a
//! clean rescue `Verified`. A rescue with bad sectors is never verified.
//!
//! `--rescue-to-e01` is orchestrated by the caller (CLI) after the rescue
//! report is written, with `engines::converter::convert`; this engine only
//! records that it was requested.

use crate::engines::ddrescue_map::{self, Mapfile, MAP_SOURCE};
use crate::engines::error::AcquisitionError;
use crate::engines::preflight;
use crate::engines::process::{self, ProcessEvent, ProcessSpec, StreamTag};
use crate::engines::session::{EngineContext, EngineOutput};
use crate::models::config::{EngineSettings, HashSelection, RescueSettings, SmartPolicy};
use crate::models::identity::{normalize_wwn, SerialSource, SourceIdentity, SourceKind};
use crate::models::info_report::{
    sha256_file, sync_dir, write_atomic, ForensicInfoReport, HashResults, SessionInfo,
    INFO_JSON_SUFFIX, INFO_SUFFIX,
};
use crate::models::outcome::{RangeKind, ReadErrorTable, VerificationResult};
use crate::models::provenance::{DFDISK_GIT_REV, DFDISK_VERSION};
use crate::models::telemetry::ProgressTelemetry;
use crate::models::text::{plural, sanitize_line};
use chrono::{DateTime, Utc};
use digest::Digest;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

/// The ddrescue program (looked up in PATH).
pub const DDRESCUE: &str = "ddrescue";
/// The rescued image, `<base>.raw`.
pub const IMAGE_SUFFIX: &str = ".raw";
/// ddrescue's map, `<base>.map`.
pub const MAP_SUFFIX: &str = ".map";
/// Identity of the source recorded at the first start, `<base>.identity.json`.
pub const IDENTITY_SUFFIX: &str = ".identity.json";
/// A kept report of an earlier session: `<base>.info.session-N` and
/// `<base>.info.session-N.json`.
pub const SESSION_SUFFIX: &str = ".info.session-";
/// Bytes dfdisk found in bad-sector areas before it wrote zeros over them
/// (S-N3): `<base>.zeroed-N.bin` (the sector bytes, concatenated) and
/// `<base>.zeroed-N.tsv` (where each run of them was), N the rescue session
/// (see [`zeroed_number`]).
pub const ZEROED_SUFFIX: &str = ".zeroed-";
/// SIGINT → SIGTERM delay on abort: ddrescue saves its map on SIGINT.
pub const DDRESCUE_GRACE: Duration = Duration::from_secs(30);
/// How often the map is re-read for the live bad-sector count.
const MAP_POLL: Duration = Duration::from_secs(2);
/// Chunk size for hashing the image.
const HASH_CHUNK: usize = 4 << 20;
/// Chunk size for writing zeros over bad-sector areas.
const ZERO_CHUNK: usize = 1 << 20;

const NO_STREAM_DIGEST: &str = "ddrescue computes no digest while reading, so the image digests have nothing to be compared with; --verify-source compares them with a second read of the source";

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Rescue the source into `<base>.raw` with its map `<base>.map` (step 8).
pub async fn acquire(ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
    acquire_with(ctx, OsStr::new(DDRESCUE)).await
}

/// [`acquire`] with another ddrescue program (tests).
pub async fn acquire_with(
    ctx: &EngineContext,
    program: &OsStr,
) -> Result<EngineOutput, AcquisitionError> {
    let config = ctx.config();
    let expected = ctx.expected_bytes();
    let sector_size = ctx.sector_size();
    let image = ctx.output_path(IMAGE_SUFFIX);
    let map = ctx.output_path(MAP_SUFFIX);
    let sidecar = ctx.output_path(IDENTITY_SUFFIX);
    // Direct access applies to devices; a regular-file source is read like
    // any file
    let direct_io = ctx.identity.is_block_device();
    let settings = RescueSettings {
        retries: config.error_retries,
        direct_io,
        sector_size,
        resume: config.resume,
        rescue_to_e01: config.rescue_to_e01,
    };
    let mut notes: Vec<String> = Vec::new();

    // Nothing is written before ddrescue is known to run
    let program_name = program.to_string_lossy().into_owned();
    let version = process::tool_version(&program_name, &["--version"], Duration::from_secs(10))
        .await
        .ok_or_else(|| {
            AcquisitionError::failed(format!(
                "GNU ddrescue ({program_name}) is not available on this host or does not run; install it and retry"
            ))
        })?;
    ctx.provenance.set_tool_version(DDRESCUE, &version);

    let mut resume_sessions = Vec::new();
    // The previous report kept by a resume: put back when ddrescue never ran
    let mut kept_report: Option<u32> = None;
    if config.resume {
        let prepared = prepare_resume(ctx, &map)?;
        resume_sessions = prepared.sessions;
        kept_report = prepared.kept;
        notes.extend(prepared.notes);
    } else {
        write_identity_record(&sidecar, ctx)?;
    }
    if !direct_io {
        notes.push(
            "the source is a regular file: ddrescue reads it without direct access (-d applies to devices)"
                .into(),
        );
    }
    if config.smart == SmartPolicy::Off && ctx.identity.is_block_device() {
        notes.push(
            "no SMART snapshot before and after the rescue (--smart off): the health of the drive is not recorded"
                .into(),
        );
    }
    if config.rescue_to_e01 {
        notes.push(
            "--rescue-to-e01 was requested: the image is converted to E01 after this report is written; the conversion has its own report, which refers to this one. This report does not state the result of the conversion"
                .into(),
        );
    }

    let mut args: Vec<OsString> = Vec::new();
    if direct_io {
        args.push("-d".into());
    }
    args.push("-r".into());
    args.push(config.error_retries.to_string().into());
    args.push("-b".into());
    args.push(sector_size.to_string().into());
    if config.resume {
        // ddrescue refuses when the size of the source differs from the map
        args.push("-I".into());
    }
    args.push(ctx.tool_source_path.clone().into());
    args.push(image.clone().into());
    args.push(map.clone().into());
    let spec = ProcessSpec::new(program).args(args).grace(DDRESCUE_GRACE);

    let image_name = file_name(&image);
    ctx.progress.update(|t| {
        t.total_bytes = expected;
        t.current_segment = image_name.clone();
        t.status_message = format!("Starting {version}");
    });
    let t0 = Instant::now();
    let mut screen = ScreenStatus::default();
    let mut stderr_tail: Vec<String> = Vec::new();
    let mut map_checked: Option<Instant> = None;
    let mut map_mtime: Option<SystemTime> = None;
    let run = process::run(
        &spec,
        &ctx.stop_control(),
        Some(&ctx.provenance),
        |ev| match ev {
            ProcessEvent::Line {
                stream: StreamTag::Stdout,
                text,
                ..
            } => match screen.feed(text) {
                Some(ScreenEvent::Progress) => {
                    ctx.progress
                        .update(|t| screen.apply(t, expected, t0.elapsed()));
                }
                Some(ScreenEvent::Phase(phase)) => ctx.progress.log(format!("ddrescue: {phase}")),
                Some(ScreenEvent::Message(m)) => ctx.progress.log(format!("ddrescue: {m}")),
                None => {}
            },
            ProcessEvent::Line {
                stream: StreamTag::Stderr,
                text,
                ..
            } => {
                let line = sanitize_line(&strip_ansi(text));
                if !line.is_empty() {
                    ctx.progress.log(format!("ddrescue: {line}"));
                    stderr_tail.push(line);
                    if stderr_tail.len() > 20 {
                        stderr_tail.remove(0);
                    }
                }
            }
            ProcessEvent::Tick { .. } => {
                if map_checked.is_none_or(|t| t.elapsed() >= MAP_POLL) {
                    map_checked = Some(Instant::now());
                    let mtime = fs::metadata(&map).and_then(|m| m.modified()).ok();
                    if mtime.is_some() && mtime != map_mtime {
                        map_mtime = mtime;
                        if let Ok(m) = ddrescue_map::read(&map) {
                            let bad = m.bad_sectors(sector_size);
                            ctx.progress.update(|t| t.bad_sectors = bad);
                        }
                    }
                }
            }
        },
    )
    .await;

    let outcome = match run {
        Ok(o) => o,
        Err(e) => {
            discard_unused_record(config.resume, &sidecar, &image, &map);
            let mut message = format!("cannot start ddrescue: {e}");
            if let Some(n) = kept_report {
                // ddrescue never ran: the previous report is the last word again
                if let Err(r) = restore_previous_report(&ctx.output_dir, &ctx.base_name, n) {
                    message.push_str(&format!(
                        "; the report of the previous session stays kept as session {n} ({r})"
                    ));
                }
            }
            return Err(AcquisitionError::failed(message));
        }
    };
    let aborted = outcome.aborted || outcome.force_killed || ctx.is_aborted();
    if !config.resume && !image.exists() && !map.exists() {
        // ddrescue wrote nothing: there is nothing to report about
        discard_unused_record(false, &sidecar, &image, &map);
        if aborted {
            return Err(AcquisitionError::aborted(
                "the rescue was aborted before ddrescue wrote anything",
            ));
        }
        return Err(AcquisitionError::failed(format!(
            "ddrescue wrote neither an image nor a map ({})",
            exit_description(&outcome, &stderr_tail)
        )));
    }

    // This session's number: one past the kept reports of earlier sessions
    // (the previous report was kept above)
    let session = kept_sessions(&ctx.output_dir, &ctx.base_name)
        .last()
        .map(|(n, _, _)| n + 1)
        .unwrap_or(1);
    // E-R3-1: never the number of a sidecar that exists already (left by a
    // session that ended without its report, so its number was not kept)
    let zeroed_n = preflight::existing_outputs(&ctx.output_dir, &ctx.base_name)
        .iter()
        .filter_map(|p| zeroed_number(&ctx.base_name, &p.file_name()?.to_string_lossy()))
        .max()
        .map_or(session, |highest| session.max(highest.saturating_add(1)));
    let zeroed_files = ZeroSidecar::new(&ctx.output_dir, &ctx.base_name, zeroed_n);
    let fin = finalize(&map, &image, expected, sector_size, &zeroed_files);
    notes.extend(fin.notes);
    let mut stop_reason = fin.stop_reason;
    if outcome.force_killed {
        notes.push(
            "ddrescue was killed at once (forced stop): it could not save its map a last time, so the map may miss its most recent progress; those areas count as not acquired and a resume reads them again"
                .into(),
        );
    } else if aborted {
        let signals: Vec<&str> = outcome.signals_sent.iter().map(|s| s.name()).collect();
        notes.push(if signals.is_empty() {
            "the rescue was aborted".to_string()
        } else {
            format!(
                "the rescue was stopped with {}; ddrescue writes its map when it is interrupted, and this report describes the map as ddrescue left it",
                signals.join(", ")
            )
        });
    } else if !outcome.success() {
        let reason = format!(
            "ddrescue ended abnormally ({})",
            exit_description(&outcome, &stderr_tail)
        );
        stop_reason = Some(match stop_reason {
            Some(s) => format!("{reason}; {s}"),
            None => reason,
        });
    }
    ctx.progress.update(|t| {
        t.bad_sectors = fin.bad_sectors;
        t.bytes_processed = fin.bytes_acquired;
        t.percentage = if expected > 0 {
            fin.bytes_acquired as f64 * 100.0 / expected as f64
        } else {
            100.0
        };
        t.elapsed_secs = t0.elapsed().as_secs();
        t.eta_secs = None;
    });

    let mut auxiliary_files = Vec::new();
    if map.exists() {
        auxiliary_files.push(map.clone());
    }
    if sidecar.exists() {
        auxiliary_files.push(sidecar.clone());
    }
    auxiliary_files.extend(fin.auxiliary_files);
    Ok(EngineOutput {
        bytes_acquired: fin.bytes_acquired,
        expected_bytes: expected,
        read_errors: fin.read_errors,
        stop_reason,
        aborted,
        image_files: if image.exists() {
            vec![image]
        } else {
            Vec::new()
        },
        auxiliary_files,
        notes,
        settings: Some(EngineSettings::Rescue(settings)),
        resume_sessions,
        ..Default::default()
    })
}

/// Remove the identity record a first start wrote when ddrescue left
/// nothing behind (a resume never removes anything).
fn discard_unused_record(resume: bool, sidecar: &Path, image: &Path, map: &Path) {
    if resume || image.exists() || map.exists() {
        return;
    }
    if fs::remove_file(sidecar).is_ok() {
        if let Some(dir) = sidecar.parent() {
            let _ = sync_dir(dir);
        }
    }
}

fn exit_description(outcome: &process::ProcessOutcome, stderr_tail: &[String]) -> String {
    let status = match (outcome.exit_code, outcome.signal) {
        (Some(1), _) => {
            "exit status 1: environmental problem (file not found, invalid option, I/O error)"
                .to_string()
        }
        (Some(2), _) => "exit status 2: corrupt or invalid input file or map".to_string(),
        (Some(3), _) => "exit status 3: internal error in ddrescue".to_string(),
        (Some(c), _) => format!("exit status {c}"),
        (None, Some(s)) => format!("ended by signal {s}"),
        (None, None) => "no exit status".to_string(),
    };
    let timed_out = if outcome.timed_out { ", timed out" } else { "" };
    let start = stderr_tail.len().saturating_sub(3);
    let lines = &stderr_tail[start..];
    if lines.is_empty() {
        format!("{status}{timed_out}")
    } else {
        format!("{status}{timed_out}: {}", lines.join(" / "))
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// What the map says once ddrescue ended.
#[derive(Debug, Clone)]
struct Finalized {
    read_errors: ReadErrorTable,
    bytes_acquired: u64,
    stop_reason: Option<String>,
    bad_sectors: u64,
    notes: Vec<String>,
    /// The files keeping bytes the zeros replaced (S-N3)
    auxiliary_files: Vec<PathBuf>,
}

/// Parse the map, extend a finished image to the size of the source when
/// only bad sectors are missing at its end, and derive the facts. Bytes
/// found in bad-sector areas are kept in `zeroed_files` before the zeros
/// are written.
fn finalize(
    map_path: &Path,
    image_path: &Path,
    expected: u64,
    sector_size: u32,
    zeroed_files: &ZeroSidecar,
) -> Finalized {
    let image_len = fs::metadata(image_path).map(|m| m.len()).ok();
    let map = match ddrescue_map::read(map_path) {
        Ok(m) => m,
        Err(e) => {
            let mut table = ReadErrorTable::new(sector_size, MAP_SOURCE);
            table.push(0, expected, RangeKind::Unread);
            return Finalized {
                read_errors: table,
                bytes_acquired: 0,
                stop_reason: Some(format!(
                    "{e}; without a readable map nothing can be said about the rescued areas, so the whole source counts as not acquired"
                )),
                bad_sectors: 0,
                notes: Vec::new(),
                auxiliary_files: Vec::new(),
            };
        }
    };
    let mut notes = Vec::new();
    let mut len = image_len.unwrap_or(0);
    if image_len.is_none() {
        notes.push(format!(
            "the image file {} does not exist",
            image_path.display()
        ));
    }
    // R-2: the report says bad sectors are zeros in the image; ddrescue only
    // never writes them, so data an earlier session wrote there before its
    // map recorded it would stay. dfdisk writes the zeros itself
    let mut stop_reason = None;
    let mut auxiliary_files = Vec::new();
    // E-R3-1: the end of the image part whose bad-sector areas may not be zeros
    let mut not_zeroed: Option<u64> = None;
    let zeroed = match image_len {
        Some(l) => match zero_bad_sectors(image_path, &map, l, sector_size, zeroed_files) {
            Ok(z) => z.map(|z| {
                if z.kept {
                    auxiliary_files.extend(zeroed_files.paths());
                }
                z.statement(zeroed_files)
            }),
            Err(e) => {
                not_zeroed = Some(l);
                stop_reason = Some(format!(
                    "dfdisk could not write zeros over the bad-sector areas of the map in the image ({}); the image may hold other data there than zeros, so those areas count as not acquired",
                    e.message
                ));
                if e.kept {
                    auxiliary_files.extend(zeroed_files.paths());
                    notes.push(format!(
                        "the bytes the bad-sector areas held before dfdisk began to write zeros over them are kept in {} and {}",
                        file_name(&zeroed_files.bin),
                        file_name(&zeroed_files.tsv)
                    ));
                }
                None
            }
        },
        None => None,
    };
    if image_len.is_some()
        && len < expected
        && map.covers(expected)
        && map.is_finished()
        && map.assess(expected, len, sector_size).rescued_beyond_image == 0
    {
        match extend_image(image_path, expected) {
            Ok(()) => {
                notes.push(format!(
                    "the image file was extended from {len} to {expected} bytes: ddrescue does not write unreadable sectors at the end of the source, and the bad-sector blocks the map lists there are zeros in the image"
                ));
                len = expected;
            }
            Err(e) => notes.push(format!(
                "the image file could not be extended to the size of the source ({e}); the bad sectors at its end count as not acquired"
            )),
        }
    }
    if len > expected {
        notes.push(format!(
            "the image file is {len} bytes long, longer than the source ({expected} bytes); its digests cover the whole file"
        ));
    }
    let mut a = map.assess(expected, len, sector_size);
    notes.push(map_summary(&map, map_path, &a.counts));
    notes.extend(zeroed);
    if let Some(limit) = not_zeroed {
        // Not zeros: bad sectors whose content in the image is unknown are
        // not acquired (beyond `limit`, the extension made them zeros)
        let unknown: Vec<(u64, u64)> = a
            .read_errors
            .ranges
            .iter()
            .filter(|r| r.kind == RangeKind::Substituted && r.offset < limit)
            .map(|r| (r.offset, r.end().min(limit) - r.offset))
            .collect();
        let bytes: u64 = unknown.iter().map(|(_, n)| n).sum();
        for (offset, n) in unknown {
            a.read_errors.push(offset, n, RangeKind::Unread);
        }
        a.bytes_acquired = a.bytes_acquired.saturating_sub(bytes);
        if bytes > 0 {
            notes.push(format!(
                "the bad-sector areas of the map inside the image ({}) count as not acquired, not as zeros: dfdisk could not write zeros over them, so the image may hold other data there",
                plural(bytes, "byte", "bytes")
            ));
        }
    }
    notes.extend(a.notes.iter().cloned());
    Finalized {
        bad_sectors: map.bad_sectors(sector_size),
        read_errors: a.read_errors,
        bytes_acquired: a.bytes_acquired,
        stop_reason,
        notes,
        auxiliary_files,
    }
}

/// Where [`zero_bad_sectors`] keeps the bytes it finds in bad-sector areas
/// (S-N3): `<base>.zeroed-N.bin` holds them concatenated, `<base>.zeroed-N.tsv`
/// one line per run of sectors: image offset, length, offset in the .bin
/// file and SHA-256 of those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroSidecar {
    pub bin: PathBuf,
    pub tsv: PathBuf,
}

impl ZeroSidecar {
    pub fn new(dir: &Path, base: &str, session: u32) -> Self {
        Self {
            bin: dir.join(format!("{base}{ZEROED_SUFFIX}{session}.bin")),
            tsv: dir.join(format!("{base}{ZEROED_SUFFIX}{session}.tsv")),
        }
    }

    fn paths(&self) -> [PathBuf; 2] {
        [self.bin.clone(), self.tsv.clone()]
    }

    /// Remove the files this run created after a failure before anything
    /// was zeroed (the image still holds the bytes); a file that existed
    /// before is never touched.
    fn discard(&self, bin: bool, tsv: bool) {
        if bin {
            let _ = fs::remove_file(&self.bin);
        }
        if tsv {
            let _ = fs::remove_file(&self.tsv);
        }
    }
}

/// The header line of `<base>.zeroed-N.tsv`.
pub const ZEROED_TSV_HEADER: &str = "image_offset\tlength\tbin_offset\tsha256";

/// What [`zero_bad_sectors`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Zeroed {
    /// Bad-sector blocks of the map inside the image file
    ranges: usize,
    /// Bytes of them inside the image file (all now zeros)
    bytes: u64,
    /// Sectors among them that held something other than zeros before
    sectors_with_data: u64,
    sector_size: u32,
    /// Those sectors were kept in the sidecar files
    kept: bool,
}

impl Zeroed {
    fn statement(&self, files: &ZeroSidecar) -> String {
        let what = format!(
            "dfdisk wrote zeros over the {} of the map inside the image ({}) after ddrescue ended, so the image holds zeros there",
            plural(self.ranges as u64, "bad-sector area", "bad-sector areas"),
            plural(self.bytes, "byte", "bytes")
        );
        if self.sectors_with_data == 0 {
            format!("{what}; none of their sectors held other data before")
        } else {
            format!(
                "{what}; {} ({}-byte) held other data before, which the map does not record as rescued (ddrescue writes data before its map records it, so a run killed before it saved its map can leave data there, also sectors a retry pass read); their bytes are kept in {} with their image offsets and SHA-256 in {}",
                plural(self.sectors_with_data, "sector", "sectors"),
                self.sector_size,
                file_name(&files.bin),
                file_name(&files.tsv)
            )
        }
    }
}

/// Why [`zero_bad_sectors`] failed, and whether the sidecar files exist
/// (the zeroing had begun: they hold bytes the image no longer has).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZeroError {
    message: String,
    kept: bool,
}

impl ZeroError {
    fn before(message: String) -> Self {
        Self {
            message,
            kept: false,
        }
    }
}

/// A run of adjacent sectors with data, being copied to the .bin file.
struct KeptRun {
    image_offset: u64,
    length: u64,
    bin_offset: u64,
    sha256: sha2::Sha256,
}

/// Write zeros over every bad-sector (`-`) block of `map` inside the image
/// file (up to `image_len`; nothing is written beyond its end), then fsync
/// it. ddrescue never writes a bad sector, so the image holds zeros there
/// only if nothing else was written before: a session killed before it
/// saved its map leaves data the map does not list as rescued, which a
/// later session can mark bad. `None` when no bad-sector block lies inside
/// the image.
///
/// Every sector there that holds anything but zeros is first copied to
/// `files` (S-N3), created new (an existing file is never overwritten) and
/// fsynced with the directory, so nothing is destroyed; nothing is written
/// when no sector held data. A read error, or a sidecar that cannot be
/// written, stops before any zero is written.
fn zero_bad_sectors(
    image: &Path,
    map: &Mapfile,
    image_len: u64,
    sector_size: u32,
    files: &ZeroSidecar,
) -> Result<Option<Zeroed>, ZeroError> {
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    let ranges: Vec<(u64, u64)> = map
        .blocks
        .iter()
        .filter(|b| b.status == ddrescue_map::BlockStatus::BadSector)
        .map(|b| (b.pos, b.end().min(image_len)))
        .filter(|(start, end)| end > start)
        .collect();
    if ranges.is_empty() {
        return Ok(None);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image)
        .map_err(|e| ZeroError::before(format!("cannot open {}: {e}", image.display())))?;
    let sector = u64::from(sector_size.max(1));
    let mut buf = vec![0u8; ZERO_CHUNK];
    let mut z = Zeroed {
        ranges: ranges.len(),
        bytes: 0,
        sectors_with_data: 0,
        sector_size: sector_size.max(1),
        kept: false,
    };

    // 1: copy every sector that holds data to the .bin file
    let mut bin: Option<io::BufWriter<File>> = None;
    let mut bin_len = 0u64;
    let mut rows: Vec<String> = Vec::new();
    let mut run: Option<KeptRun> = None;
    let finish = |run: &mut Option<KeptRun>, rows: &mut Vec<String>| {
        if let Some(r) = run.take() {
            rows.push(format!(
                "{}\t{}\t{}\t{}",
                r.image_offset,
                r.length,
                r.bin_offset,
                hex::encode(r.sha256.finalize())
            ));
        }
    };
    let failed = |message: String, bin_created: bool, tsv_created: bool| {
        files.discard(bin_created, tsv_created);
        ZeroError::before(format!("{message}; nothing was overwritten"))
    };
    for &(start, end) in &ranges {
        let mut offset = start;
        while offset < end {
            let n = (end - offset).min(ZERO_CHUNK as u64) as usize;
            if let Err(e) = file.read_exact_at(&mut buf[..n], offset) {
                return Err(failed(
                    format!("read error in the image at byte offset {offset}: {e}"),
                    bin.is_some(),
                    false,
                ));
            }
            // Per sector (clipped to the area): data is kept, zeros are not
            let mut s = offset - offset % sector;
            while s < offset + n as u64 {
                let from = s.max(offset);
                let to = (s + sector).min(offset + n as u64);
                let bytes = &buf[(from - offset) as usize..(to - offset) as usize];
                if bytes.iter().any(|b| *b != 0) {
                    z.sectors_with_data += 1;
                    if bin.is_none() {
                        let created = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&files.bin)
                            .map_err(|e| {
                                failed(
                                    format!(
                                        "cannot create {} to keep the bytes found there: {e}{}",
                                        files.bin.display(),
                                        if e.kind() == io::ErrorKind::AlreadyExists {
                                            " (dfdisk never overwrites it)"
                                        } else {
                                            ""
                                        }
                                    ),
                                    false,
                                    false,
                                )
                            })?;
                        bin = Some(io::BufWriter::new(created));
                    }
                    if let Some(w) = bin.as_mut() {
                        if let Err(e) = w.write_all(bytes) {
                            return Err(failed(
                                format!("write to {}: {e}", files.bin.display()),
                                true,
                                false,
                            ));
                        }
                    }
                    match run.as_mut() {
                        Some(r) if r.image_offset + r.length == from => {
                            r.length += to - from;
                            r.sha256.update(bytes);
                        }
                        _ => {
                            finish(&mut run, &mut rows);
                            let mut sha256 = sha2::Sha256::new();
                            sha256.update(bytes);
                            run = Some(KeptRun {
                                image_offset: from,
                                length: to - from,
                                bin_offset: bin_len,
                                sha256,
                            });
                        }
                    }
                    bin_len += to - from;
                } else {
                    finish(&mut run, &mut rows);
                }
                s += sector;
            }
            offset += n as u64;
        }
        finish(&mut run, &mut rows);
    }
    if let Some(w) = bin.take() {
        let mut tsv_created = false;
        let durable = || -> Result<(), String> {
            w.into_inner()
                .map_err(|e| e.into_error())
                .and_then(|f| f.sync_all())
                .map_err(|e| format!("cannot write {}: {e}", files.bin.display()))?;
            let mut tsv = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&files.tsv)
                .map_err(|e| format!("cannot create {}: {e}", files.tsv.display()))?;
            tsv_created = true;
            let mut text = format!("{ZEROED_TSV_HEADER}\n");
            for row in &rows {
                text.push_str(row);
                text.push('\n');
            }
            tsv.write_all(text.as_bytes())
                .and_then(|()| tsv.sync_all())
                .map_err(|e| format!("cannot write {}: {e}", files.tsv.display()))?;
            match files.bin.parent() {
                Some(dir) => sync_dir(dir).map_err(|e| e.to_string()),
                None => Ok(()),
            }
        };
        if let Err(e) = durable() {
            return Err(failed(e, true, tsv_created));
        }
        z.kept = true;
    }

    // 2: the zeros
    let zeros = vec![0u8; ZERO_CHUNK];
    let after = |message: String| ZeroError {
        message,
        kept: z.kept,
    };
    for (start, end) in ranges {
        let mut offset = start;
        while offset < end {
            let n = (end - offset).min(ZERO_CHUNK as u64) as usize;
            file.write_all_at(&zeros[..n], offset)
                .map_err(|e| after(format!("write at byte offset {offset}: {e}")))?;
            offset += n as u64;
            z.bytes += n as u64;
        }
    }
    file.sync_all()
        .map_err(|e| after(format!("fsync of {}: {e}", image.display())))?;
    Ok(Some(z))
}

fn map_summary(map: &Mapfile, path: &Path, counts: &ddrescue_map::MapCounts) -> String {
    format!(
        "ddrescue map {} ({}; last phase: {}): {}",
        file_name(path),
        map.created_by().unwrap_or("ddrescue version not recorded"),
        ddrescue_map::phase_label(map.current_status),
        counts.describe()
    )
}

/// Grow (never shrink) the image to `len` bytes; the new bytes are zeros.
fn extend_image(path: &Path, len: u64) -> io::Result<()> {
    let f = OpenOptions::new().write(true).open(path)?;
    if f.metadata()?.len() < len {
        f.set_len(len)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Hash the rescued image (step 11, after the session's flush and cache
/// eviction). ddrescue computes no digest while reading, so there is nothing
/// to compare with: `NotPossible`; the session's `--verify-source` second
/// read can verify a clean rescue.
pub async fn verify(ctx: &EngineContext, out: &EngineOutput) -> (VerificationResult, HashResults) {
    let Some(image) = out.image_files.first().cloned() else {
        return (
            VerificationResult::Failed {
                reason: "ddrescue produced no image".into(),
            },
            HashResults::default(),
        );
    };
    let selection = ctx.selection;
    let abort = ctx.abort.clone();
    let sink = ctx.progress.clone();
    let t0 = Instant::now();
    let task = tokio::task::spawn_blocking(move || {
        hash_image(&image, selection, &abort, |done, total| {
            let secs = t0.elapsed().as_secs_f64();
            let speed = if secs > 0.0 { done as f64 / secs } else { 0.0 };
            sink.phase_progress(done, total, speed);
        })
    });
    match task.await {
        Ok(Ok(hashes)) => (
            VerificationResult::NotPossible {
                reason: NO_STREAM_DIGEST.into(),
            },
            hashes,
        ),
        Ok(Err(e)) => (
            VerificationResult::Failed { reason: e.message },
            HashResults::default(),
        ),
        Err(e) => (
            VerificationResult::Failed {
                reason: format!("the hashing task failed: {e}"),
            },
            HashResults::default(),
        ),
    }
}

/// Digests of the whole image file, read with positioned reads; its page
/// cache is dropped first and behind every chunk so the bytes come from the
/// destination medium.
pub fn hash_image(
    path: &Path,
    selection: HashSelection,
    abort: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<HashResults, AcquisitionError> {
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::AsRawFd;
    let file = File::open(path).map_err(|e| {
        AcquisitionError::failed(format!("cannot open the image {}: {e}", path.display()))
    })?;
    let len = file
        .metadata()
        .map_err(|e| {
            AcquisitionError::failed(format!("cannot inspect the image {}: {e}", path.display()))
        })?
        .len();
    let evict = |offset: u64, n: u64| {
        // SAFETY: advisory call on a descriptor we own
        unsafe {
            libc::posix_fadvise(
                file.as_raw_fd(),
                offset as libc::off_t,
                n as libc::off_t,
                libc::POSIX_FADV_DONTNEED,
            )
        };
    };
    evict(0, 0);
    let mut md5 = selection.md5.then(md5::Md5::new);
    let mut sha1 = selection.sha1.then(sha1::Sha1::new);
    let mut sha256 = selection.sha256.then(sha2::Sha256::new);
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut offset = 0u64;
    let mut last = Instant::now();
    while offset < len {
        if abort.load(Ordering::SeqCst) {
            return Err(AcquisitionError::aborted(format!(
                "hashing the image was aborted at byte offset {offset}"
            )));
        }
        let want = (len - offset).min(HASH_CHUNK as u64) as usize;
        let n = loop {
            match file.read_at(&mut buf[..want], offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(AcquisitionError::failed(format!(
                        "read error in the image {} at byte offset {offset}: {e}",
                        path.display()
                    )))
                }
                Ok(n) => break n,
            }
        };
        if n == 0 {
            return Err(AcquisitionError::failed(format!(
                "the image {} ended at byte offset {offset} while it was hashed; {len} bytes were expected",
                path.display()
            )));
        }
        let chunk = &buf[..n];
        if let Some(h) = md5.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = sha1.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = sha256.as_mut() {
            h.update(chunk);
        }
        evict(offset, n as u64);
        offset += n as u64;
        if last.elapsed() >= Duration::from_millis(100) || offset == len {
            progress(offset, len);
            last = Instant::now();
        }
    }
    Ok(HashResults {
        md5: md5.map(|h| hex::encode(h.finalize())),
        sha1: sha1.map(|h| hex::encode(h.finalize())),
        sha256: sha256.map(|h| hex::encode(h.finalize())),
    })
}

// ---------------------------------------------------------------------------
// Identity record and resume
// ---------------------------------------------------------------------------

/// Version of [`IdentityRecord`].
pub const IDENTITY_RECORD_SCHEMA: u32 = 1;

/// `<base>.identity.json`: who the source was when the rescue first started.
/// Written once, never changed; a resume must match it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub schema_version: u32,
    pub purpose: String,
    pub recorded_at: DateTime<Utc>,
    pub dfdisk_version: String,
    pub dfdisk_git_rev: String,
    pub base_name: String,
    /// The path ddrescue read the source through
    pub tool_source_path: String,
    pub sector_size: u32,
    pub identity: SourceIdentity,
}

impl IdentityRecord {
    pub fn new(
        identity: &SourceIdentity,
        base_name: &str,
        tool_source_path: &str,
        sector_size: u32,
    ) -> Self {
        Self {
            schema_version: IDENTITY_RECORD_SCHEMA,
            purpose: "identity of the source of this rescue at its first start; a resumed rescue must be the same device of the same size".into(),
            recorded_at: Utc::now(),
            dfdisk_version: DFDISK_VERSION.into(),
            dfdisk_git_rev: DFDISK_GIT_REV.into(),
            base_name: base_name.into(),
            tool_source_path: tool_source_path.into(),
            sector_size,
            identity: identity.clone(),
        }
    }
}

/// `<dir>/<base>.identity.json`.
pub fn identity_record_path(dir: &Path, base: &str) -> PathBuf {
    dir.join(format!("{base}{IDENTITY_SUFFIX}"))
}

fn write_identity_record(path: &Path, ctx: &EngineContext) -> Result<(), AcquisitionError> {
    if path.exists() {
        return Err(AcquisitionError::refused(format!(
            "{} already exists; refusing to overwrite the identity record of another rescue",
            path.display()
        )));
    }
    let record = IdentityRecord::new(
        &ctx.identity,
        &ctx.base_name,
        &ctx.tool_source_path,
        ctx.sector_size(),
    );
    let json = serde_json::to_string_pretty(&record)
        .map_err(|e| AcquisitionError::failed(format!("cannot encode the identity record: {e}")))?;
    write_atomic(path, json.as_bytes())
        .and_then(|()| sync_dir(path.parent().unwrap_or(Path::new("."))))
        .map_err(|e| {
            AcquisitionError::failed(format!(
                "cannot write the identity record {}: {e}",
                path.display()
            ))
        })
}

/// Read `<base>.identity.json`.
pub fn read_identity_record(path: &Path) -> Result<IdentityRecord, String> {
    let text = fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => format!("the identity record {} does not exist", path.display()),
        _ => format!("the identity record {} cannot be read: {e}", path.display()),
    })?;
    let record: IdentityRecord = serde_json::from_str(&text)
        .map_err(|e| format!("the identity record {} is not valid: {e}", path.display()))?;
    if record.schema_version != IDENTITY_RECORD_SCHEMA {
        return Err(format!(
            "the identity record {} has schema version {}, this dfdisk reads version {IDENTITY_RECORD_SCHEMA}",
            path.display(),
            record.schema_version
        ));
    }
    Ok(record)
}

/// Every serial value of `id` with where it was read (`None`: the preferred
/// serial without a candidate entry).
fn serial_values(id: &SourceIdentity) -> Vec<(Option<SerialSource>, String)> {
    let mut v: Vec<(Option<SerialSource>, String)> = id
        .serial_candidates
        .iter()
        .map(|c| (Some(c.source), c.value.trim().to_string()))
        .filter(|(_, s)| !s.is_empty())
        .collect();
    if let Some(s) = id
        .serial
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !v.iter().any(|(_, x)| x.eq_ignore_ascii_case(s)) {
            v.push((None, s.to_string()));
        }
    }
    v
}

fn distinct(values: &[(Option<SerialSource>, String)]) -> String {
    let mut out: Vec<&str> = Vec::new();
    for (_, s) in values {
        if !out.iter().any(|x| x.eq_ignore_ascii_case(s)) {
            out.push(s);
        }
    }
    out.join(" / ")
}

/// The serial that ties `now` to `recorded`: `Ok(None)` when neither has a
/// serial; `Err` when only one has one, when a source both read differs (e.g.
/// another drive behind the same USB bridge answers IDENTIFY differently),
/// or when no value is shared.
fn serial_tie(recorded: &SourceIdentity, now: &SourceIdentity) -> Result<Option<String>, String> {
    let a = serial_values(recorded);
    let b = serial_values(now);
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ok(None),
        (true, false) => {
            return Err(format!(
                "serial {}, the first start recorded none",
                distinct(&b)
            ))
        }
        (false, true) => return Err(format!("no serial reported, was {}", distinct(&a))),
        (false, false) => {}
    }
    for (sa, x) in &a {
        for (sb, y) in &b {
            if let (Some(sa), Some(sb)) = (sa, sb) {
                if sa == sb && !x.eq_ignore_ascii_case(y) {
                    return Err(format!("serial {y} ({}), was {x}", sa.label()));
                }
            }
        }
    }
    a.iter()
        .find(|(_, x)| b.iter().any(|(_, y)| x.eq_ignore_ascii_case(y)))
        .map(|(_, x)| Some(x.clone()))
        .ok_or_else(|| format!("serial {}, was {}", distinct(&b), distinct(&a)))
}

/// Attached through USB (transport "usb").
fn is_usb(id: &SourceIdentity) -> bool {
    id.transport
        .as_deref()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("usb"))
}

/// The serial the drive itself reported through ATA IDENTIFY (smartctl),
/// when both identities have it and it is the same: behind a USB bridge the
/// only serial that names the drive rather than the bridge.
fn drive_serial_tie(recorded: &SourceIdentity, now: &SourceIdentity) -> Option<String> {
    let identify = |id: &SourceIdentity| -> Option<String> {
        id.serial_candidates
            .iter()
            .find(|c| c.source == SerialSource::SmartctlIdentify)
            .map(|c| c.value.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    match (identify(recorded), identify(now)) {
        (Some(a), Some(b)) if a.eq_ignore_ascii_case(&b) => Some(b),
        _ => None,
    }
}

/// The same attachment: kernel name and major:minor, and the disk sequence
/// number where both have one (a new attachment gets a new one).
fn same_attachment(recorded: &SourceIdentity, now: &SourceIdentity) -> bool {
    let seq_ok = match (recorded.diskseq, now.diskseq) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    recorded.maj_min.is_some()
        && recorded.maj_min == now.maj_min
        && recorded.kernel_name == now.kernel_name
        && seq_ok
}

/// "sdx, major:minor 8:16, disk sequence number 7".
fn attachment(id: &SourceIdentity) -> String {
    format!(
        "{}, major:minor {}{}",
        id.kernel_name,
        id.maj_min.as_deref().unwrap_or("unknown"),
        id.diskseq
            .map(|s| format!(", disk sequence number {s}"))
            .unwrap_or_else(|| ", disk sequence number unknown".into())
    )
}

/// Both known and different (trimmed, case-insensitive).
fn differs(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => !a.trim().eq_ignore_ascii_case(b.trim()),
        _ => false,
    }
}

/// Is `now` the device `recorded` describes (same device, same size)?
/// Stricter than dfcore's `same_device`: kind, size, logical sector size,
/// model and partition placement must agree where both are known; a WWN
/// present on both sides must match; the serials must share a value and no
/// serial source may disagree; a device with neither serial nor WWN is
/// accepted only in the same attachment (major:minor, disk sequence number),
/// because a re-attached drive without either cannot be told from another.
/// Behind a USB bridge without a WWN the serials (SCSI VPD page, udev) are
/// the bridge's: only the drive's own ATA IDENTIFY serial on both sides, or
/// the same attachment, ties the drive.
/// Regular files: same canonical path and file identity. `Ok` says what tied
/// them; `Err` lists every difference.
pub fn compare_resume_identity(
    recorded: &SourceIdentity,
    now: &SourceIdentity,
) -> Result<String, String> {
    let mut diffs: Vec<String> = Vec::new();
    let mut basis: Vec<String> = Vec::new();
    if recorded.kind != now.kind {
        diffs.push(format!(
            "{}, was {}",
            now.kind.label(),
            recorded.kind.label()
        ));
    }
    if recorded.size_bytes != now.size_bytes {
        diffs.push(format!(
            "size {} bytes, was {} bytes",
            now.size_bytes, recorded.size_bytes
        ));
    }
    if recorded.logical_sector_size != 0
        && now.logical_sector_size != 0
        && recorded.logical_sector_size != now.logical_sector_size
    {
        diffs.push(format!(
            "logical sector size {} bytes, was {} bytes",
            now.logical_sector_size, recorded.logical_sector_size
        ));
    }
    if now.kind == SourceKind::RegularFile || recorded.kind == SourceKind::RegularFile {
        if recorded.canonical_path != now.canonical_path {
            diffs.push(format!(
                "file {}, was {}",
                now.canonical_path, recorded.canonical_path
            ));
        }
        match (&recorded.file_id, &now.file_id) {
            (Some(a), Some(b)) if a != b => diffs.push(format!(
                "file identity (device:inode) {b}, was {a}: another file at the same path"
            )),
            _ => basis.push(format!("the same file {}", now.canonical_path)),
        }
    } else {
        if differs(&recorded.model, &now.model) {
            diffs.push(format!(
                "model {}, was {}",
                now.model.as_deref().unwrap_or("-"),
                recorded.model.as_deref().unwrap_or("-")
            ));
        }
        if let (Some(a), Some(b)) = (recorded.partition_number, now.partition_number) {
            if a != b {
                diffs.push(format!("partition {b}, was {a}"));
            }
        }
        if let (Some(a), Some(b)) = (recorded.partition_start_sector, now.partition_start_sector) {
            if a != b {
                diffs.push(format!("partition start sector {b}, was {a}"));
            }
        }
        let wwn_pair = match (&recorded.wwn, &now.wwn) {
            (Some(a), Some(b)) => {
                if normalize_wwn(a) == normalize_wwn(b) {
                    basis.push(format!("WWN {b}"));
                } else {
                    diffs.push(format!("WWN {b}, was {a}"));
                }
                true
            }
            _ => false,
        };
        let usb = is_usb(recorded) || is_usb(now);
        match serial_tie(recorded, now) {
            Ok(Some(s)) if usb && !wwn_pair => match drive_serial_tie(recorded, now) {
                Some(drive) => basis.push(format!(
                    "the drive's own serial {drive} (ATA IDENTIFY)"
                )),
                // Behind a USB bridge the serial is the bridge's (SCSI VPD
                // page, udev): another drive of the same model and size in
                // the same enclosure reports it too (R-5)
                None if same_attachment(recorded, now) => basis.push(format!(
                    "serial {s} as the USB bridge reports it, in the same attachment ({})",
                    attachment(now)
                )),
                None => diffs.push(format!(
                    "the source is attached through USB and its serial {s} is the one the USB bridge reports (SCSI VPD page, udev), not the drive's own: another drive of the same model and size behind the same bridge reports it too. Without the drive's own serial (ATA IDENTIFY, read when SMART runs) at the first start and now, or a WWN, only the same attachment can tie it to this rescue; it is now ({}), was ({})",
                    attachment(now),
                    attachment(recorded)
                )),
            },
            Ok(Some(s)) => basis.push(format!("serial {s}")),
            Ok(None) if !wwn_pair => {
                // dfcore's fallback (name + major:minor) cannot tell a
                // re-attached drive from another one: the same attachment only
                if same_attachment(recorded, now) {
                    basis.push(format!(
                        "no serial number or WWN; the same attachment ({})",
                        attachment(now)
                    ));
                } else {
                    diffs.push(format!(
                        "the source reports no serial number and no WWN, so only the same attachment can tie it to this rescue; it is now ({}), was ({}) (a re-attached drive without serial cannot be told from another drive)",
                        attachment(now),
                        attachment(recorded)
                    ));
                }
            }
            Ok(None) => {}
            Err(d) => diffs.push(d),
        }
    }
    if diffs.is_empty() {
        basis.push(format!("{} bytes", now.size_bytes));
        Ok(basis.join(", "))
    } else {
        Err(diffs.join("; "))
    }
}

/// The newest report of the rescue `base` in `dir`: `<base>.info.json` when
/// it exists (the previous session's report before a resume keeps it), else
/// the JSON twin of the highest kept session. (label, path)
fn latest_report_json(dir: &Path, base: &str) -> Option<(String, PathBuf)> {
    let current = dir.join(format!("{base}{INFO_JSON_SUFFIX}"));
    if current.is_file() {
        return Some(("the report of the last session".into(), current));
    }
    kept_sessions(dir, base)
        .into_iter()
        .rev()
        .find_map(|(n, _, json)| json.map(|j| (format!("the report of session {n}"), j)))
}

/// SHA-256 of the auxiliary file whose name ends with `suffix` that the
/// report `json` lists. `Err` when the report cannot be read.
fn digest_listed_in(json: &Path, suffix: &str) -> Result<Option<String>, String> {
    let text = fs::read_to_string(json).map_err(|e| format!("cannot read it: {e}"))?;
    let report =
        ForensicInfoReport::from_json(&text).map_err(|e| format!("it is not readable: {e}"))?;
    Ok(report
        .auxiliary_files
        .iter()
        .find(|f| f.path.to_lowercase().ends_with(suffix))
        .map(|f| f.sha256.clone()))
}

/// The identity record must be the one the newest report lists (R-6): a
/// record changed or replaced after that report cannot tie a resume to the
/// source. Returns the statement; `Err` names both digests.
fn check_identity_record_digest(
    dir: &Path,
    base: &str,
    record: &Path,
) -> Result<String, AcquisitionError> {
    let now = sha256_file(record).map_err(|e| {
        AcquisitionError::refused(format!(
            "cannot resume the rescue: the identity record {} cannot be hashed: {e}",
            record.display()
        ))
    })?;
    let Some((label, report)) = latest_report_json(dir, base) else {
        return Ok(format!(
            "no report of an earlier session lists the identity record {} (SHA-256 {now}); it cannot be compared with one",
            file_name(record)
        ));
    };
    match digest_listed_in(&report, IDENTITY_SUFFIX) {
        Ok(Some(listed)) if listed.eq_ignore_ascii_case(&now) => Ok(format!(
            "the identity record {} (SHA-256 {now}) is the one {label} ({}) lists",
            file_name(record),
            file_name(&report)
        )),
        Ok(Some(listed)) => Err(AcquisitionError::refused(format!(
            "cannot resume the rescue: the identity record {} was changed or replaced after {label} ({}) was written: that report lists SHA-256 {listed}, the record now has {now}. The record is what ties the map and image to the source; dfdisk does not resume on a record it cannot trust. Restore the original record, or start a new rescue under a new evidence number",
            record.display(),
            report.display()
        ))),
        Ok(None) => Ok(format!(
            "{label} ({}) lists no digest of the identity record {} (SHA-256 {now}) to compare it with",
            file_name(&report),
            file_name(record)
        )),
        Err(e) => Ok(format!(
            "the identity record {} (SHA-256 {now}) could not be compared with {label} ({}): {e}",
            file_name(record),
            file_name(&report)
        )),
    }
}

/// Before a resumed rescue writes anything (session step 4, and the engine
/// again with the identity that includes the SMART IDENTIFY serial): the
/// identity recorded at the first start must exist, be the record the newest
/// report lists, and describe this source. Returns the statements for the
/// report; `Refused` otherwise.
pub fn check_resume_identity(
    dir: &Path,
    base: &str,
    now: &SourceIdentity,
) -> Result<Vec<String>, AcquisitionError> {
    let path = identity_record_path(dir, base);
    let record = read_identity_record(&path).map_err(|e| {
        AcquisitionError::refused(format!(
            "cannot resume the rescue: {e}. Without the identity recorded at its first start the map and image cannot be tied to this source; start a new rescue under a new evidence number"
        ))
    })?;
    if !record.base_name.eq_ignore_ascii_case(base) {
        return Err(AcquisitionError::refused(format!(
            "cannot resume the rescue: {} was written for the acquisition {}, not {base}",
            path.display(),
            record.base_name
        )));
    }
    let digest_statement = check_identity_record_digest(dir, base, &path)?;
    let tie = compare_resume_identity(&record.identity, now).map_err(|d| {
        AcquisitionError::refused(format!(
            "cannot resume the rescue: the source is not the device this rescue started on ({d}). The map and image belong to {} ({}, {} bytes, serial {}), recorded at {} in {}. dfdisk never merges two devices into one image",
            record.identity.path,
            record.identity.display_name(),
            record.identity.size_bytes,
            record.identity.serial_with_provenance(),
            record.recorded_at.to_rfc3339(),
            path.display()
        ))
    })?;
    Ok(vec![
        format!(
            "resumed rescue: the source matches the identity recorded at the first start of this rescue ({}, {}): {tie}",
            file_name(&path),
            record.recorded_at.to_rfc3339()
        ),
        digest_statement,
    ])
}

/// Session number of `file_name` if it is a kept report of `base`
/// (`<base>.info.session-N` or `<base>.info.session-N.json`); the flag says
/// whether it is the JSON twin.
fn session_number(base: &str, file_name: &str) -> Option<(u32, bool)> {
    let lower = file_name.to_lowercase();
    let rest = lower.strip_prefix(&format!("{}{SESSION_SUFFIX}", base.to_lowercase()))?;
    let (digits, json) = match rest.strip_suffix(".json") {
        Some(d) => (d, true),
        None => (rest, false),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().map(|n| (n, json))
}

/// The number N of a zero sidecar file `<base>.zeroed-N.bin` or
/// `<base>.zeroed-N.tsv` (case-insensitive, as the outputs are matched).
fn zeroed_number(base: &str, file_name: &str) -> Option<u32> {
    let lower = file_name.to_lowercase();
    let rest = lower.strip_prefix(&format!("{}{ZEROED_SUFFIX}", base.to_lowercase()))?;
    let digits = rest
        .strip_suffix(".bin")
        .or_else(|| rest.strip_suffix(".tsv"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// A kept session: number, text report, JSON report.
type KeptSession = (u32, Option<PathBuf>, Option<PathBuf>);

/// Kept reports of `base` in `dir`, by session number.
fn kept_sessions(dir: &Path, base: &str) -> Vec<KeptSession> {
    let mut sessions: BTreeMap<u32, (Option<PathBuf>, Option<PathBuf>)> = BTreeMap::new();
    for p in preflight::existing_outputs(dir, base) {
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if let Some((n, json)) = session_number(base, &name) {
            let entry = sessions.entry(n).or_default();
            if json {
                entry.1 = Some(p);
            } else {
                entry.0 = Some(p);
            }
        }
    }
    sessions
        .into_iter()
        .map(|(n, (text, json))| (n, text, json))
        .collect()
}

/// The report files of the current session (`<base>.info`,
/// `<base>.info.json`) and of kept session `n`, pairwise.
fn report_and_kept(dir: &Path, base: &str, n: u32) -> [(PathBuf, PathBuf); 2] {
    [
        (
            dir.join(format!("{base}{INFO_SUFFIX}")),
            dir.join(format!("{base}{SESSION_SUFFIX}{n}")),
        ),
        (
            dir.join(format!("{base}{INFO_JSON_SUFFIX}")),
            dir.join(format!("{base}{SESSION_SUFFIX}{n}.json")),
        ),
    ]
}

/// Keep the report of the previous session (`<base>.info`, `<base>.info.json`)
/// as `<base>.info.session-N` and `<base>.info.session-N.json`, N one past the
/// highest kept session. Returns N and the kept files, `None` when there was
/// no report. Never overwrites; a failure part way renames back what was
/// already renamed, so an error leaves the previous report where it was.
pub fn keep_previous_report(dir: &Path, base: &str) -> io::Result<Option<(u32, Vec<PathBuf>)>> {
    let n = kept_sessions(dir, base)
        .last()
        .map(|(n, _, _)| n + 1)
        .unwrap_or(1);
    let pairs: Vec<(PathBuf, PathBuf)> = report_and_kept(dir, base, n)
        .into_iter()
        .filter(|(from, _)| from.exists())
        .collect();
    if pairs.is_empty() {
        return Ok(None);
    }
    if let Some((_, to)) = pairs.iter().find(|(_, to)| to.exists()) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", to.display()),
        ));
    }
    let mut kept: Vec<PathBuf> = Vec::new();
    for (i, (from, to)) in pairs.iter().enumerate() {
        if let Err(e) = fs::rename(from, to) {
            for (back_from, back_to) in &pairs[..i] {
                let _ = fs::rename(back_to, back_from);
            }
            let _ = sync_dir(dir);
            return Err(e);
        }
        kept.push(to.clone());
    }
    sync_dir(dir)?;
    Ok(Some((n, kept)))
}

/// Undo [`keep_previous_report`] for kept session `n` (the resume ended
/// before ddrescue ran): its files get their previous names again. Never
/// overwrites a report of the current session.
fn restore_previous_report(dir: &Path, base: &str, n: u32) -> io::Result<()> {
    for (current, kept) in report_and_kept(dir, base, n) {
        if !kept.exists() {
            continue;
        }
        if current.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already exists", current.display()),
            ));
        }
        fs::rename(&kept, &current)?;
    }
    sync_dir(dir)
}

/// Every kept session report of `base` in `dir`, with the digest of the
/// report file and, from its JSON twin, start, end and outcome.
pub fn list_sessions(dir: &Path, base: &str) -> Vec<SessionInfo> {
    kept_sessions(dir, base)
        .into_iter()
        .filter_map(|(n, text, json)| {
            let report = text.or_else(|| json.clone())?;
            let parsed = json
                .as_deref()
                .and_then(|j| fs::read_to_string(j).ok())
                .and_then(|s| ForensicInfoReport::from_json(&s).ok());
            Some(SessionInfo {
                session: n,
                report_file: report.to_string_lossy().into_owned(),
                report_sha256: sha256_file(&report).ok(),
                started_at: parsed.as_ref().map(|r| r.started_at),
                ended_at: parsed.as_ref().map(|r| r.ended_at),
                outcome: parsed.as_ref().map(|r| r.outcome),
            })
        })
        .collect()
}

/// SHA-256 of the map the report of kept session `session` lists.
fn map_digest_in_report(dir: &Path, base: &str, session: u32) -> Option<String> {
    let json = dir.join(format!("{base}{SESSION_SUFFIX}{session}.json"));
    digest_listed_in(&json, MAP_SUFFIX).ok().flatten()
}

/// What [`prepare_resume`] found and did.
struct PreparedResume {
    sessions: Vec<SessionInfo>,
    notes: Vec<String>,
    /// Number under which the previous report was kept
    kept: Option<u32>,
}

/// Resume: check the identity again (now with the SMART IDENTIFY serial,
/// when SMART ran), keep the previous report, list the sessions and state
/// whether the map changed since the last report. The identity is checked
/// before the previous report is renamed: a refused resume leaves every file
/// as it was (the previous report stays `<base>.info`). The previous report
/// is kept before ddrescue runs, so it is never overwritten.
fn prepare_resume(ctx: &EngineContext, map: &Path) -> Result<PreparedResume, AcquisitionError> {
    let dir = &ctx.output_dir;
    let base = &ctx.base_name;
    // The session checked the identity before anything was written; now the
    // identity includes a SMART IDENTIFY serial when SMART ran. Its
    // statement is the session's (step 4), not repeated here
    check_resume_identity(dir, base, &ctx.identity)?;
    let mut notes = Vec::new();
    let kept = match keep_previous_report(dir, base) {
        Ok(Some((n, files))) => {
            notes.push(format!(
                "the report of the previous session was kept as {}",
                files
                    .iter()
                    .map(|f| file_name(f))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ));
            Some(n)
        }
        Ok(None) => {
            notes.push(
                "no report of the previous session was found: it ended without writing one".into(),
            );
            None
        }
        Err(e) => {
            return Err(AcquisitionError::failed(format!(
                "cannot keep the report of the previous session: {e}"
            )))
        }
    };
    let sessions = list_sessions(dir, base);
    for s in &sessions {
        let when =
            |t: Option<DateTime<Utc>>| t.map(|t| t.to_rfc3339()).unwrap_or_else(|| "?".into());
        notes.push(format!(
            "earlier session {}: {}, {} to {}, report {}{}",
            s.session,
            s.outcome
                .map(|o| o.label().to_string())
                .unwrap_or_else(|| "outcome unknown (no readable JSON report)".into()),
            when(s.started_at),
            when(s.ended_at),
            file_name(Path::new(&s.report_file)),
            s.report_sha256
                .as_deref()
                .map(|h| format!(" (SHA-256 {h})"))
                .unwrap_or_default()
        ));
    }
    match sha256_file(map) {
        Ok(now) => {
            let last = sessions.last();
            let recorded = last.and_then(|s| map_digest_in_report(dir, base, s.session));
            notes.push(match (last, recorded) {
                (Some(s), Some(r)) if r.eq_ignore_ascii_case(&now) => format!(
                    "the map at the start of this session (SHA-256 {now}) is the map the report of session {} lists",
                    s.session
                ),
                (Some(s), Some(r)) => format!(
                    "the map changed after the report of session {} (SHA-256 then {r}, now {now}): a session that ended without a report continued the rescue, or the map was edited; ddrescue continues from the map as it is now",
                    s.session
                ),
                (Some(s), None) => format!(
                    "the map at the start of this session has SHA-256 {now}; the report of session {} lists no map digest to compare it with",
                    s.session
                ),
                (None, _) => format!(
                    "no report of an earlier session exists; the map at the start of this session (SHA-256 {now}) was written by a session that ended without a report"
                ),
            });
        }
        Err(e) => notes.push(format!(
            "the map could not be hashed before this session: {e}"
        )),
    }
    Ok(PreparedResume {
        sessions,
        notes,
        kept,
    })
}

// ---------------------------------------------------------------------------
// ddrescue's status screen (progress only; never a source of facts)
// ---------------------------------------------------------------------------

static ANSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").expect("valid regex"));
static PCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"pct rescued:\s*([0-9]+(?:\.[0-9]+)?)%").expect("valid regex"));
static CURRENT_RATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"current rate:\s*([0-9]+(?:\.[0-9]+)?)\s*([kMGTPEZYR]?)(i?)B/s")
        .expect("valid regex")
});
static AVERAGE_RATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"average rate:\s*([0-9]+(?:\.[0-9]+)?)\s*([kMGTPEZYR]?)(i?)B/s")
        .expect("valid regex")
});
static REMAINING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"remaining time:\s*(.*)$").expect("valid regex"));
static DURATION_PART: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([0-9]+)\s*([dhms])\b").expect("valid regex"));
static PHASE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(Copying|Trimming|Scraping|Retrying|Filling|Generating)\b.*\.\.\.")
        .expect("valid regex")
});

/// Remove terminal control sequences (ddrescue moves the cursor up).
pub fn strip_ansi(line: &str) -> String {
    ANSI.replace_all(line, "").into_owned()
}

fn rate(caps: &regex::Captures<'_>) -> Option<f64> {
    let value: f64 = caps[1].parse().ok()?;
    let base: f64 = if caps[3].is_empty() { 1000.0 } else { 1024.0 };
    let exp = match &caps[2] {
        "" => 0,
        "k" => 1,
        "M" => 2,
        "G" => 3,
        "T" => 4,
        "P" => 5,
        "E" => 6,
        "Z" => 7,
        "Y" => 8,
        _ => 9,
    };
    Some(value * base.powi(exp))
}

/// ddrescue's "remaining time" ("1h 23m", "11s", "2d 3h") in seconds;
/// `None` for "n/a".
pub fn parse_remaining(text: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut any = false;
    for c in DURATION_PART.captures_iter(text) {
        let n: u64 = c[1].parse().ok()?;
        total += n * match &c[2] {
            "d" => 86_400,
            "h" => 3_600,
            "m" => 60,
            _ => 1,
        };
        any = true;
    }
    any.then_some(total)
}

/// What a line of the status screen changed.
#[derive(Debug, Clone, PartialEq)]
pub enum ScreenEvent {
    /// The "pct rescued" line (once per screen refresh)
    Progress,
    /// A new phase, e.g. "Trimming failed blocks... (forwards)"
    Phase(String),
    /// "Finished", "Interrupted by user", the initial status of a resume
    Message(String),
}

/// The latest values of ddrescue's status screen. Display only: rounded,
/// SI-prefixed numbers; the report takes its facts from the map.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScreenStatus {
    pub pct_rescued: Option<f64>,
    /// Bytes per second
    pub current_rate: Option<f64>,
    pub average_rate: Option<f64>,
    pub remaining_secs: Option<u64>,
    pub phase: Option<String>,
}

impl ScreenStatus {
    /// Take one line of ddrescue's standard output.
    pub fn feed(&mut self, raw: &str) -> Option<ScreenEvent> {
        let clean = strip_ansi(raw);
        let line = clean.trim();
        if line.is_empty() {
            return None;
        }
        if let Some(c) = CURRENT_RATE.captures(line) {
            self.current_rate = rate(&c);
        }
        if let Some(c) = AVERAGE_RATE.captures(line) {
            self.average_rate = rate(&c);
        }
        if let Some(c) = PCT.captures(line) {
            self.pct_rescued = c[1].parse().ok();
            self.remaining_secs = REMAINING
                .captures(line)
                .and_then(|r| parse_remaining(&r[1]));
            return Some(ScreenEvent::Progress);
        }
        if PHASE.is_match(line) {
            let phase = sanitize_line(line);
            if self.phase.as_deref() != Some(phase.as_str()) {
                self.phase = Some(phase.clone());
                return Some(ScreenEvent::Phase(phase));
            }
            return None;
        }
        if line == "Finished"
            || line.starts_with("Interrupted")
            || line.starts_with("Initial status")
            // The initial status of a resume ("rescued: .., tried: .., ..")
            || (line.starts_with("rescued:") && line.contains("tried:"))
        {
            return Some(ScreenEvent::Message(sanitize_line(line)));
        }
        None
    }

    /// Copy the values into the progress telemetry.
    pub fn apply(&self, t: &mut ProgressTelemetry, expected: u64, elapsed: Duration) {
        if let Some(p) = self.pct_rescued {
            let p = p.clamp(0.0, 100.0);
            t.percentage = p;
            t.bytes_processed = ((expected as f64 * p / 100.0).round() as u64).min(expected);
        }
        if let Some(r) = self.current_rate {
            t.speed_bps = r;
        }
        if let Some(r) = self.average_rate {
            t.avg_speed_bps = r;
        }
        t.eta_secs = self.remaining_secs;
        t.elapsed_secs = elapsed.as_secs();
        t.status_message = match (&self.phase, self.pct_rescued) {
            (Some(ph), Some(p)) => format!("ddrescue: {ph}, {p:.2}% rescued"),
            (Some(ph), None) => format!("ddrescue: {ph}"),
            (None, Some(p)) => format!("ddrescue: {p:.2}% rescued"),
            (None, None) => "ddrescue running".into(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::process::LineSplitter;
    use crate::engines::session::AcquisitionRequest;
    use crate::models::case::CaseMetadata;
    use crate::models::config::AcquisitionConfig;
    use crate::models::device::BlockDevice;
    use crate::models::outcome::Outcome;

    const MIB: u64 = 1 << 20;
    const BAD_TAIL: &str = include_str!("../../tests/fixtures/ddrescue/bad_tail.map");
    const BAD_MIDDLE: &str = include_str!("../../tests/fixtures/ddrescue/bad_middle.map");
    const INTERRUPTED: &str = include_str!("../../tests/fixtures/ddrescue/interrupted.map");
    const SCREEN_BAD_MIDDLE: &[u8] =
        include_bytes!("../../tests/fixtures/ddrescue/screen_bad_middle.txt");
    const SCREEN_INTERRUPTED: &[u8] =
        include_bytes!("../../tests/fixtures/ddrescue/screen_interrupted.txt");

    fn disk() -> SourceIdentity {
        let mut id = SourceIdentity {
            path: "/dev/sdx".into(),
            canonical_path: "/dev/sdx".into(),
            kernel_name: "sdx".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(7),
            kind: SourceKind::Disk,
            size_bytes: 1_000_204_886_016,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            model: Some("WDC WD10EZEX".into()),
            wwn: Some("0x50014ee2b5a5c5c5".into()),
            ..Default::default()
        };
        id.add_serial_candidate("WD-WCC4M0000001", SerialSource::VpdPage80);
        id.add_serial_candidate("WD-WCC4M0000001", SerialSource::UdevIdSerialShort);
        id
    }

    fn no_serial() -> SourceIdentity {
        SourceIdentity {
            wwn: None,
            serial: None,
            serial_candidates: Vec::new(),
            model: None,
            ..disk()
        }
    }

    #[test]
    fn the_same_disk_resumes_even_re_attached() {
        let rec = disk();
        // Re-plugged: another node, another disk sequence number
        let mut now = disk();
        now.kernel_name = "sdy".into();
        now.path = "/dev/sdy".into();
        now.maj_min = Some("8:32".into());
        now.diskseq = Some(12);
        now.wwn = Some("naa.50014ee2b5a5c5c5".into());
        let tie = compare_resume_identity(&rec, &now).unwrap();
        assert!(
            tie.contains("WWN") && tie.contains("serial WD-WCC4M0000001"),
            "{tie}"
        );
        assert!(tie.contains("1000204886016 bytes"), "{tie}");
        // The first start had an IDENTIFY serial (SMART), this probe has none
        let mut rec = disk();
        rec.add_serial_candidate("WD-WCC4M0000001", SerialSource::SmartctlIdentify);
        assert!(compare_resume_identity(&rec, &disk()).is_ok());
    }

    #[test]
    fn another_device_is_refused_with_every_difference() {
        let rec = disk();
        let mut now = disk();
        now.size_bytes = 500;
        now.wwn = Some("0x5000c500ffffffff".into());
        now.model = Some("Other".into());
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(e.contains("size 500 bytes, was 1000204886016 bytes"), "{e}");
        assert!(e.contains("WWN 0x5000c500ffffffff"), "{e}");
        assert!(e.contains("model Other, was WDC WD10EZEX"), "{e}");

        // Same WWN unknown, other serial
        let mut now = disk();
        now.wwn = None;
        now.serial_candidates.clear();
        now.serial = None;
        now.add_serial_candidate("WD-OTHER", SerialSource::VpdPage80);
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(e.contains("WD-OTHER"), "{e}");

        // A serial now, none at the first start, and the reverse
        let e = compare_resume_identity(&no_serial(), &disk()).unwrap_err();
        assert!(e.contains("the first start recorded none"), "{e}");
        let mut now = no_serial();
        now.wwn = None;
        let mut rec = disk();
        rec.wwn = None;
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(e.contains("no serial reported, was WD-WCC4M0000001"), "{e}");

        // Kind, sector size, partition placement
        let mut now = disk();
        now.kind = SourceKind::Partition;
        now.logical_sector_size = 4096;
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(e.contains("partition, was whole disk"), "{e}");
        assert!(e.contains("logical sector size 4096"), "{e}");
        let mut a = disk();
        a.partition_start_sector = Some(2048);
        a.partition_number = Some(1);
        let mut b = a.clone();
        b.partition_start_sector = Some(4096);
        b.partition_number = Some(2);
        let e = compare_resume_identity(&a, &b).unwrap_err();
        assert!(e.contains("partition start sector 4096, was 2048"), "{e}");
        assert!(e.contains("partition 2, was 1"), "{e}");
    }

    #[test]
    fn another_drive_behind_the_same_usb_bridge_is_refused() {
        // The bridge reports its own serial (VPD); IDENTIFY tells the drives apart
        let mut rec = no_serial();
        rec.transport = Some("usb".into());
        rec.add_serial_candidate("BRIDGE0001", SerialSource::VpdPage80);
        rec.add_serial_candidate("DRIVE-A", SerialSource::SmartctlIdentify);
        let mut now = rec.clone();
        now.serial_candidates.clear();
        now.serial = None;
        now.add_serial_candidate("BRIDGE0001", SerialSource::VpdPage80);
        now.add_serial_candidate("DRIVE-B", SerialSource::SmartctlIdentify);
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(
            e.contains("DRIVE-B (ATA IDENTIFY (smartctl)), was DRIVE-A"),
            "{e}"
        );
        // Without IDENTIFY on this side the bridge serial ties them only in
        // the same attachment
        let mut now = rec.clone();
        now.serial_candidates
            .retain(|c| c.source == SerialSource::VpdPage80);
        now.choose_serial();
        let tie = compare_resume_identity(&rec, &now).unwrap();
        assert!(tie.contains("as the USB bridge reports it"), "{tie}");
        now.diskseq = Some(8);
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(e.contains("is the one the USB bridge reports"), "{e}");
    }

    #[test]
    fn a_usb_bridge_serial_alone_ties_only_the_same_attachment() {
        // R-5: SMART did not run at the first start; the bridge's serial is
        // all there is, and another drive in the same enclosure has it too
        let mut rec = no_serial();
        rec.transport = Some("usb".into());
        rec.model = Some("ST2000DM008".into());
        rec.add_serial_candidate("BRIDGE0001", SerialSource::VpdPage80);
        rec.add_serial_candidate("BRIDGE0001", SerialSource::UdevIdSerialShort);
        let mut other_drive = rec.clone();
        other_drive.kernel_name = "sdy".into();
        other_drive.maj_min = Some("8:32".into());
        other_drive.diskseq = Some(12);
        let e = compare_resume_identity(&rec, &other_drive).unwrap_err();
        assert!(
            e.contains("serial BRIDGE0001 is the one the USB bridge"),
            "{e}"
        );
        assert!(e.contains("ATA IDENTIFY"), "{e}");
        assert!(
            e.contains(
                "it is now (sdy, major:minor 8:32, disk sequence number 12), was (sdx, major:minor 8:16, disk sequence number 7)"
            ),
            "{e}"
        );
        // SMART now, but not at the first start: still the bridge's serial
        let mut smart_now = other_drive.clone();
        smart_now.add_serial_candidate("DRIVE-B", SerialSource::SmartctlIdentify);
        assert!(compare_resume_identity(&rec, &smart_now).is_err());
        // The same attachment (never unplugged): the same drive
        assert!(compare_resume_identity(&rec, &rec.clone()).is_ok());
        // The drive's own serial on both sides ties a re-attached drive
        let mut rec_smart = rec.clone();
        rec_smart.add_serial_candidate("DRIVE-A", SerialSource::SmartctlIdentify);
        let mut again = other_drive.clone();
        again.add_serial_candidate("DRIVE-A", SerialSource::SmartctlIdentify);
        let tie = compare_resume_identity(&rec_smart, &again).unwrap();
        assert!(tie.contains("the drive's own serial DRIVE-A"), "{tie}");
        // A WWN ties as on any transport
        let mut a = rec.clone();
        a.wwn = Some("0x5000c500a1b2c3d4".into());
        let mut b = other_drive.clone();
        b.wwn = a.wwn.clone();
        assert!(compare_resume_identity(&a, &b).unwrap().contains("WWN"));
        // Not USB: the serial ties a re-attached drive as before
        let mut sata = rec.clone();
        sata.transport = Some("sata".into());
        let mut sata_now = other_drive.clone();
        sata_now.transport = Some("sata".into());
        assert!(compare_resume_identity(&sata, &sata_now).is_ok());
    }

    #[test]
    fn a_device_without_serial_or_wwn_resumes_only_in_the_same_attachment() {
        let rec = no_serial();
        let tie = compare_resume_identity(&rec, &no_serial()).unwrap();
        assert!(
            tie.contains("the same attachment (sdx, major:minor 8:16, disk sequence number 7)"),
            "{tie}"
        );
        // Re-attached (new disk sequence number): cannot be told from another drive
        let mut now = no_serial();
        now.diskseq = Some(8);
        let e = compare_resume_identity(&rec, &now).unwrap_err();
        assert!(e.contains("only the same attachment"), "{e}");
        let mut now = no_serial();
        now.maj_min = Some("8:32".into());
        assert!(compare_resume_identity(&rec, &now).is_err());
        // WWN alone ties a device without serial
        let mut a = no_serial();
        a.wwn = Some("eui.0025388b91b0a1c2".into());
        let mut b = a.clone();
        b.diskseq = Some(99);
        assert!(compare_resume_identity(&a, &b).unwrap().contains("WWN"));
    }

    #[test]
    fn regular_files_resume_only_as_the_same_file() {
        let f = SourceIdentity {
            path: "/x/src.bin".into(),
            canonical_path: "/x/src.bin".into(),
            kind: SourceKind::RegularFile,
            size_bytes: 4096,
            logical_sector_size: 512,
            file_id: Some("2049:77".into()),
            ..Default::default()
        };
        assert!(compare_resume_identity(&f, &f.clone())
            .unwrap()
            .contains("the same file /x/src.bin"));
        let mut other = f.clone();
        other.file_id = Some("2049:78".into());
        let e = compare_resume_identity(&f, &other).unwrap_err();
        assert!(e.contains("another file at the same path"), "{e}");
        let mut moved = f.clone();
        moved.canonical_path = "/y/src.bin".into();
        assert!(compare_resume_identity(&f, &moved).is_err());
        assert!(compare_resume_identity(&f, &disk()).is_err());
    }

    #[test]
    fn the_identity_record_ties_a_resume_to_its_source() {
        let dir = tempfile::tempdir().unwrap();
        let base = "c_01_e_SER";
        // Missing record: refused
        let e = check_resume_identity(dir.path(), base, &disk()).unwrap_err();
        assert!(e.is_refusal());
        assert!(e.message.contains("does not exist"), "{e}");

        let record = IdentityRecord::new(&disk(), base, "/dev/disk/by-diskseq/7", 512);
        let path = identity_record_path(dir.path(), base);
        std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap()).unwrap();
        assert_eq!(read_identity_record(&path).unwrap(), record);
        let notes = check_resume_identity(dir.path(), base, &disk()).unwrap();
        assert!(
            notes[0].starts_with("resumed rescue: the source matches"),
            "{notes:?}"
        );

        let mut other = disk();
        other.size_bytes = 1;
        let e = check_resume_identity(dir.path(), base, &other).unwrap_err();
        assert!(e.is_refusal());
        assert!(
            e.message.contains("not the device this rescue started on"),
            "{e}"
        );
        assert!(e.message.contains("never merges two devices"), "{e}");

        // A record of another acquisition, a broken record, an unknown schema
        let foreign = IdentityRecord::new(&disk(), "other", "/dev/sdx", 512);
        std::fs::write(&path, serde_json::to_string(&foreign).unwrap()).unwrap();
        assert!(check_resume_identity(dir.path(), base, &disk())
            .unwrap_err()
            .message
            .contains("written for the acquisition other"));
        std::fs::write(&path, "{").unwrap();
        assert!(read_identity_record(&path)
            .unwrap_err()
            .contains("not valid"));
        let mut future = record.clone();
        future.schema_version = 99;
        std::fs::write(&path, serde_json::to_string(&future).unwrap()).unwrap();
        assert!(read_identity_record(&path)
            .unwrap_err()
            .contains("schema version 99"));
    }

    fn report_json(outcome: Outcome, map_sha: &str) -> String {
        report_json_listing(outcome, map_sha, None)
    }

    /// A rescue report listing the map and, when given, the identity record.
    fn report_json_listing(outcome: Outcome, map_sha: &str, identity_sha: Option<&str>) -> String {
        let source = disk();
        let config = AcquisitionConfig::rescue("/out");
        let mut r = ForensicInfoReport::new(
            crate::models::config::EngineKind::Rescue,
            &CaseMetadata::default(),
            source.clone(),
            crate::models::config::EffectiveConfig::build(&config, Some(&source)),
        );
        r.outcome = outcome;
        r.auxiliary_files
            .push(crate::models::info_report::FileDigest {
                path: "/out/b.map".into(),
                sha256: map_sha.into(),
            });
        if let Some(sha) = identity_sha {
            r.auxiliary_files
                .push(crate::models::info_report::FileDigest {
                    path: "/out/b.identity.json".into(),
                    sha256: sha.into(),
                });
        }
        r.to_json()
    }

    #[test]
    fn the_identity_record_must_be_the_one_the_last_report_lists() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let base = "b";
        let record = IdentityRecord::new(&disk(), base, "/dev/sdx", 512);
        let path = identity_record_path(d, base);
        std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap()).unwrap();
        let sha = sha256_file(&path).unwrap();

        // No report yet: stated, not refused
        let notes = check_resume_identity(d, base, &disk()).unwrap();
        assert!(
            notes[1].contains("no report of an earlier session lists"),
            "{notes:?}"
        );
        // The last report lists this record
        std::fs::write(
            d.join("b.info.json"),
            report_json_listing(Outcome::Aborted, "aa", Some(&sha)),
        )
        .unwrap();
        let notes = check_resume_identity(d, base, &disk()).unwrap();
        assert!(
            notes[1].contains(&format!(
                "(SHA-256 {sha}) is the one the report of the last session (b.info.json) lists"
            )),
            "{notes:?}"
        );
        // The record was replaced afterwards (same identity, other bytes)
        std::fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();
        let e = check_resume_identity(d, base, &disk()).unwrap_err();
        assert!(e.is_refusal(), "{e}");
        assert!(e.message.contains("changed or replaced"), "{e}");
        assert!(e.message.contains(&sha), "{e}");
        // Kept as session 1 by an earlier resume: compared all the same
        std::fs::rename(d.join("b.info.json"), d.join("b.info.session-1.json")).unwrap();
        let e = check_resume_identity(d, base, &disk()).unwrap_err();
        assert!(e.message.contains("the report of session 1"), "{e}");
        // A report without the record's digest: stated
        std::fs::write(
            d.join("b.info.json"),
            report_json_listing(Outcome::Aborted, "aa", None),
        )
        .unwrap();
        let notes = check_resume_identity(d, base, &disk()).unwrap();
        assert!(notes[1].contains("lists no digest"), "{notes:?}");
    }

    #[test]
    fn earlier_reports_are_kept_numbered_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let base = "b";
        assert_eq!(keep_previous_report(d, base).unwrap(), None);
        std::fs::write(d.join("b.info"), "first").unwrap();
        std::fs::write(d.join("b.info.json"), report_json(Outcome::Aborted, "aa")).unwrap();
        let (n, kept) = keep_previous_report(d, base).unwrap().unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            kept,
            vec![d.join("b.info.session-1"), d.join("b.info.session-1.json")]
        );
        assert!(!d.join("b.info").exists());
        std::fs::write(d.join("b.info"), "second").unwrap();
        let (n, _) = keep_previous_report(d, base).unwrap().unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            std::fs::read_to_string(d.join("b.info.session-1")).unwrap(),
            "first"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("b.info.session-2")).unwrap(),
            "second"
        );
        // Numbering continues after the highest, gaps are not reused
        std::fs::write(d.join("b.info.session-7.json"), "{}").unwrap();
        std::fs::write(d.join("b.info"), "third").unwrap();
        assert_eq!(keep_previous_report(d, base).unwrap().unwrap().0, 8);

        let sessions = list_sessions(d, base);
        assert_eq!(
            sessions.iter().map(|s| s.session).collect::<Vec<_>>(),
            vec![1, 2, 7, 8]
        );
        assert_eq!(sessions[0].outcome, Some(Outcome::Aborted));
        assert_eq!(
            sessions[0].report_sha256.as_deref(),
            Some(crate::models::info_report::sha256_hex(b"first").as_str())
        );
        assert_eq!(sessions[1].outcome, None);
        assert!(sessions[2].report_file.ends_with("b.info.session-7.json"));
        assert_eq!(map_digest_in_report(d, base, 1).as_deref(), Some("aa"));
        assert_eq!(map_digest_in_report(d, base, 2), None);
        // Other names are not sessions
        assert_eq!(session_number("b", "b.info.session-"), None);
        assert_eq!(session_number("b", "b.info.session-x.json"), None);
        assert_eq!(session_number("B", "b.INFO.SESSION-3"), Some((3, false)));
        // A later resume accepts every kept report and its JSON twin
        for (n, _, _) in kept_sessions(d, base) {
            for name in [
                format!("b.info.session-{n}"),
                format!("b.info.session-{n}.json"),
            ] {
                assert!(preflight::resume_may_exist(base, &name), "{name}");
            }
        }
        assert!(!preflight::resume_may_exist(base, "b.info.session-.json"));
    }

    /// The sidecar of session `n` of base "b" in `dir`.
    fn zs(dir: &Path, n: u32) -> ZeroSidecar {
        ZeroSidecar::new(dir, "b", n)
    }

    /// (image offset, length, bin offset, SHA-256) rows of a .tsv sidecar.
    fn tsv_rows(path: &Path) -> Vec<(u64, u64, u64, String)> {
        let text = std::fs::read_to_string(path).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some(ZEROED_TSV_HEADER));
        lines
            .map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                assert_eq!(f.len(), 4, "{l}");
                (
                    f[0].parse().unwrap(),
                    f[1].parse().unwrap(),
                    f[2].parse().unwrap(),
                    f[3].to_string(),
                )
            })
            .collect()
    }

    fn sha256_of(bytes: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(bytes))
    }

    #[test]
    fn a_finished_image_short_of_its_bad_tail_is_extended() {
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("b.map");
        let image = dir.path().join("b.raw");
        std::fs::write(&map, BAD_TAIL).unwrap();
        std::fs::write(&image, vec![7u8; (MIB - 0x400) as usize]).unwrap();
        let fin = finalize(&map, &image, MIB, 512, &zs(dir.path(), 1));
        assert_eq!(std::fs::metadata(&image).unwrap().len(), MIB);
        assert_eq!(fin.bytes_acquired, MIB);
        assert_eq!(fin.read_errors.substituted_bytes(), 0x400);
        assert_eq!(fin.read_errors.unread_bytes(), 0);
        assert_eq!(fin.bad_sectors, 2);
        assert!(fin.stop_reason.is_none());
        assert!(
            fin.notes[0].contains("extended from 1047552 to 1048576 bytes"),
            "{:?}",
            fin.notes
        );
        assert!(
            fin.notes[1].contains("GNU ddrescue version 1.30"),
            "{:?}",
            fin.notes
        );
        let data = std::fs::read(&image).unwrap();
        assert!(data[(MIB - 0x400) as usize..].iter().all(|b| *b == 0));
        assert!(data[..(MIB - 0x400) as usize].iter().all(|b| *b == 7));
    }

    #[test]
    fn bad_sector_areas_are_zeros_in_the_image_whatever_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("b.map");
        let image = dir.path().join("b.raw");
        // BAD_MIDDLE: bad 0x10000+0x400 and 0x90000+0x200 in 1 MiB
        std::fs::write(&map, BAD_MIDDLE).unwrap();
        let mut data = vec![7u8; MIB as usize];
        data[0x10000..0x10200].fill(0); // one sector of the first area already zeros
        std::fs::write(&image, &data).unwrap();
        let fin = finalize(&map, &image, MIB, 512, &zs(dir.path(), 1));
        let after = std::fs::read(&image).unwrap();
        assert!(after[0x10000..0x10400].iter().all(|b| *b == 0));
        assert!(after[0x90000..0x90200].iter().all(|b| *b == 0));
        assert!(after[..0x10000].iter().all(|b| *b == 7));
        assert!(after[0x10400..0x90000].iter().all(|b| *b == 7));
        assert!(after[0x90200..].iter().all(|b| *b == 7));
        assert_eq!(after.len(), MIB as usize);
        assert_eq!(fin.stop_reason, None);
        assert_eq!(fin.read_errors.substituted_bytes(), 0x600);
        let notes = fin.notes.join("\n");
        assert!(
            notes.contains(
                "dfdisk wrote zeros over the 2 bad-sector areas of the map inside the image (1536 bytes)"
            ),
            "{notes}"
        );
        assert!(
            notes.contains("2 sectors (512-byte) held other data before"),
            "{notes}"
        );
        // S-N3: the bytes the zeros replaced are kept, with their places and
        // digests, and listed as files of the report
        let kept = zs(dir.path(), 1);
        assert!(
            notes.contains("their bytes are kept in b.zeroed-1.bin with their image offsets and SHA-256 in b.zeroed-1.tsv"),
            "{notes}"
        );
        assert_eq!(fin.auxiliary_files, [kept.bin.clone(), kept.tsv.clone()]);
        let bin = std::fs::read(&kept.bin).unwrap();
        let mut expected = data[0x10200..0x10400].to_vec();
        expected.extend_from_slice(&data[0x90000..0x90200]);
        assert_eq!(bin, expected);
        assert_eq!(
            tsv_rows(&kept.tsv),
            [
                (0x10200, 0x200, 0, sha256_of(&data[0x10200..0x10400])),
                (0x90000, 0x200, 0x200, sha256_of(&data[0x90000..0x90200])),
            ]
        );
        // Run again: nothing but zeros there now, so nothing is kept
        let fin = finalize(&map, &image, MIB, 512, &zs(dir.path(), 2));
        assert!(
            fin.notes
                .join("\n")
                .contains("none of their sectors held other data before"),
            "{:?}",
            fin.notes
        );
        assert!(fin.auxiliary_files.is_empty());
        assert!(!zs(dir.path(), 2).bin.exists() && !zs(dir.path(), 2).tsv.exists());
        // Bad areas beyond the end of an unfinished image are not written
        std::fs::write(&image, vec![7u8; 0x10200]).unwrap();
        let fin = finalize(&map, &image, MIB, 512, &zs(dir.path(), 3));
        let after = std::fs::read(&image).unwrap();
        assert_eq!(after.len(), 0x10200);
        assert!(after[0x10000..].iter().all(|b| *b == 0));
        assert!(
            fin.notes
                .join("\n")
                .contains("the 1 bad-sector area of the map inside the image (512 bytes)"),
            "{:?}",
            fin.notes
        );
    }

    #[test]
    fn an_image_that_cannot_be_zeroed_is_not_claimed_to_hold_zeros() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("b.map");
        let image = dir.path().join("b.raw");
        std::fs::write(&map, BAD_MIDDLE).unwrap();
        std::fs::write(&image, vec![7u8; MIB as usize]).unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o444)).unwrap();
        if OpenOptions::new().write(true).open(&image).is_ok() {
            // root ignores the mode: nothing to test here
            return;
        }
        let fin = finalize(&map, &image, MIB, 512, &zs(dir.path(), 1));
        let stop = fin.stop_reason.unwrap();
        assert!(
            stop.contains("could not write zeros over the bad-sector areas"),
            "{stop}"
        );
        // E-R3-1: the bad-sector areas are not called zeros anywhere
        assert_eq!(fin.read_errors.substituted_bytes(), 0);
        assert_eq!(fin.read_errors.unread_bytes(), 0x600);
        assert_eq!(fin.bytes_acquired, MIB - 0x600);
    }

    #[test]
    fn kept_bytes_are_never_overwritten_and_nothing_is_zeroed_without_them() {
        // S-N3: the sidecar of this session exists already (create_new):
        // the zeros are not written, the image keeps its data, the existing
        // files are untouched, and the report does not claim zeros
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("b.map");
        let image = dir.path().join("b.raw");
        std::fs::write(&map, BAD_MIDDLE).unwrap();
        std::fs::write(&image, vec![7u8; MIB as usize]).unwrap();
        let kept = zs(dir.path(), 4);
        let refused = |existing: &Path, other: &Path| {
            std::fs::write(existing, "earlier\n").unwrap();
            let fin = finalize(&map, &image, MIB, 512, &kept);
            let stop = fin.stop_reason.unwrap();
            assert!(
                stop.contains("could not write zeros over the bad-sector areas"),
                "{stop}"
            );
            assert!(stop.contains("nothing was overwritten"), "{stop}");
            assert_eq!(std::fs::read(existing).unwrap(), b"earlier\n");
            assert!(!other.exists(), "{} left behind", other.display());
            assert!(std::fs::read(&image).unwrap().iter().all(|b| *b == 7));
            assert!(fin.auxiliary_files.is_empty());
            assert!(!fin.notes.iter().any(|n| n.contains("dfdisk wrote zeros")));
            // E-R3-1: they are not acquired, not zeros
            assert_eq!(fin.read_errors.substituted_bytes(), 0);
            assert_eq!(fin.read_errors.unread_bytes(), 0x600);
            assert_eq!(fin.bytes_acquired, MIB - 0x600);
            assert!(
                fin.notes
                    .iter()
                    .any(|n| n.contains("count as not acquired, not as zeros")),
                "{:?}",
                fin.notes
            );
            std::fs::remove_file(existing).unwrap();
        };
        refused(&kept.bin, &kept.tsv);
        // The .tsv exists: the .bin this run wrote is removed again
        refused(&kept.tsv, &kept.bin);
        // No data in the bad areas: nothing is written at all
        let clean = tempfile::tempdir().unwrap();
        let map = clean.path().join("b.map");
        let image = clean.path().join("b.raw");
        std::fs::write(&map, BAD_MIDDLE).unwrap();
        std::fs::write(&image, vec![0u8; MIB as usize]).unwrap();
        let fin = finalize(&map, &image, MIB, 512, &zs(clean.path(), 1));
        assert_eq!(fin.stop_reason, None);
        assert!(fin.auxiliary_files.is_empty());
        assert_eq!(std::fs::read_dir(clean.path()).unwrap().count(), 2);
    }

    #[test]
    fn an_unfinished_or_inconsistent_image_is_never_padded() {
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("b.map");
        let image = dir.path().join("b.raw");
        // Interrupted: non-tried blocks remain
        std::fs::write(&map, INTERRUPTED).unwrap();
        std::fs::write(&image, vec![1u8; 0xA0000]).unwrap();
        let fin = finalize(&map, &image, 4 * MIB, 512, &zs(dir.path(), 1));
        assert_eq!(std::fs::metadata(&image).unwrap().len(), 0xA0000);
        assert_eq!(fin.bytes_acquired, 0xA0000);
        assert_eq!(fin.read_errors.unread_bytes(), 4 * MIB - 0xA0000);
        // Finished map, but the image lacks rescued data at its end
        std::fs::write(&map, BAD_MIDDLE).unwrap();
        std::fs::write(&image, vec![1u8; (MIB / 2) as usize]).unwrap();
        let fin = finalize(&map, &image, MIB, 512, &zs(dir.path(), 1));
        assert_eq!(std::fs::metadata(&image).unwrap().len(), MIB / 2);
        assert_eq!(fin.read_errors.unread_bytes(), MIB / 2);
        assert!(fin
            .notes
            .iter()
            .any(|n| n.contains("as rescued beyond the end of the image file")));
        // A map for a smaller source: not covering this one
        std::fs::write(&map, BAD_TAIL).unwrap();
        std::fs::write(&image, vec![1u8; (MIB - 0x400) as usize]).unwrap();
        let fin = finalize(&map, &image, 2 * MIB, 512, &zs(dir.path(), 1));
        assert_eq!(std::fs::metadata(&image).unwrap().len(), MIB - 0x400);
        assert_eq!(fin.read_errors.unread_bytes(), MIB + 0x400);
        assert!(fin.notes.iter().any(|n| n.contains("does not list")));
    }

    #[test]
    fn without_a_readable_map_nothing_is_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let map = dir.path().join("b.map");
        let image = dir.path().join("b.raw");
        std::fs::write(&image, vec![1u8; 4096]).unwrap();
        for content in [None, Some("not a map\n")] {
            if let Some(c) = content {
                std::fs::write(&map, c).unwrap();
            }
            let fin = finalize(&map, &image, 4096, 512, &zs(dir.path(), 1));
            assert_eq!(fin.bytes_acquired, 0);
            assert_eq!(fin.read_errors.unread_bytes(), 4096);
            assert!(fin
                .stop_reason
                .unwrap()
                .contains("whole source counts as not acquired"));
        }
    }

    /// Lines of a captured screen as the process runner delivers them.
    fn screen_lines(bytes: &[u8]) -> Vec<String> {
        let mut s = LineSplitter::new(64 * 1024);
        let mut lines: Vec<String> = s.feed(bytes).into_iter().map(|l| l.text).collect();
        lines.extend(s.finish().map(|l| l.text));
        lines
    }

    #[test]
    fn progress_from_the_real_status_screen() {
        let mut st = ScreenStatus::default();
        let mut phases = Vec::new();
        let mut messages = Vec::new();
        let mut progress = 0;
        for line in screen_lines(SCREEN_BAD_MIDDLE) {
            match st.feed(&line) {
                Some(ScreenEvent::Phase(p)) => phases.push(p),
                Some(ScreenEvent::Message(m)) => messages.push(m),
                Some(ScreenEvent::Progress) => progress += 1,
                None => {}
            }
        }
        assert!(progress >= 3, "{progress}");
        assert_eq!(st.pct_rescued, Some(99.85));
        assert_eq!(st.current_rate, Some(1_047_000.0));
        assert_eq!(st.average_rate, Some(1_047_000.0));
        assert_eq!(st.remaining_secs, None);
        assert_eq!(
            phases,
            vec![
                "Copying non-tried blocks... Pass 1 (forwards)",
                "Copying non-tried blocks... Pass 2 (backwards)",
                "Trimming failed blocks... (forwards)",
            ]
        );
        assert_eq!(messages, vec!["Finished"]);

        let mut t = ProgressTelemetry::default();
        st.apply(&mut t, MIB, Duration::from_secs(3));
        assert_eq!(t.percentage, 99.85);
        assert_eq!(t.bytes_processed, 1_047_003);
        assert_eq!(t.elapsed_secs, 3);
        assert!(
            t.status_message.contains("Trimming failed blocks"),
            "{}",
            t.status_message
        );

        let mut st = ScreenStatus::default();
        let mut messages = Vec::new();
        for line in screen_lines(SCREEN_INTERRUPTED) {
            if let Some(ScreenEvent::Message(m)) = st.feed(&line) {
                messages.push(m);
            }
        }
        assert_eq!(st.pct_rescued, Some(15.62));
        assert_eq!(st.remaining_secs, Some(11));
        assert_eq!(messages, vec!["Interrupted by user"]);
    }

    #[test]
    fn screen_details() {
        assert_eq!(strip_ansi("\x1b[A\x1b[A  ipos: 0 B"), "  ipos: 0 B");
        assert_eq!(parse_remaining("1h 23m"), Some(4980));
        assert_eq!(parse_remaining("2d 3h"), Some(183_600));
        assert_eq!(parse_remaining("n/a"), None);
        let mut st = ScreenStatus::default();
        st.feed("     ipos: 1 B, non-trimmed: 0 B,   current rate:  2.5 MiB/s");
        assert_eq!(st.current_rate, Some(2.5 * 1024.0 * 1024.0));
        st.feed("     opos: 1 B, non-scraped: 0 B,   average rate:  12 B/s");
        assert_eq!(st.average_rate, Some(12.0));
        assert_eq!(
            st.feed("Initial status (read from mapfile)"),
            Some(ScreenEvent::Message(
                "Initial status (read from mapfile)".into()
            ))
        );
        // The initial status of a resume is a message, the status block is not
        assert!(matches!(
            st.feed("rescued: 655360 B, tried: 0 B, bad-sector: 0 B, bad areas: 0"),
            Some(ScreenEvent::Message(_))
        ));
        assert!(st
            .feed("  rescued:   786432 B,   bad areas:          0,       run time:          0s")
            .is_none());
        // A repeated phase is reported once
        assert!(st
            .feed("Retrying bad sectors... Retry 1 (forwards)")
            .is_some());
        assert!(st
            .feed("Retrying bad sectors... Retry 1 (forwards)")
            .is_none());
        assert!(st.feed("GNU ddrescue 1.30").is_none());
    }

    // -----------------------------------------------------------------------
    // The engine against fake ddrescue programs (shell scripts)
    // -----------------------------------------------------------------------

    /// An executable script; waits until it can be executed (ETXTBSY races
    /// with other tests forking while the file was open for writing).
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        for _ in 0..100 {
            match std::process::Command::new(&p).arg("--version").output() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => break,
            }
        }
        p
    }

    /// The fake prints a version for `--version`; otherwise it runs `body`
    /// with $IMG and $MAP set to its last two arguments.
    fn fake_ddrescue(dir: &Path, body: &str) -> PathBuf {
        script(
            dir,
            "fake-ddrescue",
            &format!(
                "if [ \"$1\" = --version ]; then echo 'GNU ddrescue 1.30 (fake)'; exit 0; fi\n\
                 for a; do IMG=\"$MAP\"; MAP=\"$a\"; done\n\
                 echo \"$@\" > \"$MAP.args\"\n{body}"
            ),
        )
    }

    fn context(dir: &Path, size: u64, resume: bool) -> EngineContext {
        let src = dir.join("src.bin");
        std::fs::write(&src, vec![0x5au8; size as usize]).unwrap();
        let identity = crate::discovery::identity::probe_file(&src.to_string_lossy()).unwrap();
        let device = BlockDevice {
            name: "src".into(),
            path: src.to_string_lossy().into_owned(),
            size_bytes: size,
            ..Default::default()
        };
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let config = AcquisitionConfig {
            resume,
            ..AcquisitionConfig::rescue(&out)
        };
        EngineContext::new(
            AcquisitionRequest::new(device, CaseMetadata::default(), config),
            identity,
            "b",
        )
    }

    #[tokio::test]
    async fn the_engine_reports_what_the_map_says() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = fake_ddrescue(
            tmp.path(),
            &format!(
                "head -c {} /dev/zero > \"$IMG\"\nprintf '%s' '{}' > \"$MAP\"\n\
                 echo 'pct rescued:   99.90%, read errors:          2, remaining time:         n/a'\nexit 0\n",
                MIB - 0x400,
                BAD_TAIL
            ),
        );
        let ctx = context(tmp.path(), MIB, false);
        let out = acquire_with(&ctx, fake.as_os_str()).await.unwrap();
        assert!(!out.aborted);
        assert_eq!(out.stop_reason, None);
        assert_eq!(out.bytes_acquired, MIB);
        assert_eq!(out.expected_bytes, MIB);
        assert_eq!(out.read_errors.source, MAP_SOURCE);
        assert_eq!(out.read_errors.substituted_bytes(), 0x400);
        assert_eq!(out.read_errors.ranges[0].offset, MIB - 0x400);
        assert_eq!(out.image_files, vec![ctx.output_path(".raw")]);
        assert_eq!(
            out.auxiliary_files,
            vec![ctx.output_path(".map"), ctx.output_path(".identity.json")]
        );
        assert_eq!(
            std::fs::metadata(ctx.output_path(".raw")).unwrap().len(),
            MIB
        );
        let Some(EngineSettings::Rescue(s)) = &out.settings else {
            panic!("{:?}", out.settings)
        };
        assert!(!s.direct_io && !s.resume);
        assert_eq!((s.retries, s.sector_size), (2, 512));
        // Regular file: no -d; no -I on a first start
        let args = std::fs::read_to_string(tmp.path().join("out/b.map.args")).unwrap();
        assert!(args.starts_with("-r 2 -b 512 "), "{args}");
        assert!(!args.contains("-d ") && !args.contains("-I"), "{args}");
        // The identity record holds the probed identity
        let record = read_identity_record(&ctx.output_path(".identity.json")).unwrap();
        assert_eq!(record.identity, ctx.identity);
        assert_eq!(record.base_name, "b");
        // The command is recorded, with the version
        let rec = ctx.provenance.commands();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].exit_code, Some(0));
        assert_eq!(
            ctx.provenance.tools().get(DDRESCUE).map(String::as_str),
            Some("GNU ddrescue 1.30 (fake)")
        );
        assert_eq!(ctx.progress.snapshot().bad_sectors, 2);
        assert!(out
            .notes
            .iter()
            .any(|n| n.contains("without direct access")));
    }

    #[tokio::test]
    async fn a_failing_ddrescue_is_an_incomplete_rescue_or_an_error() {
        // It wrote a map, then failed: the facts stand, with the reason
        let tmp = tempfile::tempdir().unwrap();
        let fake = fake_ddrescue(
            tmp.path(),
            &format!(
                "printf '%s' '{INTERRUPTED}' > \"$MAP\"\n: > \"$IMG\"\n\
                 echo 'ddrescue: Write error: No space left on device' >&2\nexit 1\n"
            ),
        );
        let ctx = context(tmp.path(), 4 * MIB, false);
        let out = acquire_with(&ctx, fake.as_os_str()).await.unwrap();
        let stop = out.stop_reason.unwrap();
        assert!(stop.contains("exit status 1"), "{stop}");
        assert!(stop.contains("No space left on device"), "{stop}");
        assert_eq!(out.bytes_acquired, 0);
        assert_eq!(out.read_errors.unread_bytes(), 4 * MIB);

        // It wrote nothing: an error, and the identity record goes again
        let tmp = tempfile::tempdir().unwrap();
        let fake = fake_ddrescue(
            tmp.path(),
            "echo 'ddrescue: Cannot open input file' >&2\nexit 1\n",
        );
        let ctx = context(tmp.path(), MIB, false);
        let e = acquire_with(&ctx, fake.as_os_str()).await.unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Failed);
        assert!(e.message.contains("Cannot open input file"), "{e}");
        assert!(!ctx.output_path(".identity.json").exists());

        // Not installed: nothing is written
        let tmp = tempfile::tempdir().unwrap();
        let ctx = context(tmp.path(), MIB, false);
        let missing = tmp.path().join("no-such-ddrescue");
        let e = acquire_with(&ctx, missing.as_os_str()).await.unwrap_err();
        assert!(e.message.contains("not available"), "{e}");
        assert_eq!(
            std::fs::read_dir(tmp.path().join("out")).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn abort_interrupts_ddrescue_which_saves_its_map() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = fake_ddrescue(
            tmp.path(),
            &format!(
                "head -c 655360 /dev/zero > \"$IMG\"\nprintf '%s' '{INTERRUPTED}' > \"$MAP\"\n\
                 trap 'echo Interrupted by user; exit 130' INT\n\
                 i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done\nexit 0\n"
            ),
        );
        let ctx = context(tmp.path(), 4 * MIB, false);
        let abort = ctx.abort.clone();
        // Abort once the fake has written its map (a fixed delay raced with
        // a slow start of the script under load)
        let map = ctx.output_path(".map");
        tokio::spawn(async move {
            for _ in 0..200 {
                if std::fs::metadata(&map).is_ok_and(|m| m.len() > 0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            abort.store(true, Ordering::SeqCst);
        });
        let t0 = Instant::now();
        let out = acquire_with(&ctx, fake.as_os_str()).await.unwrap();
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "SIGINT was not delivered"
        );
        assert!(out.aborted);
        assert_eq!(out.stop_reason, None);
        assert!(
            out.notes.iter().any(|n| n.contains("stopped with SIGINT")),
            "{:?}",
            out.notes
        );
        assert_eq!(out.read_errors.unread_bytes(), 4 * MIB - 0xA0000);
        let rec = &ctx.provenance.commands()[0];
        assert!(
            rec.stop.as_deref().unwrap_or("").contains("SIGINT"),
            "{rec:?}"
        );
    }

    #[tokio::test]
    async fn resume_keeps_the_previous_report_and_passes_dash_i() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = fake_ddrescue(
            tmp.path(),
            &format!("printf '%s' '{BAD_MIDDLE}' > \"$MAP\"\nexit 0\n"),
        );
        // First start
        let ctx = context(tmp.path(), MIB, false);
        std::fs::write(ctx.output_path(".raw"), vec![0u8; MIB as usize]).unwrap();
        acquire_with(&ctx, fake.as_os_str()).await.unwrap();
        let map_sha = sha256_file(&ctx.output_path(".map")).unwrap();
        std::fs::write(ctx.output_path(".info"), "report 1").unwrap();
        std::fs::write(
            ctx.output_path(".info.json"),
            report_json(Outcome::Aborted, &map_sha),
        )
        .unwrap();

        // Resume, same source file
        let ctx2 = context_again(&ctx, true);
        let out = acquire_with(&ctx2, fake.as_os_str()).await.unwrap();
        let args = std::fs::read_to_string(ctx.output_path(".map.args")).unwrap();
        assert!(args.contains("-I "), "{args}");
        assert_eq!(out.resume_sessions.len(), 1);
        assert_eq!(out.resume_sessions[0].session, 1);
        assert_eq!(out.resume_sessions[0].outcome, Some(Outcome::Aborted));
        assert!(!ctx.output_path(".info").exists());
        assert_eq!(
            std::fs::read_to_string(ctx.output_path(".info.session-1")).unwrap(),
            "report 1"
        );
        let notes = out.notes.join("\n");
        assert!(
            notes.contains("kept as b.info.session-1 and b.info.session-1.json"),
            "{notes}"
        );
        assert!(
            notes.contains("is the map the report of session 1 lists"),
            "{notes}"
        );
        let Some(EngineSettings::Rescue(s)) = &out.settings else {
            panic!()
        };
        assert!(s.resume);
        // The identity record is not rewritten and is still listed
        assert!(out
            .auxiliary_files
            .contains(&ctx.output_path(".identity.json")));

        // Resuming again: the map changed since the last kept report
        std::fs::write(ctx.output_path(".info"), "report 2").unwrap();
        std::fs::write(
            ctx.output_path(".info.json"),
            report_json(Outcome::Incomplete, "00"),
        )
        .unwrap();
        let out = acquire_with(&ctx2, fake.as_os_str()).await.unwrap();
        assert_eq!(out.resume_sessions.len(), 2);
        assert!(out
            .notes
            .join("\n")
            .contains("the map changed after the report of session 2"));

        // Another file at the same path: refused before anything is renamed;
        // the previous report stays the report of the rescue (R-1)
        std::fs::write(ctx.output_path(".info"), "report 3").unwrap();
        std::fs::write(
            ctx.output_path(".info.json"),
            report_json(Outcome::Incomplete, "00"),
        )
        .unwrap();
        let mut ctx3 = context_again(&ctx, true);
        ctx3.identity.file_id = Some("0:0".into());
        let e = acquire_with(&ctx3, fake.as_os_str()).await.unwrap_err();
        assert!(e.is_refusal(), "{e}");
        assert_eq!(
            std::fs::read_to_string(ctx.output_path(".info")).unwrap(),
            "report 3"
        );
        assert!(ctx.output_path(".info.json").exists());
        assert!(!ctx.output_path(".info.session-3").exists());
        assert!(!ctx.output_path(".info.session-3.json").exists());
    }

    #[tokio::test]
    async fn data_a_killed_session_left_in_bad_areas_is_zeroed_on_resume() {
        // R-2: the first session wrote the whole image but was killed before
        // ddrescue saved a map listing it; the resumed session finds those
        // areas unreadable and marks them bad without writing them
        let tmp = tempfile::tempdir().unwrap();
        let first = fake_ddrescue(
            tmp.path(),
            &format!(
                "head -c {MIB} /dev/zero | tr '\\0' 'Z' > \"$IMG\"\nprintf '%s' '{INTERRUPTED}' > \"$MAP\"\nkill -KILL $$\n"
            ),
        );
        let ctx = context(tmp.path(), MIB, false);
        let out = acquire_with(&ctx, first.as_os_str()).await.unwrap();
        assert!(out.stop_reason.is_some(), "{out:?}");
        let resumed = script(
            tmp.path(),
            "resumed-ddrescue",
            &format!(
                "if [ \"$1\" = --version ]; then echo 'GNU ddrescue 1.30 (fake)'; exit 0; fi\n\
                 for a; do MAP=\"$a\"; done\nprintf '%s' '{BAD_MIDDLE}' > \"$MAP\"\nexit 0\n"
            ),
        );
        let out = acquire_with(&context_again(&ctx, true), resumed.as_os_str())
            .await
            .unwrap();
        assert_eq!(out.stop_reason, None);
        assert_eq!(out.read_errors.substituted_bytes(), 0x600);
        let image = std::fs::read(ctx.output_path(".raw")).unwrap();
        assert!(image[0x10000..0x10400].iter().all(|b| *b == 0));
        assert!(image[0x90000..0x90200].iter().all(|b| *b == 0));
        assert!(image[..0x10000].iter().all(|b| *b == b'Z'));
        assert!(image[0x90200..].iter().all(|b| *b == b'Z'));
        let notes = out.notes.join("\n");
        assert!(
            notes.contains("3 sectors (512-byte) held other data before"),
            "{notes}"
        );
        // S-N3: what the zeros replaced is kept (session 1: no report of an
        // earlier session exists) and listed with the files of the run
        let kept = ZeroSidecar::new(&ctx.output_dir, "b", 1);
        assert_eq!(std::fs::read(&kept.bin).unwrap(), vec![b'Z'; 0x600]);
        assert_eq!(
            tsv_rows(&kept.tsv),
            [
                (0x10000, 0x400, 0, sha256_of(&[b'Z'; 0x400])),
                (0x90000, 0x200, 0x400, sha256_of(&[b'Z'; 0x200])),
            ]
        );
        assert!(out.auxiliary_files.contains(&kept.bin));
        assert!(out.auxiliary_files.contains(&kept.tsv));
        assert!(
            notes.contains("their bytes are kept in b.zeroed-1.bin"),
            "{notes}"
        );
    }

    #[tokio::test]
    async fn sectors_a_killed_retry_pass_read_are_kept_before_the_zeros() {
        // E-NEW-1: a retry pass reads sectors of a bad area and ddrescue
        // writes them, but it is killed (SIGKILL, the OOM killer, a second
        // Ctrl+C) before it saves its map, which still lists the area as bad.
        // The zeros dfdisk writes there must not destroy what was read
        let tmp = tempfile::tempdir().unwrap();
        let killed = fake_ddrescue(
            tmp.path(),
            &format!(
                "head -c {MIB} /dev/zero | tr '\\0' 'R' > \"$IMG\"\nprintf '%s' '{BAD_MIDDLE}' > \"$MAP\"\nkill -KILL $$\n"
            ),
        );
        let ctx = context(tmp.path(), MIB, false);
        let out = acquire_with(&ctx, killed.as_os_str()).await.unwrap();
        assert!(
            out.stop_reason
                .as_deref()
                .is_some_and(|r| r.contains("ended by signal 9")),
            "{:?}",
            out.stop_reason
        );
        let image = std::fs::read(ctx.output_path(".raw")).unwrap();
        assert!(image[0x10000..0x10400].iter().all(|b| *b == 0));
        assert!(image[0x90000..0x90200].iter().all(|b| *b == 0));
        let kept = ZeroSidecar::new(&ctx.output_dir, "b", 1);
        assert_eq!(std::fs::read(&kept.bin).unwrap(), vec![b'R'; 0x600]);
        assert_eq!(tsv_rows(&kept.tsv).len(), 2);
        assert!(out.auxiliary_files.contains(&kept.bin));

        // Resumed, ddrescue finds the areas bad again: nothing but zeros is
        // there now, so no further file is written
        let resumed = script(
            tmp.path(),
            "resumed-ddrescue",
            &format!(
                "if [ \"$1\" = --version ]; then echo 'GNU ddrescue 1.30 (fake)'; exit 0; fi\n\
                 for a; do MAP=\"$a\"; done\nprintf '%s' '{BAD_MIDDLE}' > \"$MAP\"\nexit 0\n"
            ),
        );
        let out = acquire_with(&context_again(&ctx, true), resumed.as_os_str())
            .await
            .unwrap();
        assert_eq!(out.stop_reason, None);
        assert!(!ZeroSidecar::new(&ctx.output_dir, "b", 2).bin.exists());
        assert!(out
            .notes
            .iter()
            .any(|n| n.contains("none of their sectors held other data before")));
        // The first session's files stay as they were
        assert_eq!(std::fs::read(&kept.bin).unwrap(), vec![b'R'; 0x600]);
    }

    #[tokio::test]
    async fn a_sidecar_an_earlier_session_left_is_never_a_collision() {
        // E-R3-1: b.zeroed-1.bin exists, but no kept report (its session
        // ended before its report, e.g. during the image hash), so this
        // session is number 1 again. Its sidecar takes the next number, the
        // zeros are written, and the report's "zeros" is true
        let tmp = tempfile::tempdir().unwrap();
        let killed = fake_ddrescue(
            tmp.path(),
            &format!(
                "head -c {MIB} /dev/zero | tr '\\0' 'R' > \"$IMG\"\nprintf '%s' '{BAD_MIDDLE}' > \"$MAP\"\nkill -KILL $$\n"
            ),
        );
        let ctx = context(tmp.path(), MIB, false);
        let earlier = ZeroSidecar::new(&ctx.output_dir, "b", 1);
        std::fs::write(&earlier.bin, "earlier\n").unwrap();
        let out = acquire_with(&ctx, killed.as_os_str()).await.unwrap();
        let stop = out.stop_reason.clone().unwrap_or_default();
        assert!(stop.contains("ended by signal 9"), "{stop}");
        assert!(!stop.contains("could not write zeros"), "{stop}");
        assert_eq!(out.read_errors.substituted_bytes(), 0x600);
        let image = std::fs::read(ctx.output_path(".raw")).unwrap();
        assert!(image[0x10000..0x10400].iter().all(|b| *b == 0));
        let kept = ZeroSidecar::new(&ctx.output_dir, "b", 2);
        assert_eq!(std::fs::read(&kept.bin).unwrap(), vec![b'R'; 0x600]);
        assert!(out.auxiliary_files.contains(&kept.bin));
        assert!(!out.auxiliary_files.contains(&earlier.bin));
        assert_eq!(std::fs::read(&earlier.bin).unwrap(), b"earlier\n");
        assert!(
            out.notes
                .join("\n")
                .contains("their bytes are kept in b.zeroed-2.bin"),
            "{:?}",
            out.notes
        );
    }

    #[test]
    fn zero_sidecar_numbers() {
        assert_eq!(zeroed_number("b", "b.zeroed-3.bin"), Some(3));
        assert_eq!(zeroed_number("b", "B.ZEROED-12.TSV"), Some(12));
        for name in [
            "b.zeroed-.bin",
            "b.zeroed-2.txt",
            "b.zeroed-x.bin",
            "c.zeroed-2.bin",
        ] {
            assert_eq!(zeroed_number("b", name), None, "{name}");
        }
    }

    #[tokio::test]
    async fn a_resume_that_never_starts_ddrescue_puts_the_previous_report_back() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = fake_ddrescue(
            tmp.path(),
            &format!("printf '%s' '{BAD_MIDDLE}' > \"$MAP\"\nexit 0\n"),
        );
        let ctx = context(tmp.path(), MIB, false);
        std::fs::write(ctx.output_path(".raw"), vec![0u8; MIB as usize]).unwrap();
        acquire_with(&ctx, ok.as_os_str()).await.unwrap();
        std::fs::write(ctx.output_path(".info"), "report 1").unwrap();
        std::fs::write(
            ctx.output_path(".info.json"),
            report_json(Outcome::Aborted, "aa"),
        )
        .unwrap();
        // Answers --version, then is gone when the rescue starts it
        let vanishing = script(
            tmp.path(),
            "vanishing-ddrescue",
            "if [ \"$1\" = --version ]; then echo 'GNU ddrescue 1.30 (fake)'; \
             if [ -f \"$0.vanish\" ]; then rm -f \"$0\"; fi; exit 0; fi\nexit 0\n",
        );
        std::fs::write(tmp.path().join("vanishing-ddrescue.vanish"), "").unwrap();
        let e = acquire_with(&context_again(&ctx, true), vanishing.as_os_str())
            .await
            .unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Failed, "{e}");
        assert!(e.message.contains("cannot start ddrescue"), "{e}");
        assert_eq!(
            std::fs::read_to_string(ctx.output_path(".info")).unwrap(),
            "report 1"
        );
        assert!(ctx.output_path(".info.json").exists());
        assert!(kept_sessions(&ctx.output_dir, "b").is_empty());
    }

    #[test]
    fn a_kept_report_can_be_put_back() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("b.info"), "text").unwrap();
        std::fs::write(d.join("b.info.json"), "{}").unwrap();
        let (n, kept) = keep_previous_report(d, "b").unwrap().unwrap();
        assert_eq!((n, kept.len()), (1, 2));
        restore_previous_report(d, "b", 1).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("b.info")).unwrap(), "text");
        assert_eq!(
            std::fs::read_to_string(d.join("b.info.json")).unwrap(),
            "{}"
        );
        assert!(kept_sessions(d, "b").is_empty());
        // Never over a report of the current session
        keep_previous_report(d, "b").unwrap();
        std::fs::write(d.join("b.info"), "new").unwrap();
        assert!(restore_previous_report(d, "b", 1).is_err());
        assert_eq!(std::fs::read_to_string(d.join("b.info")).unwrap(), "new");
    }

    /// A context for the same output as `ctx` (`resume` as given).
    fn context_again(ctx: &EngineContext, resume: bool) -> EngineContext {
        let mut config = ctx.request.config.clone();
        config.resume = resume;
        EngineContext::new(
            AcquisitionRequest::new(ctx.request.device.clone(), CaseMetadata::default(), config),
            ctx.identity.clone(),
            ctx.base_name.clone(),
        )
    }

    #[tokio::test]
    async fn verify_hashes_the_image_and_never_claims_a_comparison() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = context(tmp.path(), 4096, false);
        let image = ctx.output_path(".raw");
        std::fs::write(&image, b"abc").unwrap();
        let out = EngineOutput {
            image_files: vec![image],
            ..Default::default()
        };
        let (result, hashes) = verify(&ctx, &out).await;
        assert!(
            matches!(result, VerificationResult::NotPossible { .. }),
            "{result:?}"
        );
        assert_eq!(
            hashes.md5.as_deref(),
            Some("900150983cd24fb0d6963f7d28e17f72")
        );
        assert_eq!(
            hashes.sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            hashes.sha1.as_deref(),
            Some("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        // No image: failed
        let (result, _) = verify(&ctx, &EngineOutput::default()).await;
        assert!(matches!(result, VerificationResult::Failed { .. }));
        // Abort while hashing
        let abort = AtomicBool::new(true);
        let e = hash_image(&ctx.output_path(".raw"), ctx.selection, &abort, |_, _| {}).unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Aborted);
    }
}
