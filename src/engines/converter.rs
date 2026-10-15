//! Image conversion (§13 Converter, review H3).
//!
//! RAW to E01: `ewfacquire -u` reads the RAW file, or every segment of a
//! split RAW set (`x.001`, `x.002`, ... all passed in order; ewfacquire reads
//! them as one stream through libsmraw), and writes `<base>.E01`,
//! `<base>.E02`, .... E01 to RAW: `ewfexport -u -f raw` reads the EWF family
//! and writes `<base>.raw` (plus its own `<base>.raw.info`).
//!
//! Held to the rigour of an acquisition (P1-P5):
//! 1. Plan, writing nothing: the source files (split RAW and EWF families
//!    complete and gap-free, else a usage error), the size a multiple of the
//!    sector size (else a usage error: ewfacquire silently drops the tail),
//!    the source report (`<base>.info.json` next to the image, or the one
//!    given), the required case values (given > report > E01 header), the
//!    base name within 255 bytes.
//! 2. Destination checks ([`preflight::evaluate`]: evidence mount, read-only,
//!    tmpfs, FAT limit, free space) and existing outputs, compared
//!    case-insensitively: refused, because the libewf tools overwrite with
//!    `-u`.
//! 3. First write: the output directory and the report reservation; audit
//!    "conversion_started" (on dfnix an unwritable log refuses).
//! 4. The tool through [`process::run`] (LC_ALL=C, own process group, both
//!    streams read; abort = SIGINT, 15 s grace, then SIGTERM and SIGKILL; a
//!    force flag kills at once); progress from its status lines.
//! 5. fsync and page-cache eviction of every output, then verification:
//!    RAW to E01 re-reads the E01 with ewfverify and compares the digests with
//!    the source's (from its report, or computed by dfdisk while ewfacquire
//!    reads the image); E01 to RAW hashes the written RAW file and compares
//!    with the digests stored in the E01 (and the report's).
//! 6. Verdict by `classify` (the source acquisition's read errors and
//!    incompleteness are inherited), the reports
//!    `<base>.conversion.info(.json)`, audit "conversion_finished" on every
//!    path after "started" (a drop guard covers panics and cancellation).
//!
//! An aborted or failed conversion keeps what the tool wrote (as an
//! acquisition does) and its report says the output is partial; a conversion
//! that wrote nothing returns the error instead of a report.

use crate::discovery::writeprotect;
use crate::engines::audit;
use crate::engines::error::{AcquisitionError, ErrorKind};
use crate::engines::ewf::{self, RunBlock};
use crate::engines::preflight::{self, DestinationFacts, DestinationRules};
use crate::engines::process::{self, ProcessEvent, ProcessOutcome, ProcessSpec, StreamTag};
use crate::engines::progress::ProgressSink;
use crate::engines::session::flush_and_evict;
use crate::models::case::{check_filename_length, sanitize_header, CaseMetadata};
use crate::models::config::{
    CompressionLevel, EngineKind, HashAlgorithm, HashSelection, SplitSize,
};
use crate::models::conversion::{
    ConversionReport, ConversionRequest, ConversionSettings, ConversionTarget, DigestComparison,
    SourceFile, SourceReportRef, CONVERSION_LOG_SUFFIX, CONVERSION_REPORT_KIND, CONVERSION_STEM,
    LONGEST_CONVERSION_SUFFIX,
};
use crate::models::info_report::{
    sha256_file, AuditInfo, AuditStatus, FileDigest, ForensicInfoReport, HashResults,
};
use crate::models::outcome::{Outcome, RangeKind, ReadErrorTable, VerificationResult};
use crate::models::protection::RegistryPresence;
use crate::models::provenance::{ClockInfo, ProvenanceRecorder, ToolProvenance};
use crate::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use crate::models::text::{format_iec, sanitize_line};
use crate::signals::StopFlags;
use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// SIGINT to SIGTERM delay when a conversion is aborted (§13: ewfacquire
/// gets 15 s to close its segments).
pub const TOOL_GRACE: Duration = Duration::from_secs(15);
/// Longest an `ewfinfo` run may take.
const INFO_TIMEOUT: Duration = Duration::from_secs(600);
/// Read buffer of dfdisk's own hashing.
const HASH_BUFFER: usize = 4 << 20;
/// Lines of tool output kept for parsing.
const MAX_KEPT_LINES: usize = 20_000;
/// libewf's smallest segment size.
const MIN_SEGMENT_BYTES: u64 = 1 << 20;
/// ewfexport's list of the sectors it could not read (libewf 20140816 and
/// 20231119), followed by "total number:" and "at sector(s):" lines.
const EXPORT_ERRORS_TITLE: &str = "Read errors during export";
/// Values libewf's tools write into an E01 header when none was given; they
/// are placeholders, never case values.
const LIBEWF_PLACEHOLDERS: &[&str] = &[
    "case_number",
    "evidence_number",
    "examiner_name",
    "description",
    "notes",
];

/// The libewf programs a conversion runs (names on PATH, or paths).
#[derive(Debug, Clone)]
pub struct ConverterTools {
    pub ewfacquire: OsString,
    pub ewfexport: OsString,
    pub ewfinfo: OsString,
    pub ewfverify: OsString,
}

impl Default for ConverterTools {
    fn default() -> Self {
        Self {
            ewfacquire: "ewfacquire".into(),
            ewfexport: "ewfexport".into(),
            ewfinfo: "ewfinfo".into(),
            ewfverify: "ewfverify".into(),
        }
    }
}

/// What a conversion depends on besides its request: the tools, the audit
/// log and the dfnix registry state, the mount table, the abort grace.
/// [`ConvertEnv::host`] is this host; tests inject their own.
#[derive(Debug, Clone)]
pub struct ConvertEnv {
    pub tools: ConverterTools,
    /// Where "conversion_started" / "conversion_finished" go
    pub audit_log: PathBuf,
    /// dfnix registry present: an audit log that cannot be written refuses
    pub registry: RegistryPresence,
    /// Content of /proc/self/mountinfo; `None` reads it at the destination check
    pub mountinfo: Option<String>,
    /// SIGINT to SIGTERM delay on abort
    pub grace: Duration,
    /// Copy the audit log into the output directory (`audit-<boot_id>.jsonl`)
    pub export_audit: bool,
}

impl ConvertEnv {
    /// This host: libewf tools on PATH, `DFNIX_AUDIT_LOG` (or the dfnix
    /// default), the dfnix registry, /proc/self/mountinfo.
    pub fn host() -> Self {
        Self {
            tools: ConverterTools::default(),
            audit_log: audit::log_path(),
            registry: writeprotect::registry_presence(),
            mountinfo: None,
            grace: TOOL_GRACE,
            export_audit: true,
        }
    }
}

/// Converts an image as described by `req` (§13 Converter) and writes the
/// conversion report. The CLI (`convert`, `--rescue-to-e01`) and the TUI call
/// this.
///
/// `Ok(report)` for every outcome once anything was written (verified,
/// unverified, read errors, incomplete, mismatch, verification failed,
/// aborted); `Err` for usage errors and refusals (nothing written), and for
/// failures or aborts that left no output.
pub async fn convert(
    req: ConversionRequest,
    progress_tx: mpsc::Sender<ProgressTelemetry>,
    stop: StopFlags,
) -> Result<ConversionReport, AcquisitionError> {
    convert_with(&ConvertEnv::host(), req, progress_tx, stop).await
}

/// [`convert`] with an explicit environment (tests: fake tools, own audit
/// log, mount table).
pub async fn convert_with(
    env: &ConvertEnv,
    req: ConversionRequest,
    progress_tx: mpsc::Sender<ProgressTelemetry>,
    stop: StopFlags,
) -> Result<ConversionReport, AcquisitionError> {
    let sink = ProgressSink::new(progress_tx);
    let result = run(env, &req, &sink, &stop).await;
    match &result {
        Ok(r) => {
            sink.finish(
                AcquisitionStatus::Completed,
                Some(r.outcome),
                format!(
                    "Conversion finished: {} (exit code {}); report {}",
                    r.outcome.label(),
                    r.exit_code,
                    r.report_file.display()
                ),
            )
            .await
        }
        Err(e) if e.kind == ErrorKind::Aborted => {
            sink.finish(AcquisitionStatus::Aborted, None, e.message.clone())
                .await
        }
        Err(e) => {
            sink.finish(
                AcquisitionStatus::Failed(e.message.clone()),
                None,
                format!(
                    "Conversion not completed ({}): {}",
                    e.kind.label(),
                    e.message
                ),
            )
            .await
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Notes of a converted rescue (CLI --rescue-to-e01, TUI)

/// Most zero-filled ranges [`rescue_notes`] lists (the rescue report lists
/// all of them; the note says how many there are).
pub const MAX_RESCUE_NOTE_RANGES: usize = 20;
/// How [`rescue_notes`] begins its line in the E01 header notes.
const RESCUE_NOTE_MARKER: &str = "Zero-filled sectors of the rescue";
/// How [`ewf_notes`] states inherited zero-filled sectors in the E01 header
/// notes ("<summary> unreadable in the acquisition, zeros in this image").
const ZEROS_NOTE_MARKER: &str = "unreadable in the acquisition, zeros in this image";

/// E01 notes of a converted rescue beyond what the converter states itself
/// (where the image came from, the rescue report's verdict and its
/// read-error summary): the zero-filled sector ranges of the ddrescue map
/// (the first ones; the rescue report lists all). Empty without bad sectors.
pub fn rescue_notes(report: &ForensicInfoReport, report_json: &Path) -> Vec<String> {
    let name = |p: &Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.display().to_string())
    };
    let table = &report.read_errors;
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
    if ranges.is_empty() {
        return Vec::new();
    }
    let shown = ranges.len().min(MAX_RESCUE_NOTE_RANGES);
    let mut line = format!(
        "{RESCUE_NOTE_MARKER} ({}, {} bytes each){}: {}",
        if table.source.is_empty() {
            "ddrescue mapfile"
        } else {
            table.source.as_str()
        },
        sector,
        if ranges.len() > shown {
            format!(", the first {shown} of {} ranges", ranges.len())
        } else {
            String::new()
        },
        ranges[..shown].join(", ")
    );
    if ranges.len() > shown {
        line.push_str(&format!(
            " and {} more ranges (see {})",
            ranges.len() - shown,
            name(report_json)
        ));
    }
    vec![line]
}

// ---------------------------------------------------------------------------
// Source files and names

/// The base name of a conversion's outputs: the source file name without its
/// split number (`.001`), EWF segment extension (`.E01`) and image extension
/// (`.raw`, `.dd`, `.img`, `.bin`). `None` when nothing usable is left or
/// the name is not UTF-8.
pub fn conversion_base_name(source: &Path) -> Option<String> {
    let name = source.file_name()?.to_str()?;
    let mut stem = name;
    if let Some((s, ext)) = stem.rsplit_once('.') {
        if is_split_number(ext) || ewf_segment_number(ext).is_some() {
            stem = s;
        }
    }
    if let Some((s, ext)) = stem.rsplit_once('.') {
        if ["raw", "dd", "img", "bin"]
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e))
        {
            stem = s;
        }
    }
    (!stem.is_empty() && !stem.starts_with('.')).then(|| stem.to_string())
}

/// `001`, `002`, ... (three or more digits): a split RAW segment number.
fn is_split_number(ext: &str) -> bool {
    ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit())
}

/// Family and number of an EWF segment extension, any case: `E01`..`E99`
/// are 1..99, `EAA`..`EZZ` 100.. (also `s01`, `L01`, `Ex01`, `Lx01`). The
/// family is the lower-cased letter prefix ("e", "s", "l", "ex", "lx").
pub fn ewf_segment_number(ext: &str) -> Option<(String, u32)> {
    let lower = ext.to_ascii_lowercase();
    let b = lower.as_bytes();
    let (prefix, rest) = match b.len() {
        3 if matches!(b[0], b'e' | b's' | b'l') => (&lower[..1], &b[1..]),
        4 if matches!(b[0], b'e' | b'l') && b[1] == b'x' => (&lower[..2], &b[2..]),
        _ => return None,
    };
    let n = if rest.iter().all(u8::is_ascii_digit) {
        let n = u32::from(rest[0] - b'0') * 10 + u32::from(rest[1] - b'0');
        (n > 0).then_some(n)?
    } else if rest.iter().all(u8::is_ascii_lowercase) {
        100 + u32::from(rest[0] - b'a') * 26 + u32::from(rest[1] - b'a')
    } else {
        return None;
    };
    Some((prefix.to_string(), n))
}

fn usage(msg: impl Into<String>) -> AcquisitionError {
    AcquisitionError::usage(msg)
}

fn file_size(path: &Path) -> Result<u64, AcquisitionError> {
    let meta =
        fs::metadata(path).map_err(|e| usage(format!("cannot read {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(usage(format!(
            "{} is not a regular file; a conversion reads image files (acquire devices with `dfdisk acquire`)",
            path.display()
        )));
    }
    Ok(meta.len())
}

/// Entries of `dir` whose name is `<stem>.<ext>` (stem compared without
/// regard to case), with their extension.
fn siblings(dir: &Path, stem: &str) -> Vec<(String, PathBuf)> {
    let prefix = format!("{}.", stem.to_lowercase());
    let mut out: Vec<(String, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let lower = name.to_lowercase();
            let ext = lower.strip_prefix(&prefix)?;
            (!ext.contains('.')).then(|| (name[name.len() - ext.len()..].to_string(), e.path()))
        })
        .collect();
    out.sort();
    out
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Every segment of the split RAW set `first` starts (`x.001`, `x.002`, ...
/// or from `x.000`), in order. Refuses a set given by a later segment, a set
/// with a gap, and segments of unequal size (except the last): a shorter
/// segment means a damaged or incomplete set, never silently converted.
pub fn split_raw_segments(first: &Path) -> Result<Vec<SourceFile>, AcquisitionError> {
    let name = first
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| usage(format!("{} has no usable file name", first.display())))?;
    let Some((stem, ext)) = name.rsplit_once('.').filter(|(_, e)| is_split_number(e)) else {
        return Ok(vec![SourceFile {
            path: first.to_path_buf(),
            bytes: file_size(first)?,
        }]);
    };
    let width = ext.len();
    let start: u64 = ext
        .parse()
        .map_err(|_| usage(format!("{name}: segment number out of range")))?;
    let dir = parent_dir(first);
    let numbered: Vec<(u64, PathBuf)> = siblings(&dir, stem)
        .into_iter()
        .filter(|(e, _)| e.len() == width && is_split_number(e))
        .filter_map(|(e, p)| e.parse().ok().map(|n| (n, p)))
        .collect();
    if let Some((n, p)) = numbered.iter().find(|(n, _)| *n < start) {
        return Err(usage(format!(
            "{} is not the first segment of its split RAW set ({} exists, number {n}); give the first segment",
            first.display(),
            p.display()
        )));
    }
    let mut files = Vec::new();
    let mut n = start;
    loop {
        let path = dir.join(format!("{stem}.{n:0width$}"));
        if !path.exists() {
            break;
        }
        files.push(SourceFile {
            bytes: file_size(&path)?,
            path,
        });
        n += 1;
    }
    if files.is_empty() {
        return Err(usage(format!("{} does not exist", first.display())));
    }
    if let Some((m, p)) = numbered.iter().find(|(m, _)| *m >= n) {
        return Err(usage(format!(
            "the split RAW set {stem}.{start:0width$} is not complete: segment {stem}.{n:0width$} is missing but {} (number {m}) exists; a conversion never skips a segment",
            p.display()
        )));
    }
    let first_len = files[0].bytes;
    if let Some(bad) = files[..files.len() - 1]
        .iter()
        .find(|f| f.bytes != first_len)
    {
        return Err(usage(format!(
            "the segments of the split RAW set differ in size: {} has {} bytes, {} has {}; only the last segment may be shorter. A shorter segment means a damaged or incomplete set",
            files[0].path.display(),
            first_len,
            bad.path.display(),
            bad.bytes
        )));
    }
    if files.iter().skip(1).any(|f| f.bytes == 0) {
        return Err(usage(format!(
            "the split RAW set {stem} has an empty segment"
        )));
    }
    Ok(files)
}

/// Every segment of the EWF family of `path` (any segment of it given), in
/// order, starting with the first. Refuses gaps, duplicates (`x.E01` and
/// `x.e01`) and logical evidence files (`.L01`).
pub fn ewf_segments(path: &Path) -> Result<Vec<SourceFile>, AcquisitionError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| usage(format!("{} has no usable file name", path.display())))?;
    let Some((stem, family)) = name
        .rsplit_once('.')
        .and_then(|(s, e)| ewf_segment_number(e).map(|(f, _)| (s, f)))
    else {
        // An EWF file recognised by its signature, not its name: libewf reads it alone
        return Ok(vec![SourceFile {
            path: path.to_path_buf(),
            bytes: file_size(path)?,
        }]);
    };
    if family.starts_with('l') {
        return Err(usage(format!(
            "{} is an EWF logical evidence file (L01): it holds files, not a disk image, and cannot be converted to RAW",
            path.display()
        )));
    }
    let dir = parent_dir(path);
    let sibs = siblings(&dir, stem);
    let mut segments: Vec<(u32, PathBuf)> = sibs
        .iter()
        .filter_map(|(e, p)| {
            ewf_segment_number(e)
                .filter(|(f, _)| *f == family)
                .map(|(_, n)| (n, p.clone()))
        })
        .collect();
    segments.sort();
    if let Some(w) = segments.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(usage(format!(
            "the EWF set {stem} is ambiguous: {} and {} are the same segment",
            w[0].1.display(),
            w[1].1.display()
        )));
    }
    for (i, (n, p)) in segments.iter().enumerate() {
        let want = i as u32 + 1;
        if *n != want {
            return Err(usage(format!(
                "the EWF set {stem} is not complete: segment number {want} is missing (next found: {}); a conversion never skips a segment",
                p.display()
            )));
        }
    }
    let Some(first) = segments.first().map(|(_, p)| p.clone()) else {
        return Err(usage(format!("{} does not exist", path.display())));
    };
    // Beyond .EZZ libewf continues with .FAA ... .ZZZ: follow its naming
    let first_ext = first
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut paths: Vec<PathBuf> = segments.into_iter().map(|(_, p)| p).collect();
    paths.extend(segment_chain(
        &sibs,
        &first_ext,
        paths.len() as u32 + 1,
        stem,
    )?);
    paths
        .into_iter()
        .map(|p| {
            Ok(SourceFile {
                bytes: file_size(&p)?,
                path: p,
            })
        })
        .collect()
}

/// Segments `from`, `from + 1`, ... of the family whose first segment has
/// the extension `first_ext`, named as libewf names them
/// ([`ewf::segment_extension`]), among `sibs` (compared without regard to
/// case), up to the first number that does not exist (libewf reads a family
/// the same way).
fn segment_chain(
    sibs: &[(String, PathBuf)],
    first_ext: &str,
    from: u32,
    stem: &str,
) -> Result<Vec<PathBuf>, AcquisitionError> {
    let mut out = Vec::new();
    let mut n = from;
    while let Some(ext) = ewf::segment_extension(first_ext, n) {
        let found: Vec<&PathBuf> = sibs
            .iter()
            .filter(|(e, _)| e.eq_ignore_ascii_case(&ext))
            .map(|(_, p)| p)
            .collect();
        match found.as_slice() {
            [] => break,
            [p] => out.push((*p).clone()),
            [a, b, ..] => {
                return Err(usage(format!(
                    "the EWF set {stem} is ambiguous: {} and {} are the same segment",
                    a.display(),
                    b.display()
                )))
            }
        }
        n += 1;
    }
    Ok(out)
}

/// Output files of a conversion named `base` in `dir`, compared without
/// regard to case (exFAT, NTFS and vfat treat `X.E01` and `x.e01` as one
/// file): the reports, the tool log, and the images of `target`.
pub fn existing_conversion_outputs(
    dir: &Path,
    base: &str,
    target: ConversionTarget,
) -> Vec<PathBuf> {
    let prefix = format!("{}.", base.to_lowercase());
    let conversion = format!("{}{}.", base.to_lowercase(), CONVERSION_STEM);
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let lower = e.file_name().to_string_lossy().to_lowercase();
            if lower.starts_with(&conversion) {
                return true;
            }
            let Some(ext) = lower.strip_prefix(&prefix) else {
                return false;
            };
            match target {
                ConversionTarget::E01 => ewf_segment_number(ext).is_some(),
                ConversionTarget::Raw => ext == "raw" || ext.starts_with("raw."),
            }
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// E01 segments a conversion named `base` wrote into `dir`, in order: the
/// segments as libewf names them (`.E01` .. `.EZZ`, `.FAA` ...) from the
/// first on, then any other `.E..` segment (after a gap).
fn written_segments(dir: &Path, base: &str) -> Vec<PathBuf> {
    let sibs = siblings(dir, base);
    let mut out = segment_chain(&sibs, "E01", 1, base).unwrap_or_default();
    let mut rest: Vec<(u32, PathBuf)> = sibs
        .into_iter()
        .filter(|(_, p)| !out.contains(p))
        .filter_map(|(e, p)| {
            ewf_segment_number(&e)
                .filter(|(f, _)| f == "e")
                .map(|(_, n)| (n, p))
        })
        .collect();
    rest.sort();
    out.extend(rest.into_iter().map(|(_, p)| p));
    out
}

/// Files in `dir` named like segments past `.EZZ` (`.FAA` ...) that an E01
/// conversion of `source_bytes` with segments of `segment_bytes` could
/// write: ewfacquire -u would overwrite them. Bounded by the number of
/// segments the output can need (1 % overhead and one more), so a source
/// like `x.RAW` is never taken for segment 9,000-something.
fn existing_late_segments(
    dir: &Path,
    base: &str,
    source_bytes: u64,
    segment_bytes: Option<u64>,
) -> Vec<PathBuf> {
    const FIRST_LATE: u32 = 776;
    let Some(seg) = segment_bytes.filter(|s| *s > 0) else {
        return Vec::new();
    };
    let most = (source_bytes / 100 * 101 / seg).saturating_add(2);
    let most = u32::try_from(most).unwrap_or(u32::MAX);
    if most < FIRST_LATE {
        return Vec::new();
    }
    let names: std::collections::HashSet<String> = (FIRST_LATE..=most)
        .map_while(|n| ewf::segment_extension("E01", n))
        .map(|e| e.to_ascii_lowercase())
        .collect();
    siblings(dir, base)
        .into_iter()
        .filter(|(e, _)| names.contains(&e.to_ascii_lowercase()))
        .map(|(_, p)| p)
        .collect()
}

// ---------------------------------------------------------------------------
// Tool output parsing (formats of libewf 20231119, captured from real runs)

/// Whether a digest line states a value the tool calculated over the data
/// or one stored in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestOrigin {
    Calculated,
    Stored,
}

fn algorithm_of(label: &str) -> Option<HashAlgorithm> {
    match label {
        "MD5" => Some(HashAlgorithm::MD5),
        "SHA1" | "SHA-1" => Some(HashAlgorithm::SHA1),
        "SHA256" | "SHA-256" => Some(HashAlgorithm::SHA256),
        _ => None,
    }
}

fn hex_digest(alg: HashAlgorithm, value: &str) -> Option<String> {
    let v = value.trim().to_ascii_lowercase();
    let len = match alg {
        HashAlgorithm::MD5 => 32,
        HashAlgorithm::SHA1 => 40,
        HashAlgorithm::SHA256 => 64,
    };
    (v.len() == len && v.bytes().all(|b| b.is_ascii_hexdigit())).then_some(v)
}

/// "MD5 hash calculated over data:\t\t<hex>" (ewfacquire, ewfexport,
/// ewfverify) and "MD5 hash stored in file:\t\t<hex>" (ewfverify). "N/A"
/// and malformed values are ignored.
pub fn parse_digest_line(line: &str) -> Option<(DigestOrigin, HashAlgorithm, String)> {
    let (label, value) = line.trim().split_once(':')?;
    let (alg, origin) = match label.strip_suffix(" hash calculated over data") {
        Some(a) => (a, DigestOrigin::Calculated),
        None => (
            label.strip_suffix(" hash stored in file")?,
            DigestOrigin::Stored,
        ),
    };
    let alg = algorithm_of(alg.trim())?;
    Some((origin, alg, hex_digest(alg, value)?))
}

fn set_digest(h: &mut HashResults, alg: HashAlgorithm, v: String) {
    match alg {
        HashAlgorithm::MD5 => h.md5 = Some(v),
        HashAlgorithm::SHA1 => h.sha1 = Some(v),
        HashAlgorithm::SHA256 => h.sha256 = Some(v),
    }
}

/// The number in the last "(N bytes)" of `text`.
fn bytes_in_parens(text: &str) -> Option<u64> {
    let end = text.rfind(" bytes)")?;
    let start = text[..end].rfind('(')? + 1;
    text[start..end].trim().parse().ok()
}

/// "acquired 153 MiB (161153024 bytes) of total 300 MiB (314572800 bytes)"
/// (also "exported", "verified"): (done, total).
pub fn parse_status_bytes(line: &str) -> Option<(u64, u64)> {
    let (done, total) = line.split_once(" of total ")?;
    Some((bytes_in_parens(done)?, bytes_in_parens(total)?))
}

/// "... with 42 MiB/s (44938971 bytes/second)": bytes per second.
pub fn parse_status_speed(line: &str) -> Option<f64> {
    let end = line.rfind(" bytes/second)")?;
    let start = line[..end].rfind('(')? + 1;
    line[start..end].trim().parse().ok()
}

/// What `ewfinfo` says about an EWF image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EwfInfo {
    pub case_number: Option<String>,
    pub description: Option<String>,
    pub examiner: Option<String>,
    pub evidence_number: Option<String>,
    pub notes: Option<String>,
    pub media_type: Option<String>,
    pub is_physical: Option<bool>,
    pub bytes_per_sector: Option<u32>,
    pub media_size: Option<u64>,
    /// "Digest hash information" (stored in the image)
    pub stored: HashResults,
    /// "Read errors during acquiry": (first sector, number of sectors)
    pub read_errors: Vec<(u64, u64)>,
    /// "total number:" of that list
    pub read_error_total: Option<u64>,
    /// "at sector(s):" lines that could not be parsed
    pub unparsed_errors: Vec<String>,
    /// "Is corrupted: yes" (EWF information): segments are missing, or the
    /// image was never finalized (an aborted acquisition)
    pub corrupted: bool,
}

impl EwfInfo {
    /// The acquiry errors as substituted ranges (ewfacquire zero-fills them).
    pub fn error_table(&self, source: &str) -> ReadErrorTable {
        let mut t = ReadErrorTable::new(self.bytes_per_sector.unwrap_or(512), source);
        for &(first, count) in &self.read_errors {
            t.push_sectors(first, count, RangeKind::Substituted);
        }
        t
    }
}

/// "2048 - 2111 (number: 64)" (libewf 20231119) or "2048 - 2111 number: 64"
/// (20140816): first sector and number of sectors. The range is inclusive;
/// when the stated number and the range disagree, the larger is used (the
/// conservative statement).
fn parse_error_range(value: &str) -> Option<(u64, u64)> {
    let (range, number) = match value.find("number:") {
        Some(i) => (&value[..i], Some(&value[i + "number:".len()..])),
        None => (value, None),
    };
    let range = range.trim().trim_end_matches('(').trim();
    let (a, b) = range.split_once('-').unwrap_or((range, range));
    let first: u64 = a.trim().parse().ok()?;
    let last: u64 = b.trim().parse().ok()?;
    let span = last.checked_sub(first)? + 1;
    let stated = number.and_then(|n| {
        n.trim()
            .trim_end_matches(')')
            .split_whitespace()
            .next()?
            .trim_end_matches([')', ','])
            .parse::<u64>()
            .ok()
    });
    Some((first, stated.map_or(span, |n| n.max(span))))
}

/// Parse `ewfinfo` output (sections "Acquiry information", "Media
/// information", "Digest hash information", "Read errors during acquiry";
/// libewf 20231119 ends the section titles with a colon, 20140816 does not).
pub fn parse_ewfinfo(text: &str) -> EwfInfo {
    let mut info = EwfInfo::default();
    let mut section = "";
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !raw.starts_with(['\t', ' ']) {
            section = match line.trim_end_matches(':') {
                "Acquiry information" => "acquiry",
                "Media information" => "media",
                "Digest hash information" => "digest",
                "Read errors during acquiry" => "errors",
                _ => "",
            };
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let text_value = || Some(value.to_string()).filter(|v| !v.is_empty());
        match (section, key.trim()) {
            ("acquiry", "Case number") => info.case_number = text_value(),
            ("acquiry", "Description") => info.description = text_value(),
            ("acquiry", "Examiner name") => info.examiner = text_value(),
            ("acquiry", "Evidence number") => info.evidence_number = text_value(),
            ("acquiry", "Notes") => info.notes = text_value(),
            ("media", "Media type") => info.media_type = text_value(),
            ("media", "Is physical") => info.is_physical = Some(value == "yes"),
            ("media", "Bytes per sector") => info.bytes_per_sector = value.parse().ok(),
            ("media", "Media size") => info.media_size = bytes_in_parens(value),
            ("digest", label) => {
                if let Some(alg) = algorithm_of(label) {
                    if let Some(v) = hex_digest(alg, value) {
                        set_digest(&mut info.stored, alg, v);
                    }
                }
            }
            ("errors", "total number") => info.read_error_total = value.parse().ok(),
            ("errors", "at sector(s)") => match parse_error_range(value) {
                Some(range) => info.read_errors.push(range),
                None => info.unparsed_errors.push(line.to_string()),
            },
            _ => {}
        }
    }
    info.corrupted = ewf::parse_ewfinfo_media(text).corrupted;
    info
}

// ---------------------------------------------------------------------------
// The source report

/// A report the source image came from, with what the conversion inherits.
#[derive(Debug, Clone)]
struct LoadedReport {
    reference: SourceReportRef,
    case: CaseMetadata,
    read_errors: ReadErrorTable,
    /// Whole-disk source (E01 "physical"), removable media, logical sector size
    medium: Option<(bool, bool, u32)>,
}

/// Image file names a report lists.
fn report_image_names(value: &Value) -> Vec<String> {
    let key = if value.get("report_kind").and_then(Value::as_str) == Some(CONVERSION_REPORT_KIND) {
        "output_files"
    } else {
        "image_files"
    };
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|p| Path::new(p).file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Read a dfdisk report (acquisition schema 2, or a conversion report).
fn load_report(path: &Path) -> Result<(LoadedReport, Vec<String>), String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
    let sha256 = sha256_file(path).map_err(|e| format!("cannot hash {}: {e}", path.display()))?;
    let names = report_image_names(&value);
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let loaded = if value.get("report_kind").and_then(Value::as_str) == Some(CONVERSION_REPORT_KIND)
    {
        let r = ConversionReport::from_json(&text)
            .map_err(|e| format!("{} is not a dfdisk conversion report: {e}", path.display()))?;
        let mut read_errors = r.read_errors.clone();
        if !read_errors.is_empty() {
            read_errors.source = format!("conversion report {file} ({})", r.read_errors.source);
        }
        let s = &r.settings;
        LoadedReport {
            reference: SourceReportRef {
                path: path.to_path_buf(),
                sha256,
                kind: "conversion".into(),
                engine: None,
                base_name: r.base_name.clone(),
                outcome: r.outcome,
                exit_code: r.exit_code,
                outcome_reason: r.outcome_reason.clone(),
                hashes: r.output_hashes.clone(),
                hashes_basis: format!(
                    "recomputed from the output of an earlier conversion ({file})"
                ),
                verified: r.verification.is_matched(),
            },
            case: r.case_metadata.clone(),
            read_errors,
            medium: s.media_flags.as_ref().map(|f| {
                (
                    f == "physical",
                    s.media_type.as_deref() == Some("removable"),
                    s.bytes_per_sector,
                )
            }),
        }
    } else {
        let r = ForensicInfoReport::from_json(&text).map_err(|e| {
            format!(
                "{} is not a dfdisk acquisition report (schema 2): {e}",
                path.display()
            )
        })?;
        let (hashes, basis) = if !r.acquisition_hashes.is_empty() {
            (
                r.acquisition_hashes.clone(),
                "computed while reading the source medium during the acquisition",
            )
        } else {
            (
                r.image_hashes.clone(),
                "recomputed from the image after the acquisition (none were computed while reading the medium)",
            )
        };
        let mut read_errors = r.read_errors.clone();
        if !read_errors.is_empty() {
            read_errors.source = format!("acquisition report {file} ({})", r.read_errors.source);
        }
        LoadedReport {
            reference: SourceReportRef {
                path: path.to_path_buf(),
                sha256,
                kind: "acquisition".into(),
                engine: Some(r.engine.tag().to_string()),
                base_name: r.base_name.clone(),
                outcome: r.outcome,
                exit_code: r.exit_code,
                outcome_reason: r.outcome_reason.clone(),
                hashes,
                hashes_basis: basis.into(),
                verified: r.verification.result.is_matched(),
            },
            case: r.case_metadata.clone(),
            read_errors,
            medium: Some((
                r.source.kind.is_whole_disk(),
                r.source.removable,
                r.source.logical_sector_size,
            )),
        }
    };
    Ok((loaded, names))
}

/// The report of `source`: the given one (must list the image, else a usage
/// error; one the caller found itself, `source_report_auto`, is ignored with
/// a note instead), or `<base>.info.json` / `<base>.conversion.info.json`
/// next to it when it lists the image (else ignored with a note).
fn find_report(
    req: &ConversionRequest,
    source: &Path,
    base: &str,
    notes: &mut Vec<String>,
) -> Result<Option<LoadedReport>, AcquisitionError> {
    let image = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lists = |names: &[String]| names.iter().any(|n| n.eq_ignore_ascii_case(&image));
    let mut tried: Option<&Path> = None;
    if let Some(given) = &req.source_report {
        match load_report(given) {
            Ok((loaded, names)) if lists(&names) => return Ok(Some(loaded)),
            // C-5: a report the caller found (not the examiner's choice)
            // that describes another image is not this image's report
            Ok(_) if req.source_report_auto => {
                notes.push(format!(
                    "{} was not used: it does not list {image} among its image files",
                    given.display()
                ));
                tried = Some(given.as_path());
            }
            Err(e) if req.source_report_auto => {
                notes.push(format!("{} was not used: {e}", given.display()));
                tried = Some(given.as_path());
            }
            Ok(_) => {
                return Err(usage(format!(
                    "the report {} does not list {image} among its image files; it does not describe this image (convert without --report, or give the report of this image)",
                    given.display()
                )))
            }
            Err(e) => return Err(usage(e)),
        }
    }
    let dir = parent_dir(source);
    for candidate in [
        dir.join(format!("{base}.info.json")),
        dir.join(format!("{base}{CONVERSION_STEM}.info.json")),
    ] {
        if !candidate.is_file() || tried.is_some_and(|t| same_path(t, &candidate)) {
            continue;
        }
        match load_report(&candidate) {
            Ok((loaded, names)) if lists(&names) => return Ok(Some(loaded)),
            Ok(_) => notes.push(format!(
                "{} was not used: it does not list {image} among its image files",
                candidate.display()
            )),
            Err(e) => notes.push(format!("{} was not used: {e}", candidate.display())),
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Case values

type FieldRef = fn(&CaseMetadata) -> &String;
type FieldMut = fn(&mut CaseMetadata) -> &mut String;

const CASE_FIELDS: &[(&str, FieldRef, FieldMut)] = &[
    ("case number", |c| &c.case_number, |c| &mut c.case_number),
    ("EA / location", |c| &c.location_ea, |c| &mut c.location_ea),
    (
        "evidence number",
        |c| &c.evidence_number,
        |c| &mut c.evidence_number,
    ),
    ("authority", |c| &c.authority, |c| &mut c.authority),
    ("examiner", |c| &c.examiner, |c| &mut c.examiner),
    ("description", |c| &c.description, |c| &mut c.description),
    ("notes", |c| &c.notes, |c| &mut c.notes),
    ("seal number", |c| &c.seal_number, |c| &mut c.seal_number),
    ("seizure time", |c| &c.seizure_time, |c| &mut c.seizure_time),
    (
        "seizure location",
        |c| &c.seizure_location,
        |c| &mut c.seizure_location,
    ),
];

/// Merge case values, lowest priority first: every non-empty field of a
/// later layer replaces the earlier value; a replaced different value is
/// noted. Returns the merged values, the layers that contributed, notes.
fn merge_case(layers: &[(CaseMetadata, String)]) -> (CaseMetadata, Vec<String>, Vec<String>) {
    let mut merged = CaseMetadata::default();
    let mut origin: Vec<Option<&str>> = vec![None; CASE_FIELDS.len()];
    let mut used = Vec::new();
    let mut notes = Vec::new();
    for (case, source) in layers {
        let mut contributed = false;
        for (i, (label, get, get_mut)) in CASE_FIELDS.iter().enumerate() {
            let value = sanitize_header(get(case));
            if value.is_empty() {
                continue;
            }
            let current = get_mut(&mut merged);
            if !current.is_empty() && *current != value {
                notes.push(format!(
                    "{label}: {} records \"{}\"; \"{value}\" from {source} is recorded",
                    origin[i].unwrap_or("an earlier source"),
                    current
                ));
            }
            *current = value;
            origin[i] = Some(source.as_str());
            contributed = true;
        }
        if contributed {
            used.push(source.clone());
        }
    }
    (merged, used, notes)
}

/// Case values an E01 header holds (libewf placeholders dropped, noted).
fn header_case(info: &EwfInfo, notes: &mut Vec<String>) -> CaseMetadata {
    let mut take = |label: &str, v: &Option<String>| -> String {
        match v {
            Some(v) if LIBEWF_PLACEHOLDERS.contains(&v.as_str()) => {
                notes.push(format!(
                    "the E01 header's {label} is libewf's placeholder \"{v}\", not a case value; it is not used"
                ));
                String::new()
            }
            Some(v) => v.clone(),
            None => String::new(),
        }
    };
    CaseMetadata {
        case_number: take("case number", &info.case_number),
        evidence_number: take("evidence number", &info.evidence_number),
        examiner: take("examiner", &info.examiner),
        description: take("description", &info.description),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Hashing (dfdisk's own reads)

#[derive(Debug)]
enum HashError {
    Aborted,
    Io(String),
}

/// MD5 / SHA-1 / SHA-256 (as selected) of the concatenation of `paths`.
/// `done` counts the bytes hashed; `abort` stops between reads.
fn hash_files(
    paths: &[PathBuf],
    selection: HashSelection,
    abort: &AtomicBool,
    done: &AtomicU64,
) -> Result<HashResults, HashError> {
    use digest::Digest;
    let mut md5 = selection.md5.then(md5::Md5::new);
    let mut sha1 = selection.sha1.then(sha1::Sha1::new);
    let mut sha256 = selection.sha256.then(sha2::Sha256::new);
    let mut buf = vec![0u8; HASH_BUFFER];
    for path in paths {
        let mut f = fs::File::open(path)
            .map_err(|e| HashError::Io(format!("cannot open {}: {e}", path.display())))?;
        let mut offset = 0u64;
        loop {
            if abort.load(Ordering::Relaxed) {
                return Err(HashError::Aborted);
            }
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(HashError::Io(format!(
                        "read error in {} at offset {offset}: {e}",
                        path.display()
                    )))
                }
            };
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
            offset += n as u64;
            done.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
    Ok(HashResults {
        md5: md5.map(|h| hex::encode(h.finalize())),
        sha1: sha1.map(|h| hex::encode(h.finalize())),
        sha256: sha256.map(|h| hex::encode(h.finalize())),
    })
}

// ---------------------------------------------------------------------------
// Comparisons

/// Compare the digests both sides have among `selection`. Nothing in common
/// is `NotPossible`; a difference is `Mismatched` naming both values.
fn compare(
    selection: HashSelection,
    reference: (&str, &HashResults),
    compared: (&str, &HashResults),
    independent: bool,
) -> DigestComparison {
    let mut mismatches = Vec::new();
    let mut matched = Vec::new();
    for alg in selection.algorithms() {
        if let (Some(a), Some(b)) = (reference.1.get(alg), compared.1.get(alg)) {
            if a.eq_ignore_ascii_case(b) {
                matched.push(alg.label());
            } else {
                mismatches.push(format!(
                    "{}: {} {a}, {} {b}",
                    alg.label(),
                    reference.0,
                    compared.0
                ));
            }
        }
    }
    let method = format!("{} vs {}", reference.0, compared.0);
    let result = if !mismatches.is_empty() {
        VerificationResult::Mismatched {
            method,
            details: mismatches.join("; "),
        }
    } else if matched.is_empty() {
        VerificationResult::NotPossible {
            reason: format!(
                "{} and {} have no digest in common",
                reference.0, compared.0
            ),
        }
    } else {
        VerificationResult::Matched {
            method: format!("{} ({})", method, matched.join(", ")),
        }
    };
    DigestComparison {
        reference: reference.0.to_string(),
        reference_hashes: reference.1.clone(),
        compared: compared.0.to_string(),
        compared_hashes: compared.1.clone(),
        independent,
        result,
    }
}

/// The overall verification from the comparisons: any mismatch wins, then
/// a failure; `Matched` needs at least one matching independent comparison.
fn overall(comparisons: &[DigestComparison], failure: Option<String>) -> VerificationResult {
    let mismatches: Vec<&DigestComparison> = comparisons
        .iter()
        .filter(|c| matches!(c.result, VerificationResult::Mismatched { .. }))
        .collect();
    if !mismatches.is_empty() {
        let (methods, details): (Vec<String>, Vec<String>) = mismatches
            .iter()
            .map(|c| match &c.result {
                VerificationResult::Mismatched { method, details } => {
                    (method.clone(), details.clone())
                }
                _ => unreachable!(),
            })
            .unzip();
        return VerificationResult::Mismatched {
            method: methods.join("; "),
            details: details.join("; "),
        };
    }
    if let Some(reason) = failure {
        return VerificationResult::Failed { reason };
    }
    let matched: Vec<&str> = comparisons
        .iter()
        .filter(|c| c.independent)
        .filter_map(|c| match &c.result {
            VerificationResult::Matched { method } => Some(method.as_str()),
            _ => None,
        })
        .collect();
    if matched.is_empty() {
        VerificationResult::NotPossible {
            reason: comparisons
                .iter()
                .find_map(|c| match &c.result {
                    VerificationResult::NotPossible { reason } if c.independent => {
                        Some(reason.clone())
                    }
                    _ => None,
                })
                .unwrap_or_else(|| {
                    "there is no independent digest of the source image to compare the output with"
                        .into()
                }),
        }
    } else {
        VerificationResult::Matched {
            method: matched.join("; "),
        }
    }
}

// ---------------------------------------------------------------------------
// The plan (step 1, writes nothing)

/// Everything decided before the first write.
#[derive(Debug, Clone)]
struct Plan {
    target: ConversionTarget,
    /// First segment of the source
    source: PathBuf,
    source_files: Vec<SourceFile>,
    source_format: String,
    expected_bytes: u64,
    output_dir: PathBuf,
    base_name: String,
    case: CaseMetadata,
    case_sources: Vec<String>,
    report: Option<LoadedReport>,
    /// E01 source: what ewfinfo said
    ewf_source: Option<EwfInfo>,
    /// Read errors of the acquisition the image came from
    inherited_errors: ReadErrorTable,
    /// The image is itself incomplete (its report says so)
    inherited_stop: Option<String>,
    /// The image was not verified against its medium: a matching conversion
    /// stays "not verified"
    inherited_unverified: Option<String>,
    /// What the report says about unreadable ranges when none are listed
    read_errors_note: Option<String>,
    selection: HashSelection,
    settings: ConversionSettings,
    notes: Vec<String>,
}

impl Plan {
    fn report_base(&self) -> String {
        format!("{}{CONVERSION_STEM}", self.base_name)
    }

    fn primary_output(&self) -> PathBuf {
        self.output_dir
            .join(format!("{}.{}", self.base_name, self.target.extension()))
    }

    fn log_path(&self) -> PathBuf {
        self.output_dir
            .join(format!("{}{CONVERSION_LOG_SUFFIX}", self.base_name))
    }

    fn source_paths(&self) -> Vec<PathBuf> {
        self.source_files.iter().map(|f| f.path.clone()).collect()
    }
}

fn source_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Run `ewfinfo` on `image` and parse it.
async fn ewfinfo(
    env: &ConvertEnv,
    image: &Path,
    stop: &StopFlags,
    recorder: &ProvenanceRecorder,
) -> Result<EwfInfo, AcquisitionError> {
    let spec = ProcessSpec::new(&env.tools.ewfinfo)
        .arg(image)
        .timeout(INFO_TIMEOUT)
        .grace(Duration::from_secs(2));
    let out = process::run_collect(&spec, &stop.stop_control(), Some(recorder))
        .await
        .map_err(|e| {
            AcquisitionError::failed(format!("cannot run ewfinfo (is libewf installed?): {e}"))
        })?;
    if out.outcome.aborted || out.outcome.force_killed {
        return Err(AcquisitionError::aborted("the conversion was aborted"));
    }
    if !out.outcome.success() {
        return Err(AcquisitionError::failed(format!(
            "ewfinfo cannot read {} ({}): {}",
            image.display(),
            out.outcome.record.status_text(),
            out.stderr
                .iter()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .take(3)
                .collect::<Vec<_>>()
                .join(" / ")
        )));
    }
    Ok(parse_ewfinfo(&out.stdout.join("\n")))
}

async fn plan(
    env: &ConvertEnv,
    req: &ConversionRequest,
    stop: &StopFlags,
    recorder: &ProvenanceRecorder,
) -> Result<Plan, AcquisitionError> {
    if req.source.as_os_str().is_empty() {
        return Err(usage("no source image given"));
    }
    if req.output_dir.as_os_str().is_empty() {
        return Err(usage("no output directory given"));
    }
    file_size(&req.source)?;
    let is_ewf = crate::engines::verify::is_ewf_image_file(&req.source);
    let mut notes = Vec::new();
    match (req.target, is_ewf) {
        (ConversionTarget::E01, true) => {
            return Err(usage(format!(
                "{} is already an EWF image; convert it to RAW (--to raw), or verify it with `dfdisk verify`",
                req.source.display()
            )))
        }
        (ConversionTarget::Raw, false) => {
            return Err(usage(format!(
                "{} is not an EWF image (no .E01-style name or EVF signature); only E01 images convert to RAW",
                req.source.display()
            )))
        }
        _ => {}
    }

    let source_files = match req.target {
        ConversionTarget::E01 => split_raw_segments(&req.source)?,
        ConversionTarget::Raw => ewf_segments(&req.source)?,
    };
    let source = source_files[0].path.clone();
    let base_name = conversion_base_name(&source).ok_or_else(|| {
        usage(format!(
            "{} has no usable base name for the outputs (UTF-8 name required)",
            source.display()
        ))
    })?;
    check_filename_length(&base_name, LONGEST_CONVERSION_SUFFIX.len()).map_err(usage)?;
    if let SplitSize::Custom(b) = req.split_size {
        if req.target == ConversionTarget::E01 && b < MIN_SEGMENT_BYTES {
            return Err(usage(format!(
                "segment size {b} bytes is below libewf's minimum of 1 MiB"
            )));
        }
    }

    let report = find_report(req, &source, &base_name, &mut notes)?;

    // E01 source: ewfinfo (reads only)
    let ewf_source = if req.target == ConversionTarget::Raw {
        Some(ewfinfo(env, &source, stop, recorder).await?)
    } else {
        None
    };

    let (expected_bytes, source_format) = match &ewf_source {
        Some(info) => {
            let size = info.media_size.ok_or_else(|| {
                AcquisitionError::failed(format!(
                    "ewfinfo did not report the media size of {}",
                    source.display()
                ))
            })?;
            (
                size,
                format!(
                    "EWF image ({} {})",
                    source_files.len(),
                    if source_files.len() == 1 {
                        "segment"
                    } else {
                        "segments"
                    }
                ),
            )
        }
        None => {
            let total: u64 = source_files.iter().map(|f| f.bytes).sum();
            let format = if source_files.len() > 1
                || source
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(is_split_number)
            {
                format!(
                    "split RAW image ({} {})",
                    source_files.len(),
                    if source_files.len() == 1 {
                        "segment"
                    } else {
                        "segments"
                    }
                )
            } else {
                "RAW image".to_string()
            };
            (total, format)
        }
    };
    if expected_bytes == 0 {
        return Err(usage(format!("{} holds no data", source.display())));
    }

    // Case values: E01 header < source report < given
    let mut layers = Vec::new();
    if let Some(info) = &ewf_source {
        layers.push((
            header_case(info, &mut notes),
            format!("E01 header of {}", source_name(&source)),
        ));
    }
    if let Some(r) = &report {
        layers.push((
            r.case.clone(),
            format!(
                "{} report {}",
                r.reference.kind,
                source_name(&r.reference.path)
            ),
        ));
    }
    if let Some(given) = &req.case {
        layers.push((given.clone(), "given for this conversion".to_string()));
    }
    let (case, case_sources, case_notes) = merge_case(&layers);
    notes.extend(case_notes);
    let missing: Vec<&str> = [
        (case.effective_case(), "case number (--case)"),
        (case.effective_evidence(), "evidence number (--evidence)"),
        (case.effective_examiner(), "examiner (--examiner)"),
    ]
    .into_iter()
    .filter(|(v, _)| v.is_none())
    .map(|(_, n)| n)
    .collect();
    if !missing.is_empty() {
        return Err(usage(format!(
            "Required case information missing for the conversion: {}. Give it, or keep the image's acquisition report ({base_name}.info.json) next to it; nothing is filled in for you.",
            missing.join(", ")
        )));
    }

    // Sector size and the size rule
    let mut settings = ConversionSettings::default();
    let bytes_per_sector = match req.target {
        ConversionTarget::Raw => ewf_source
            .as_ref()
            .and_then(|i| i.bytes_per_sector)
            .unwrap_or(512),
        ConversionTarget::E01 => {
            let medium = report.as_ref().and_then(|r| r.medium).map(|m| m.2);
            match medium {
                Some(s) if s >= 512 && expected_bytes.is_multiple_of(u64::from(s)) => s,
                Some(s) if s > 512 && expected_bytes.is_multiple_of(512) => {
                    settings.notes.push(format!(
                        "the image size is not a multiple of the medium's {s}-byte sectors; the E01 records 512-byte sectors"
                    ));
                    512
                }
                _ => 512,
            }
        }
    };
    if req.target == ConversionTarget::E01 && !expected_bytes.is_multiple_of(512) {
        return Err(usage(format!(
            "the RAW image is {expected_bytes} bytes, not a multiple of 512: an E01 holds whole sectors, and ewfacquire would silently drop the last {} bytes while its digest still covers them (ewfverify would then fail). Keep the image as RAW, or pad or trim it deliberately and record why",
            expected_bytes % 512
        )));
    }

    // Digests: MD5 (E01 always), SHA-256, SHA-1 when a reference has it
    let ref_hashes = report.as_ref().map(|r| r.reference.hashes.clone());
    let stored = ewf_source.as_ref().map(|i| i.stored.clone());
    let selection = HashSelection {
        md5: true,
        sha1: ref_hashes.as_ref().is_some_and(|h| h.sha1.is_some())
            || stored.as_ref().is_some_and(|h| h.sha1.is_some()),
        sha256: true,
    };

    // Inherited facts of the source acquisition
    let mut inherited_errors = report
        .as_ref()
        .map(|r| r.read_errors.clone())
        .unwrap_or_default();
    if let Some(info) = &ewf_source {
        // Fail closed: zeros at places the report could not name would be
        // a silent substitution
        let listed = info.read_errors.len() as u64;
        if !info.unparsed_errors.is_empty() || info.read_error_total.is_some_and(|t| t > listed) {
            return Err(AcquisitionError::failed(format!(
                "ewfinfo reports read errors stored in {} that dfdisk cannot locate (total {}, {listed} ranges understood{}); refusing to convert without stating where the image holds zeros",
                source.display(),
                info.read_error_total.unwrap_or(listed),
                if info.unparsed_errors.is_empty() {
                    String::new()
                } else {
                    format!(": {}", info.unparsed_errors.join(" / "))
                }
            )));
        }
        let table = info.error_table(&format!("ewfinfo of {}", source_name(&source)));
        if !table.is_empty() {
            inherited_errors.merge(&table);
        }
    }
    if inherited_errors.sector_size == 0 {
        inherited_errors.sector_size = bytes_per_sector;
    }
    let mut inherited_stop = None;
    let mut inherited_unverified = None;
    // C-4: an E01 dfdisk made from an image with zero-filled sectors (e.g.
    // --rescue-to-e01) states them in its header notes only; without the
    // report that lists them the output must not pass for a verified copy
    let mut read_errors_note = None;
    if let Some(stated) = ewf_source
        .as_ref()
        .and_then(|i| zero_filled_in_notes(i.notes.as_deref()?))
    {
        if inherited_errors.summary(RangeKind::Substituted).is_none() {
            read_errors_note = Some(format!(
                "not in the error list of {} and in no report found; its header notes (written by dfdisk) state: {stated}",
                source_name(&source)
            ));
            inherited_unverified = Some(format!(
                "the header notes of {} state that sectors of the medium were unreadable and are zeros in the image ({stated}), but their positions are not in its error list and no report of its acquisition that lists them was found",
                source_name(&source)
            ));
            notes.push(format!(
                "{} records zero-filled sectors only in its header notes ({stated}); give the report of its acquisition or conversion (--report) to list them",
                source_name(&source)
            ));
        }
    }
    if let Some(r) = &report {
        let rr = &r.reference;
        let what = format!(
            "its {} report {} says {}",
            rr.kind,
            source_name(&rr.path),
            rr.outcome.label()
        );
        match rr.outcome {
            Outcome::Incomplete | Outcome::Aborted => {
                inherited_stop = Some(format!(
                    "the source image is itself incomplete: {what} ({})",
                    rr.outcome_reason
                ));
            }
            Outcome::CompleteUnverified => {
                inherited_unverified = Some(format!(
                    "the source image was never verified against its medium: {what} ({})",
                    rr.outcome_reason
                ));
            }
            // C-3: a matching conversion of such an image is no verified
            // copy of the medium
            Outcome::Mismatch => {
                inherited_unverified = Some(format!(
                    "the source image is not confirmed to reproduce its medium: {what} (a digest of the image or of a second read of the source differed: {})",
                    rr.outcome_reason
                ));
            }
            Outcome::VerificationFailed => {
                inherited_unverified = Some(format!(
                    "the source image is not confirmed to reproduce its medium: {what} (its verification could not run or complete: {})",
                    rr.outcome_reason
                ));
            }
            Outcome::Verified | Outcome::CompletedWithReadErrors => {}
        }
        if rr.hashes.is_empty() {
            notes.push(format!(
                "the {} report {} states no digest of the image",
                rr.kind,
                source_name(&rr.path)
            ));
        }
    } else {
        notes.push(
            "no acquisition report of the source image was found: this report says nothing about the medium the image was made from or about read errors of its acquisition"
                .into(),
        );
    }

    // Settings
    settings.digests = selection.algorithms();
    settings.bytes_per_sector = bytes_per_sector;
    match req.target {
        ConversionTarget::E01 => {
            settings.tool = "ewfacquire".into();
            settings.output_format = "EWF (EnCase 6, .E01)".into();
            settings.compression = Some(req.compression);
            settings.segment_bytes = req.split_size.bytes();
            match report.as_ref().and_then(|r| r.medium) {
                Some((physical, removable, _)) => {
                    settings.media_type =
                        Some(if removable { "removable" } else { "fixed" }.into());
                    settings.media_flags =
                        Some(if physical { "physical" } else { "logical" }.into());
                }
                None => {
                    settings.media_type = Some("fixed".into());
                    settings.media_flags = Some("physical".into());
                    settings.notes.push(
                        "media type \"fixed\" and flags \"physical\" are libewf's defaults, not facts: without an acquisition report the medium is unknown"
                            .into(),
                    );
                }
            }
            settings.ewf_header_notes = ewf_notes(
                &case,
                &source_files,
                report.as_ref(),
                &inherited_errors,
                &req.notes,
            );
        }
        ConversionTarget::Raw => {
            settings.tool = "ewfexport".into();
            settings.output_format = "RAW (one file)".into();
            if req.compression != CompressionLevel::default()
                || req.split_size != SplitSize::default()
            {
                settings
                    .notes
                    .push("compression and segment size apply to E01 outputs only; the RAW output is one uncompressed file".into());
            }
        }
    }
    notes.extend(
        req.notes
            .iter()
            .map(|n| sanitize_line(n))
            .filter(|n| !n.is_empty()),
    );

    Ok(Plan {
        target: req.target,
        source,
        source_files,
        source_format,
        expected_bytes,
        output_dir: req.output_dir.clone(),
        base_name,
        case: case.sanitized(),
        case_sources,
        report,
        ewf_source,
        inherited_errors,
        inherited_stop,
        inherited_unverified,
        read_errors_note,
        selection,
        settings,
        notes,
    })
}

/// The parts of E01 header notes in which dfdisk stated zero-filled
/// sectors ([`ewf_notes`], [`rescue_notes`]), joined; `None` without.
fn zero_filled_in_notes(notes: &str) -> Option<String> {
    let parts: Vec<&str> = notes
        .split("; ")
        .map(str::trim)
        .filter(|p| p.contains(ZEROS_NOTE_MARKER) || p.starts_with(RESCUE_NOTE_MARKER))
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// Notes for the E01 header (`-N`): the case fields without an own header
/// field, where the image came from, the source report's verdict and read
/// errors, and the request's notes. Sanitised; `None` when empty.
fn ewf_notes(
    case: &CaseMetadata,
    files: &[SourceFile],
    report: Option<&LoadedReport>,
    errors: &ReadErrorTable,
    extra: &[String],
) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(n) = case.ewf_header_notes() {
        parts.push(n);
    }
    let names: Vec<String> = files.iter().map(|f| source_name(&f.path)).collect();
    let from = if names.len() > 2 {
        format!(
            "{} .. {} ({} segments)",
            names[0],
            names[names.len() - 1],
            names.len()
        )
    } else {
        names.join(", ")
    };
    parts.push(format!(
        "Converted by dfdisk {} from {from}",
        env!("CARGO_PKG_VERSION")
    ));
    if let Some(r) = report {
        parts.push(format!(
            "Source {} report {}: {} (exit code {})",
            r.reference.kind,
            source_name(&r.reference.path),
            r.reference.outcome.label(),
            r.reference.exit_code
        ));
    }
    if let Some(s) = errors.summary(RangeKind::Substituted) {
        parts.push(format!("{s} {ZEROS_NOTE_MARKER}"));
    }
    if let Some(s) = errors.summary(RangeKind::Unread) {
        parts.push(format!("{s} never read by the acquisition"));
    }
    for n in extra {
        let n = sanitize_header(n);
        if !n.is_empty() && !parts.contains(&n) {
            parts.push(n);
        }
    }
    let joined = sanitize_header(&parts.join("; "));
    (!joined.is_empty()).then_some(joined)
}

// ---------------------------------------------------------------------------
// Destination (step 2)

fn check_destination(
    env: &ConvertEnv,
    req: &ConversionRequest,
    plan: &Plan,
) -> Result<(DestinationFacts, Vec<String>), AcquisitionError> {
    let mountinfo = match &env.mountinfo {
        Some(m) => m.clone(),
        None => fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
            AcquisitionError::refused(format!(
                "cannot read /proc/self/mountinfo to check the destination: {e}"
            ))
        })?,
    };
    let facts = preflight::probe_destination(&plan.output_dir, &mountinfo).map_err(|e| {
        AcquisitionError::refused(format!(
            "cannot inspect the destination {}: {e}",
            plan.output_dir.display()
        ))
    })?;
    let rules = DestinationRules {
        engine: match plan.target {
            ConversionTarget::E01 => EngineKind::Ewf,
            ConversionTarget::Raw => EngineKind::Raw,
        },
        source_bytes: plan.expected_bytes,
        segment_bytes: match plan.target {
            ConversionTarget::E01 => req.split_size.bytes(),
            ConversionTarget::Raw => None,
        },
        allow_tmpfs: req.allow_tmpfs,
        allow_low_space: req.allow_low_space,
        resumed_image_bytes: 0,
    };
    let notes = preflight::evaluate(&rules, &facts)?;
    let mut existing = existing_conversion_outputs(&plan.output_dir, &plan.base_name, plan.target);
    if plan.target == ConversionTarget::E01 {
        existing.extend(existing_late_segments(
            &plan.output_dir,
            &plan.base_name,
            plan.expected_bytes,
            req.split_size.bytes(),
        ));
    }
    if !existing.is_empty() {
        let list = existing
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(AcquisitionError::refused(format!(
            "Refusing to overwrite: conversion output already exists: {list}. The libewf tools would overwrite it; move it away or choose another output directory"
        )));
    }
    // Never write over the source (e.g. a source named like an output)
    let primary = plan.primary_output();
    for f in &plan.source_files {
        if f.path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            == primary
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
            && same_path(&parent_dir(&f.path), &plan.output_dir)
        {
            return Err(AcquisitionError::refused(format!(
                "the output {} would be the source {} itself",
                primary.display(),
                f.path.display()
            )));
        }
    }
    Ok((facts, notes))
}

/// The same file or directory (after resolving links), else the same path.
fn same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

// ---------------------------------------------------------------------------
// Audit

/// Writes "conversion_finished" exactly once: through `finished` / `error`,
/// or when dropped (panic, cancelled future).
struct ConversionAudit {
    log: PathBuf,
    source: PathBuf,
    target: PathBuf,
    anchor: Option<String>,
    sink: ProgressSink,
    armed: bool,
}

impl ConversionAudit {
    fn write(&mut self, result: Result<Map<String, Value>, &AcquisitionError>) {
        self.armed = false;
        if let Err(reason) = audit::conversion_finished(
            &self.log,
            &self.source,
            &self.target,
            self.anchor.as_deref(),
            result,
        ) {
            self.sink.warn(format!(
                "the audit record \"conversion_finished\" was not written: {reason}"
            ));
        }
    }

    fn finished(mut self, details: Map<String, Value>) {
        self.write(Ok(details));
    }

    fn error(mut self, err: &AcquisitionError) {
        self.write(Err(err));
    }
}

impl Drop for ConversionAudit {
    fn drop(&mut self) {
        if self.armed {
            let message = if std::thread::panicking() {
                "the conversion ended by an internal error (panic) without a result"
            } else {
                "the conversion ended without a result (cancelled)"
            };
            self.write(Err(&AcquisitionError::failed(message)));
        }
    }
}

fn started_details(plan: &Plan, destination: &DestinationFacts) -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("target_format".into(), json!(plan.target));
    d.insert(
        "output_dir".into(),
        json!(plan.output_dir.to_string_lossy()),
    );
    d.insert("base_name".into(), json!(plan.base_name));
    d.insert(
        "case".into(),
        json!({
            "case_number": plan.case.case_number,
            "evidence_number": plan.case.evidence_number,
            "examiner": plan.case.examiner,
        }),
    );
    d.insert("source_files".into(), json!(plan.source_files));
    d.insert("source_bytes".into(), json!(plan.expected_bytes));
    d.insert(
        "source_report".into(),
        plan.report
            .as_ref()
            .map(|r| {
                json!({
                    "path": r.reference.path.to_string_lossy(),
                    "sha256": r.reference.sha256,
                    "outcome": r.reference.outcome,
                })
            })
            .unwrap_or(Value::Null),
    );
    d.insert("settings".into(), json!(plan.settings));
    d.insert(
        "destination".into(),
        serde_json::to_value(destination).unwrap_or_default(),
    );
    d
}

fn finished_details(report: &ConversionReport) -> Map<String, Value> {
    let t = &report.read_errors;
    let mut d = Map::new();
    let mut put = |k: &str, v: Value| {
        d.insert(k.to_string(), v);
    };
    put("outcome", json!(report.outcome));
    put("exit_code", json!(report.exit_code));
    put("outcome_reason", json!(report.outcome_reason));
    put("expected_bytes", json!(report.expected_bytes));
    put("bytes_converted", json!(report.bytes_converted));
    put("stop_reason", json!(report.stop_reason));
    put("aborted", json!(report.aborted));
    put(
        "read_errors",
        json!({
            "source": t.source,
            "ranges": t.ranges.len(),
            "substituted_bytes": t.substituted_bytes(),
            "unread_bytes": t.unread_bytes(),
            "substituted_sectors": t.substituted_sectors(),
            "unread_sectors": t.unread_sectors(),
        }),
    );
    if !report.conversion_errors.is_empty() {
        let c = &report.conversion_errors;
        put(
            "conversion_errors",
            json!({
                "source": c.source,
                "ranges": c.ranges.len(),
                "substituted_bytes": c.substituted_bytes(),
                "substituted_sectors": c.substituted_sectors(),
            }),
        );
    }
    put("source_hashes", json!(report.source_hashes));
    put("output_hashes", json!(report.output_hashes));
    put("verification", json!(report.verification));
    put("report_file", json!(report.report_file.to_string_lossy()));
    put(
        "report_json_file",
        json!(report.report_json_file.to_string_lossy()),
    );
    put("report_sha256", json!(report.report_sha256));
    put("report_json_sha256", json!(report.report_json_sha256));
    put("output_files", json!(report.output_files));
    put("auxiliary_files", json!(report.auxiliary_files));
    put(
        "source_report",
        json!(report
            .source_report
            .as_ref()
            .map(|r| r.path.to_string_lossy().into_owned())),
    );
    put("audit_export", json!(report.audit.export_file));
    d
}

// ---------------------------------------------------------------------------
// Running the tools

/// What a tool run left.
#[derive(Debug)]
struct ToolRun {
    outcome: ProcessOutcome,
    stdout: Vec<String>,
    stderr: Vec<String>,
    /// Calculated digests the tool printed
    calculated: HashResults,
    /// Last "(N bytes) of total" status
    last_done: Option<u64>,
    /// "<tool>: SUCCESS" printed
    success_line: bool,
    /// "Read errors during export:" (ewfexport): sectors it could not read
    /// from the EWF image and wrote as zeros
    export_errors: Option<RunBlock>,
}

impl ToolRun {
    fn completed(&self) -> bool {
        self.outcome.success() && self.success_line
    }

    fn stopped(&self) -> bool {
        self.outcome.aborted || self.outcome.force_killed
    }

    /// Why the run did not complete, for the report.
    fn failure(&self, tool: &str) -> String {
        let tail: Vec<&str> = self
            .stderr
            .iter()
            .chain(self.stdout.iter())
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with("Status:"))
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!(
            "{tool} did not complete ({}){}",
            self.outcome.record.status_text(),
            if tail.is_empty() {
                String::new()
            } else {
                format!(": {}", tail.join(" / "))
            }
        )
    }
}

/// Which gauge a tool's status lines drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gauge {
    Conversion,
    Verification,
}

async fn run_tool(
    spec: &ProcessSpec,
    tool: &str,
    stop: &StopFlags,
    sink: &ProgressSink,
    recorder: &ProvenanceRecorder,
    gauge: Gauge,
) -> Result<ToolRun, AcquisitionError> {
    let success_marker = format!("{tool}: SUCCESS");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut calculated = HashResults::default();
    let mut last_done = None;
    let mut success_line = false;
    let mut export_errors = ExportErrors::default();
    let started = Instant::now();
    let outcome = process::run(spec, &stop.stop_control(), Some(recorder), |ev| {
        let ProcessEvent::Line { stream, text, .. } = ev else {
            return;
        };
        let line = text.trim();
        if line.is_empty() {
            return;
        }
        if line == success_marker {
            success_line = true;
        }
        export_errors.feed(line);
        if let Some((DigestOrigin::Calculated, alg, v)) = parse_digest_line(line) {
            set_digest(&mut calculated, alg, v);
        }
        if let Some((done, total)) = parse_status_bytes(line) {
            last_done = Some(done);
            let elapsed = started.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                done as f64 / elapsed
            } else {
                0.0
            };
            match gauge {
                Gauge::Conversion => sink.update(|t| {
                    t.bytes_processed = done;
                    t.total_bytes = total;
                    t.percentage = if total > 0 {
                        (done as f64 * 100.0 / total as f64).min(100.0)
                    } else {
                        0.0
                    };
                    t.speed_bps = speed;
                    t.avg_speed_bps = speed;
                    t.elapsed_secs = started.elapsed().as_secs();
                }),
                Gauge::Verification => sink.phase_progress(done, total, speed),
            }
        } else if parse_status_speed(line).is_none() && !line.starts_with("Status:") {
            let line = sanitize_line(line);
            sink.log(if line.starts_with(tool) {
                line
            } else {
                format!("{tool}: {line}")
            });
        }
        let kept = match stream {
            StreamTag::Stdout => &mut stdout,
            StreamTag::Stderr => &mut stderr,
        };
        if kept.len() < MAX_KEPT_LINES {
            kept.push(line.to_string());
        }
    })
    .await
    .map_err(|e| {
        AcquisitionError::failed(format!("cannot run {tool} (is libewf installed?): {e}"))
    })?;
    Ok(ToolRun {
        outcome,
        stdout,
        stderr,
        calculated,
        last_done,
        success_line,
        export_errors: export_errors.block,
    })
}

/// Collects ewfexport's "Read errors during export:" block from its output
/// lines (indentation already removed).
#[derive(Debug, Default)]
struct ExportErrors {
    block: Option<RunBlock>,
    inside: bool,
}

impl ExportErrors {
    fn feed(&mut self, line: &str) {
        if self.inside {
            self.inside = self
                .block
                .get_or_insert_with(RunBlock::default)
                .feed_trimmed(line);
        }
        if line.trim().trim_end_matches(':') == EXPORT_ERRORS_TITLE {
            self.inside = true;
            self.block.get_or_insert_with(RunBlock::default);
        }
    }
}

/// The ewfacquire command of a RAW to E01 conversion.
fn ewfacquire_spec(env: &ConvertEnv, plan: &Plan, req: &ConversionRequest) -> ProcessSpec {
    let s = &plan.settings;
    let case = &plan.case;
    let mut spec = ProcessSpec::new(&env.tools.ewfacquire)
        .arg("-u")
        .args(["-C", &case.effective_case().unwrap_or_default()])
        .args(["-E", &case.effective_evidence().unwrap_or_default()])
        .args(["-e", &case.effective_examiner().unwrap_or_default()])
        // Always given, empty when absent: libewf tools otherwise write placeholders
        .args(["-D", &case.effective_description().unwrap_or_default()])
        .args(["-N", s.ewf_header_notes.as_deref().unwrap_or_default()])
        .args(["-f", "encase6"])
        .args(["-c", req.compression.as_ewf_arg()])
        .args(["-S", &req.split_size.as_ewf_arg()])
        .args(["-m", s.media_type.as_deref().unwrap_or("fixed")])
        .args(["-M", s.media_flags.as_deref().unwrap_or("physical")])
        .args(["-P", &s.bytes_per_sector.to_string()]);
    let extra: Vec<&str> = [
        (plan.selection.sha1, "sha1"),
        (plan.selection.sha256, "sha256"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, n)| *n)
    .collect();
    if !extra.is_empty() {
        spec = spec.args(["-d", &extra.join(",")]);
    }
    spec.arg("-l")
        .arg(plan.log_path())
        .arg("-t")
        .arg(plan.output_dir.join(&plan.base_name))
        .args(plan.source_paths())
        .grace(env.grace)
}

fn ewfexport_spec(env: &ConvertEnv, plan: &Plan) -> ProcessSpec {
    ProcessSpec::new(&env.tools.ewfexport)
        .arg("-u")
        .args(["-f", "raw"])
        .arg("-l")
        .arg(plan.log_path())
        .arg("-t")
        .arg(plan.output_dir.join(&plan.base_name))
        .arg(&plan.source)
        .grace(env.grace)
}

fn ewfverify_spec(env: &ConvertEnv, plan: &Plan, image: &Path) -> ProcessSpec {
    let list: Vec<&str> = [
        (plan.selection.md5, "md5"),
        (plan.selection.sha1, "sha1"),
        (plan.selection.sha256, "sha256"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, n)| *n)
    .collect();
    ProcessSpec::new(&env.tools.ewfverify)
        .args(["-d", &list.join(",")])
        .arg(image)
        .grace(Duration::from_secs(5))
}

/// What the conversion phase measured.
#[derive(Debug, Default)]
struct Measured {
    output_files: Vec<PathBuf>,
    auxiliary: Vec<PathBuf>,
    bytes_converted: u64,
    aborted: bool,
    stop_reason: Option<String>,
    source_hashes: HashResults,
    output_hashes: HashResults,
    comparisons: Vec<DigestComparison>,
    verification: Option<VerificationResult>,
    verification_method: String,
    notes: Vec<String>,
    /// Sectors the tool could not read from the source image (zeros in the
    /// output)
    conversion_errors: ReadErrorTable,
}

/// Hash `paths` on a blocking thread, with the bytes done in `counter`.
async fn hash_blocking(
    paths: Vec<PathBuf>,
    selection: HashSelection,
    abort: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> Result<HashResults, HashError> {
    tokio::task::spawn_blocking(move || hash_files(&paths, selection, &abort, &counter))
        .await
        .unwrap_or_else(|e| Err(HashError::Io(format!("hashing task failed: {e}"))))
}

/// Hash `paths` while reporting the verification gauge.
async fn hash_with_gauge(
    paths: Vec<PathBuf>,
    selection: HashSelection,
    stop: &StopFlags,
    sink: &ProgressSink,
    total: u64,
) -> Result<HashResults, HashError> {
    let counter = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let task = hash_blocking(paths, selection, stop.abort.clone(), counter.clone());
    tokio::pin!(task);
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            res = &mut task => {
                let done = counter.load(Ordering::Relaxed);
                sink.phase_progress(done, total, done as f64 / started.elapsed().as_secs_f64().max(1e-3));
                return res;
            }
            _ = ticker.tick() => {
                let done = counter.load(Ordering::Relaxed);
                sink.phase_progress(done, total, done as f64 / started.elapsed().as_secs_f64().max(1e-3));
            }
        }
    }
}

/// RAW to E01: ewfacquire (with dfdisk's own hash of the RAW when no report
/// digest exists), then ewfinfo + ewfverify of the written E01.
async fn raw_to_e01(
    env: &ConvertEnv,
    req: &ConversionRequest,
    plan: &Plan,
    stop: &StopFlags,
    sink: &ProgressSink,
    recorder: &ProvenanceRecorder,
) -> Result<Measured, AcquisitionError> {
    let mut m = Measured::default();
    let report_ref = plan
        .report
        .as_ref()
        .map(|r| &r.reference)
        .filter(|r| !r.hashes.is_empty());
    let need_fresh = report_ref.is_none();

    sink.phase(
        AcquisitionStatus::Acquiring,
        format!(
            "Converting {} ({}) to E01 with ewfacquire",
            source_name(&plan.source),
            format_iec(plan.expected_bytes)
        ),
    );
    sink.update(|t| {
        t.total_bytes = plan.expected_bytes;
        t.bytes_processed = 0;
        t.percentage = 0.0;
        t.current_segment = plan.primary_output().to_string_lossy().into_owned();
    });
    let spec = ewfacquire_spec(env, plan, req);
    let cancel_hash = Arc::new(AtomicBool::new(false));
    let fresh_counter = Arc::new(AtomicU64::new(0));
    let tool = async {
        let r = run_tool(&spec, "ewfacquire", stop, sink, recorder, Gauge::Conversion).await;
        if !r.as_ref().is_ok_and(ToolRun::completed) {
            cancel_hash.store(true, Ordering::SeqCst);
        }
        r
    };
    let fresh = async {
        if !need_fresh {
            return None;
        }
        // Stops with the examiner's abort or a failed ewfacquire
        let abort = Arc::new(AtomicBool::new(false));
        let flag = abort.clone();
        let watch = {
            let stop = stop.clone();
            let cancel = cancel_hash.clone();
            async move {
                loop {
                    if stop.is_aborted() || cancel.load(Ordering::SeqCst) {
                        flag.store(true, Ordering::SeqCst);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };
        let hash = hash_blocking(
            plan.source_paths(),
            plan.selection,
            abort,
            fresh_counter.clone(),
        );
        tokio::select! {
            r = hash => Some(r),
            _ = watch => None,
        }
    };
    let (tool, fresh) = tokio::join!(tool, fresh);
    let tool = tool?;

    m.output_files = written_segments(&plan.output_dir, &plan.base_name);
    let log = plan.log_path();
    if log.exists() {
        m.auxiliary.push(log);
    }
    m.aborted = stop.is_aborted() || tool.stopped();
    if m.output_files.is_empty() && m.auxiliary.is_empty() {
        return Err(if m.aborted {
            AcquisitionError::aborted("the conversion was aborted before ewfacquire wrote anything")
        } else {
            AcquisitionError::failed(tool.failure("ewfacquire"))
        });
    }
    if !tool.completed() {
        m.bytes_converted = tool.last_done.unwrap_or(0).min(plan.expected_bytes);
        if !m.aborted {
            m.stop_reason = Some(tool.failure("ewfacquire"));
        }
        m.verification = Some(VerificationResult::NotPossible {
            reason: "the conversion did not complete".into(),
        });
        flush(&m, plan, sink);
        return Ok(m);
    }
    if let Some(seen) = tool
        .stdout
        .iter()
        .find(|l| l.starts_with("Media size:"))
        .and_then(|l| bytes_in_parens(l))
    {
        if seen != plan.expected_bytes {
            m.notes.push(format!(
                "ewfacquire saw a source of {seen} bytes, but the image files hold {} bytes",
                plan.expected_bytes
            ));
        }
    }

    flush(&m, plan, sink);

    // Verification: what the E01 says, then a full re-read by ewfverify
    sink.phase(
        AcquisitionStatus::Verifying,
        "Verifying the E01 (ewfverify, after fsync and page-cache eviction)",
    );
    let first = m.output_files[0].clone();
    let mut failure = None;
    match ewfinfo(env, &first, stop, recorder).await {
        Ok(info) => {
            m.bytes_converted = info.media_size.unwrap_or(0);
            if info.media_size.is_none() {
                failure = Some("ewfinfo did not report the media size of the E01".to_string());
            } else if info.corrupted {
                failure = Some(
                    "ewfinfo reports the written E01 as corrupted (\"Is corrupted: yes\")".into(),
                );
            }
        }
        Err(e) if e.kind == ErrorKind::Aborted => {
            m.aborted = true;
            return Ok(m);
        }
        Err(e) => failure = Some(e.message),
    }
    let verify = run_tool(
        &ewfverify_spec(env, plan, &first),
        "ewfverify",
        stop,
        sink,
        recorder,
        Gauge::Verification,
    )
    .await?;
    if verify.stopped() || stop.is_aborted() {
        m.aborted = true;
        return Ok(m);
    }
    if !verify.completed() {
        failure.get_or_insert(format!(
            "ewfverify found the E01 inconsistent or unreadable: {}",
            verify.failure("ewfverify")
        ));
    }
    m.output_hashes = verify.calculated.clone();

    // The independent reference: the report's digests, else dfdisk's own
    let verified_label = "ewfverify re-read of the E01";
    match (report_ref, fresh) {
        (Some(r), _) => {
            m.source_hashes = r.hashes.clone();
            m.comparisons.push(compare(
                plan.selection,
                (
                    &format!("{} report {}", r.kind, source_name(&r.path)),
                    &r.hashes,
                ),
                (verified_label, &verify.calculated),
                true,
            ));
        }
        (None, Some(Ok(hashes))) => {
            m.source_hashes = hashes.clone();
            m.comparisons.push(compare(
                plan.selection,
                ("dfdisk's hash of the RAW image", &hashes),
                (verified_label, &verify.calculated),
                true,
            ));
        }
        (None, Some(Err(HashError::Io(e)))) => {
            failure.get_or_insert(format!(
                "dfdisk could not hash the RAW image for the comparison: {e}"
            ));
        }
        (None, Some(Err(HashError::Aborted)) | None) => {
            if stop.is_aborted() {
                m.aborted = true;
                return Ok(m);
            }
            failure.get_or_insert("dfdisk's hash of the RAW image did not complete".into());
        }
    }
    // Consistency of the tool: what ewfacquire computed while reading vs the re-read
    m.comparisons.push(compare(
        plan.selection,
        ("ewfacquire while reading the RAW image", &tool.calculated),
        (verified_label, &verify.calculated),
        false,
    ));
    if verify.calculated.is_empty() {
        failure.get_or_insert("ewfverify reported no calculated digest".into());
    }
    m.verification = Some(overall(&m.comparisons, failure));
    m.verification_method = format!(
        "ewfverify -d {} of the E01 after fsync and page-cache eviction, compared with {}",
        plan.selection
            .algorithms()
            .iter()
            .map(|a| a.label())
            .collect::<Vec<_>>()
            .join(","),
        match report_ref {
            Some(r) => format!(
                "the digests of the {} report {}",
                r.kind,
                source_name(&r.path)
            ),
            None =>
                "dfdisk's own hash of the RAW image (read while ewfacquire converted it)".into(),
        }
    );
    Ok(m)
}

fn flush(m: &Measured, plan: &Plan, sink: &ProgressSink) {
    sink.phase(
        AcquisitionStatus::Flushing,
        "Flushing the output to the destination and evicting it from the page cache",
    );
    let files: Vec<PathBuf> = m
        .output_files
        .iter()
        .chain(m.auxiliary.iter())
        .cloned()
        .collect();
    for problem in flush_and_evict(&files, &plan.output_dir) {
        sink.warn(problem);
    }
}

/// Why an E01 to RAW output is not the whole source image, and the sectors
/// ewfexport wrote as zeros because it could not read them (C-1): ewfinfo's
/// "Is corrupted: yes" (segments missing, or never finalized) and
/// ewfexport's "Read errors during export".
fn export_problems(plan: &Plan, tool: &ToolRun, out_len: u64) -> (Vec<String>, ReadErrorTable) {
    let src = source_name(&plan.source);
    let mut problems = Vec::new();
    if plan.ewf_source.as_ref().is_some_and(|i| i.corrupted) {
        problems.push(format!(
            "ewfinfo reports {src} as corrupted (\"Is corrupted: yes\"): segments of it are missing or it was never finalized (an interrupted acquisition), so it does not hold the whole source image"
        ));
    }
    let mut table = ReadErrorTable::new(
        plan.settings.bytes_per_sector,
        format!("ewfexport (read errors during export of {src})"),
    );
    if let Some(block) = &tool.export_errors {
        for r in &block.runs {
            table.push_sectors(r.first, r.count, RangeKind::Substituted);
        }
        table.normalise();
        let what = table
            .summary(RangeKind::Substituted)
            .unwrap_or_else(|| "sectors".into());
        let mut p = format!(
            "ewfexport could not read {what} of {src} and wrote zeros there instead (listed under the read errors of this conversion)"
        );
        if block.incomplete() {
            p.push_str(&format!(
                "; it reported {} whose positions could not all be determined{}",
                block
                    .total
                    .map(|n| crate::models::text::plural(n, "read error", "read errors"))
                    .unwrap_or_else(|| "read errors".into()),
                if block.unparsed.is_empty() {
                    String::new()
                } else {
                    format!(" (not understood: {})", block.unparsed.join(" | "))
                }
            ));
        }
        if out_len < table.ranges.last().map(|r| r.end()).unwrap_or(0) {
            p.push_str(&format!(
                "; the output file ends at byte {out_len}, before the last of them"
            ));
        }
        problems.push(p);
    }
    (problems, table)
}

/// Bytes of `table` that lie inside an output of `len` bytes.
fn zeros_within(table: &ReadErrorTable, len: u64) -> u64 {
    table
        .ranges
        .iter()
        .map(|r| r.end().min(len).saturating_sub(r.offset.min(len)))
        .sum()
}

/// E01 to RAW: ewfexport, then dfdisk hashes the written RAW file and
/// compares with the digests stored in the E01 (and the report's).
async fn e01_to_raw(
    env: &ConvertEnv,
    plan: &Plan,
    stop: &StopFlags,
    sink: &ProgressSink,
    recorder: &ProvenanceRecorder,
) -> Result<Measured, AcquisitionError> {
    let mut m = Measured::default();
    sink.phase(
        AcquisitionStatus::Acquiring,
        format!(
            "Exporting {} ({}) to RAW with ewfexport",
            source_name(&plan.source),
            format_iec(plan.expected_bytes)
        ),
    );
    sink.update(|t| {
        t.total_bytes = plan.expected_bytes;
        t.bytes_processed = 0;
        t.percentage = 0.0;
        t.current_segment = plan.primary_output().to_string_lossy().into_owned();
    });
    let tool = run_tool(
        &ewfexport_spec(env, plan),
        "ewfexport",
        stop,
        sink,
        recorder,
        Gauge::Conversion,
    )
    .await?;
    let raw = plan.primary_output();
    let raw_info = plan.output_dir.join(format!("{}.raw.info", plan.base_name));
    if raw.exists() {
        m.output_files.push(raw.clone());
    }
    for aux in [raw_info, plan.log_path()] {
        if aux.exists() {
            m.auxiliary.push(aux);
        }
    }
    m.aborted = stop.is_aborted() || tool.stopped();
    if m.output_files.is_empty() && m.auxiliary.is_empty() {
        return Err(if m.aborted {
            AcquisitionError::aborted("the conversion was aborted before ewfexport wrote anything")
        } else {
            AcquisitionError::failed(tool.failure("ewfexport"))
        });
    }
    let out_len = fs::metadata(&raw).map(|md| md.len()).unwrap_or(0);
    m.bytes_converted = out_len;
    // C-1: what the E01 lacks. libewf 20140816 exports a corrupted E01
    // (missing segments, never finalized) with zeros where it cannot read
    // and ends with SUCCESS; the output then is not the whole source image
    let (problems, errors) = export_problems(plan, &tool, out_len);
    m.bytes_converted = out_len.saturating_sub(zeros_within(&errors, out_len));
    m.conversion_errors = errors;
    if !tool.completed() || m.output_files.is_empty() {
        let mut reasons = problems;
        if !m.aborted {
            reasons.push(if m.output_files.is_empty() {
                format!(
                    "ewfexport wrote no RAW file {}: {}",
                    raw.display(),
                    tool.failure("ewfexport")
                )
            } else {
                tool.failure("ewfexport")
            });
        }
        m.stop_reason = (!reasons.is_empty()).then(|| reasons.join("; "));
        m.verification = Some(VerificationResult::NotPossible {
            reason: "the conversion did not complete".into(),
        });
        flush(&m, plan, sink);
        return Ok(m);
    }
    if !problems.is_empty() {
        m.stop_reason = Some(problems.join("; "));
    }
    flush(&m, plan, sink);

    sink.phase(
        AcquisitionStatus::Verifying,
        "Hashing the written RAW file (after fsync and page-cache eviction)",
    );
    let mut failure = None;
    let output = match hash_with_gauge(vec![raw.clone()], plan.selection, stop, sink, out_len).await
    {
        Ok(h) => h,
        Err(HashError::Aborted) => {
            m.aborted = true;
            return Ok(m);
        }
        Err(HashError::Io(e)) => {
            failure = Some(format!("the written RAW file could not be read back: {e}"));
            HashResults::default()
        }
    };
    m.output_hashes = output.clone();
    let output_label = "dfdisk's hash of the written RAW file";
    let stored = plan
        .ewf_source
        .as_ref()
        .map(|i| i.stored.clone())
        .unwrap_or_default();
    let mut references = Vec::new();
    if !stored.is_empty() {
        m.source_hashes = stored.clone();
        m.comparisons.push(compare(
            plan.selection,
            (
                &format!("digests stored in {}", source_name(&plan.source)),
                &stored,
            ),
            (output_label, &output),
            true,
        ));
        references.push(format!(
            "the digests stored in the E01 ({})",
            stored
                .present()
                .iter()
                .map(|(l, _)| *l)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else if plan.ewf_source.as_ref().is_some_and(|i| i.corrupted) {
        m.notes.push(format!(
            "no digest stored in {} could be read: an E01 stores its digests in its last segment, which is missing or was never written (ewfinfo: corrupted)",
            source_name(&plan.source)
        ));
    } else {
        m.notes.push(format!(
            "{} stores no digest of its media data",
            source_name(&plan.source)
        ));
    }
    if let Some(r) = plan
        .report
        .as_ref()
        .map(|r| &r.reference)
        .filter(|r| !r.hashes.is_empty())
    {
        if m.source_hashes.is_empty() {
            m.source_hashes = r.hashes.clone();
        }
        m.comparisons.push(compare(
            plan.selection,
            (
                &format!("{} report {}", r.kind, source_name(&r.path)),
                &r.hashes,
            ),
            (output_label, &output),
            true,
        ));
        references.push(format!("the {} report {}", r.kind, source_name(&r.path)));
    }
    m.comparisons.push(compare(
        plan.selection,
        ("ewfexport while writing", &tool.calculated),
        (output_label, &output),
        false,
    ));
    m.verification = Some(overall(&m.comparisons, failure));
    m.verification_method = format!(
        "RAW file hashed by dfdisk after fsync and page-cache eviction, compared with {}",
        if references.is_empty() {
            "nothing independent".to_string()
        } else {
            references.join(" and ")
        }
    );
    Ok(m)
}

// ---------------------------------------------------------------------------
// The run

async fn run(
    env: &ConvertEnv,
    req: &ConversionRequest,
    sink: &ProgressSink,
    stop: &StopFlags,
) -> Result<ConversionReport, AcquisitionError> {
    let t0 = Instant::now();
    let clock = tokio::task::spawn_blocking(ClockInfo::capture_start)
        .await
        .unwrap_or_default();
    let recorder = ProvenanceRecorder::new();
    sink.phase(AcquisitionStatus::Preparing, "Checking the conversion");

    // 1-2: nothing is written before these pass
    let plan = plan(env, req, stop, &recorder).await?;
    let (destination, destination_notes) = check_destination(env, req, &plan)?;
    if stop.is_aborted() {
        return Err(AcquisitionError::aborted(
            "the conversion was aborted before anything was written",
        ));
    }

    // 3: first write, then "conversion_started"
    let mut output = preflight::prepare_output(&plan.output_dir, &plan.report_base(), false)?;
    let target_path = plan.primary_output();
    let audit_info = match audit::conversion_started(
        &env.audit_log,
        &plan.source,
        &target_path,
        started_details(&plan, &destination),
    ) {
        Ok(anchor) => AuditInfo {
            anchor: Some(anchor),
            status: AuditStatus::Written,
            export_file: None,
        },
        Err(reason) => {
            if env.registry != RegistryPresence::Absent {
                return Err(AcquisitionError::refused(format!(
                    "the dfnix audit log {} cannot be written ({reason}); on dfnix every conversion is recorded before it starts",
                    env.audit_log.display()
                )));
            }
            sink.warn(format!("audit log not written: {reason}"));
            AuditInfo {
                anchor: None,
                status: AuditStatus::NotWritten {
                    reason: format!(
                        "the audit log {} cannot be written: {reason}",
                        env.audit_log.display()
                    ),
                },
                export_file: None,
            }
        }
    };
    let guard = ConversionAudit {
        log: env.audit_log.clone(),
        source: plan.source.clone(),
        target: target_path,
        anchor: audit_info.anchor.clone(),
        sink: sink.clone(),
        armed: true,
    };

    // 4-5
    let measured = match plan.target {
        ConversionTarget::E01 => raw_to_e01(env, req, &plan, stop, sink, &recorder).await,
        ConversionTarget::Raw => e01_to_raw(env, &plan, stop, sink, &recorder).await,
    };
    let measured = match measured {
        Ok(m) => m,
        Err(e) => {
            guard.error(&e);
            return Err(e);
        }
    };
    output.keep();

    // 6
    sink.phase(
        AcquisitionStatus::Finalizing,
        "Writing the conversion report",
    );
    let mut report = build_report(plan, measured, clock, t0, &recorder, audit_info).await;
    report.notes.extend(destination_notes);
    if report.audit.status == AuditStatus::Written && env.export_audit {
        match dfcore::audit::export(&env.audit_log, &report.output_dir) {
            Ok(info) => report.audit.export_file = Some(info.jsonl.to_string_lossy().into_owned()),
            Err(e) => report.notes.push(format!(
                "the audit log was not copied to the output directory: {e:#}"
            )),
        }
    }
    report.notes.extend(sink.warnings());
    report.apply_classification();
    if let Err(e) = report.write_reports() {
        let err = AcquisitionError::failed(format!(
            "the conversion ended {} (exit code {}), but its report could not be written to {}: {e}",
            report.outcome.label(),
            report.exit_code,
            report.output_dir.display()
        ));
        guard.error(&err);
        return Err(err);
    }
    sink.log(format!("Report written: {}", report.report_file.display()));
    guard.finished(finished_details(&report));
    if let Some(expected) = report.audit.export_file.clone() {
        match dfcore::audit::export(&env.audit_log, &report.output_dir) {
            Ok(info) if info.jsonl.to_string_lossy() == expected.as_str() => {}
            Ok(info) => sink.warn(format!(
                "the audit log was copied to {} instead of {expected}",
                info.jsonl.display()
            )),
            Err(e) => sink.warn(format!(
                "the audit log copy {expected} was not updated with the finished record: {e:#}"
            )),
        }
    }
    Ok(report)
}

async fn build_report(
    plan: Plan,
    m: Measured,
    clock: ClockInfo,
    t0: Instant,
    recorder: &ProvenanceRecorder,
    audit_info: AuditInfo,
) -> ConversionReport {
    let mut report = ConversionReport::new(plan.source.clone(), plan.target, clock);
    report.case_metadata = plan.case.clone();
    report.case_sources = plan.case_sources.clone();
    report.source_format = plan.source_format.clone();
    report.source_files = plan.source_files.clone();
    report.source_report = plan.report.as_ref().map(|r| r.reference.clone());
    report.output_dir = plan.output_dir.clone();
    report.base_name = plan.base_name.clone();
    report.settings = plan.settings.clone();
    report.expected_bytes = plan.expected_bytes;
    report.bytes_converted = m.bytes_converted;
    report.aborted = m.aborted;
    report.read_errors = plan.inherited_errors.clone();
    report.read_errors_note = plan.read_errors_note.clone();
    report.conversion_errors = m.conversion_errors;
    report.stop_reason = match (m.stop_reason, plan.inherited_stop.clone()) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    };
    report.source_hashes = m.source_hashes;
    report.output_hashes = m.output_hashes;
    report.comparisons = m.comparisons;
    report.verification_method = m.verification_method;
    let mut verification = m
        .verification
        .unwrap_or_else(|| VerificationResult::NotPossible {
            reason: if m.aborted {
                "the conversion was aborted before its verification".into()
            } else {
                "the output was not verified".into()
            },
        });
    if let (VerificationResult::Matched { method }, Some(why)) =
        (&verification, &plan.inherited_unverified)
    {
        verification = VerificationResult::NotPossible {
            reason: format!("the output reproduces the source image ({method}), but {why}"),
        };
    }
    report.verification = verification;
    report.output_files = m.output_files;
    report.auxiliary_files = m
        .auxiliary
        .iter()
        .filter_map(|p| FileDigest::compute(p).ok())
        .collect();
    report.notes = plan.notes;
    report.notes.extend(m.notes);
    if report.aborted {
        report.notes.push(
            "the conversion was aborted: the output files listed are partial and must not be used"
                .into(),
        );
    } else if report.stop_reason.is_some()
        && !report.output_files.is_empty()
        && plan.inherited_stop.is_none()
    {
        report.notes.push(
            "the conversion did not complete: the output files listed are partial and must not be used"
                .into(),
        );
    }

    let mut provenance = ToolProvenance::capture();
    recorder.fill(&mut provenance);
    let used: std::collections::BTreeSet<OsString> = provenance
        .commands
        .iter()
        .filter_map(|c| c.argv.first().map(OsString::from))
        .collect();
    for program in used {
        let name = Path::new(&program)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if provenance.tools.contains_key(&name) {
            continue;
        }
        let version =
            process::tool_version(&program.to_string_lossy(), &["-V"], Duration::from_secs(5))
                .await
                .unwrap_or_else(|| "not available".into());
        provenance.tools.insert(name, version);
    }
    report.provenance = provenance;
    report.audit = audit_info;

    let elapsed = t0.elapsed();
    report.clock.finish(elapsed);
    report.ended_at = report.clock.end_utc.unwrap_or_else(chrono::Utc::now);
    report.elapsed_seconds = elapsed.as_secs();
    report.average_speed_bytes_sec = if elapsed.as_secs_f64() > 0.0 {
        report.bytes_converted as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ewfinfo` of an E01 that ewfacquire 20231119 made from a device with
    /// one unreadable sector (LD_PRELOAD EIO shim), captured verbatim.
    const EWFINFO_WITH_ERRORS: &str = "ewfinfo 20231119\n\nAcquiry information:\n\tCase number:\t\tCASE\n\tDescription:\t\td\n\tExaminer name:\t\tex\n\tEvidence number:\tev\n\tAcquisition date:\tWed Oct 14 21:39:53 2026\n\tSystem date:\t\tWed Oct 14 21:39:53 2026\n\tOperating system used:\tLinux\n\tSoftware version used:\t20231119\n\tPassword:\t\tN/A\n\nEWF information:\n\tFile format:\t\tEnCase 6\n\tSectors per chunk:\t64\n\tError granularity:\t64\n\tCompression method:\tdeflate\n\tCompression level:\tgood (fast) compression\n\nMedia information:\n\tMedia type:\t\tfixed disk\n\tIs physical:\t\tyes\n\tBytes per sector:\t512\n\tNumber of sectors:\t8192\n\tMedia size:\t\t4.0 MiB (4194304 bytes)\n\nDigest hash information:\n\tMD5:\t\t\tdff66e485c3b83c5234d523dff5bf008\n\tSHA1:\t\t\tea882d0546363ce521a410a61e155cd2a8a23156\n\nRead errors during acquiry:\n\ttotal number: 1\n\tat sector(s): 2048 - 2111 (number: 64)\n\n";

    /// `ewfinfo` of an E01 written by ewfacquirestream without -C/-E/-e/-D/-N:
    /// libewf's placeholders end up in the header.
    const EWFINFO_PLACEHOLDERS: &str = "ewfinfo 20231119\n\nAcquiry information:\n\tCase number:\t\tcase_number\n\tDescription:\t\tdescription\n\tExaminer name:\t\texaminer_name\n\tEvidence number:\tevidence_number\n\tNotes:\t\t\tnotes\n\tAcquisition date:\tThu Oct 15 01:08:06 2026\n\nMedia information:\n\tMedia type:\t\tfixed disk\n\tIs physical:\t\tyes\n\tBytes per sector:\t512\n\tNumber of sectors:\t1953\n\tMedia size:\t\t976 KiB (999936 bytes)\n\nDigest hash information:\n\tMD5:\t\t\t4c41b8f7a6ca2d36fa464ce1ad174290\n";

    /// ewfacquire 20231119 stdout of a 300 MiB file (status block and digests).
    const EWFACQUIRE_STDOUT: &str = "ewfacquire 20231119\n\nStorage media information:\nType:\t\t\t\t\tRAW image\nMedia size:\t\t\t\t314 MB (314572800 bytes)\nBytes per sector:\t\t\t512\n\nAcquiry started at: Oct 15, 2026 01:12:00\nThis could take a while.\n\nStatus: at 51.2%\n        acquired 153 MiB (161153024 bytes) of total 300 MiB (314572800 bytes)\n        completion in 3 second(s) with 42 MiB/s (44938971 bytes/second)\n\nAcquiry completed at: Oct 15, 2026 01:12:06\n\nWritten: 300 MiB (314574116 bytes) in 6 second(s) with 50 MiB/s (52429019 bytes/second)\nMD5 hash calculated over data:\t\tc31dbec0775852c437443f39b9d5b7f3\newfacquire: SUCCESS\n";

    /// ewfverify 20231119 stdout (SHA-256 is not stored in EnCase 6 files).
    const EWFVERIFY_STDOUT: &str = "ewfverify 20231119\n\nVerify started at: Oct 15, 2026 01:07:57\nThis could take a while.\n\nVerify completed at: Oct 15, 2026 01:07:57\n\nRead: 3.0 MiB (3145728 bytes) in 0 second(s)\n\nMD5 hash stored in file:\t\tba7750b877115ae15c5fb461714a2c2a\nMD5 hash calculated over data:\t\tba7750b877115ae15c5fb461714a2c2a\nSHA1 hash stored in file:\t\tN/A\nSHA1 hash calculated over data:\t\t7a334aa098a87f86ed5b2123f1968df01cf2a401\nSHA256 hash stored in file:\t\tN/A\nSHA256 hash calculated over data:\t65fbe9ef3f994895ead117ca0e962762960037b596f396fbcf7b0a7e6a4ef3fa\n\newfverify: SUCCESS\n";

    /// The same E01 read by ewfinfo 20140816 (Ubuntu's ewf-tools line): no
    /// colon after section titles, no parentheses around the count.
    const EWFINFO_LEGACY_WITH_ERRORS: &str = "ewfinfo 20140816\n\nAcquiry information\n\tCase number:\t\tCASE\n\tDescription:\t\td\n\tExaminer name:\t\tex\n\tEvidence number:\tev\n\tAcquisition date:\tWed Oct 14 21:39:53 2026\n\tSystem date:\t\tWed Oct 14 21:39:53 2026\n\tOperating system used:\tLinux\n\tSoftware version used:\t20231119\n\tPassword:\t\tN/A\n\nEWF information\n\tFile format:\t\tEnCase 6\n\tSectors per chunk:\t64\n\tError granularity:\t64\n\tCompression method:\tdeflate\n\tCompression level:\tgood (fast) compression\n\nMedia information\n\tMedia type:\t\tfixed disk\n\tIs physical:\t\tyes\n\tBytes per sector:\t512\n\tNumber of sectors:\t8192\n\tMedia size:\t\t4.0 MiB (4194304 bytes)\n\nDigest hash information\n\tMD5:\t\t\tdff66e485c3b83c5234d523dff5bf008\n\tSHA1:\t\t\tea882d0546363ce521a410a61e155cd2a8a23156\n\nRead errors during acquiry\n\ttotal number: 1\n\tat sector(s): 2048 - 2111 number: 64\n\n";

    /// ewfacquire 20140816 status block (sentences end with a period).
    const EWFACQUIRE_LEGACY_STATUS: &str = "Status: at 30%.\n        acquired 61 MiB (64749568 bytes) of total 200 MiB (209715200 bytes).\n        completion in 9 second(s) with 15 MiB/s (16131938 bytes/second).\n";

    /// ewfinfo of an E01 whose last segment is missing (libewf 20231119;
    /// 20140816 prints the same lines without the colons after the titles).
    const EWFINFO_CORRUPTED: &str = "ewfinfo 20231119\n\nAcquiry information:\n\tCase number:\t\tc\n\nEWF information:\n\tFile format:\t\tEnCase 6\n\tSectors per chunk:\t64\n\tError granularity:\t64\n\tCompression method:\tdeflate\n\tCompression level:\tno compression\n\tIs corrupted:\t\tyes\n\nMedia information:\n\tMedia type:\t\tfixed disk\n\tIs physical:\t\tyes\n\tBytes per sector:\t512\n\tNumber of sectors:\t6144\n\tMedia size:\t\t3.0 MiB (3145728 bytes)\n\n";

    /// ewfexport 20140816 on that E01: zeros for what it cannot read, then
    /// SUCCESS (standard error, then standard output), captured.
    const EWFEXPORT_LEGACY_ERRORS: &str = "ewfexport 20140816\n\n\nExport started at: Oct 15, 2026 08:07:33\nThis could take a while.\n\nExport completed at: Oct 15, 2026 08:07:33\n\nWritten: 3.0 MiB (3145728 bytes) in 0 second(s).\nMD5 hash calculated over data:\t\t6e17beab9ec6f8bbe2610f26664b87ad\nRead errors during export:\n\ttotal number: 1\n\tat sector(s): 5952 - 6143 (number: 192) in segment file(s):\n\newfexport: SUCCESS\n";

    #[test]
    fn a_corrupted_e01_and_ewfexports_read_errors_are_recognised() {
        let info = parse_ewfinfo(EWFINFO_CORRUPTED);
        assert!(info.corrupted);
        assert_eq!(info.media_size, Some(3_145_728));
        assert!(info.stored.is_empty());
        let legacy = EWFINFO_CORRUPTED
            .replace("information:", "information")
            .replace("ewfinfo 20231119", "ewfinfo 20140816");
        assert!(parse_ewfinfo(&legacy).corrupted);
        assert!(!parse_ewfinfo(EWFINFO_WITH_ERRORS).corrupted);

        let mut e = ExportErrors::default();
        for line in EWFEXPORT_LEGACY_ERRORS.lines() {
            let t = line.trim();
            if !t.is_empty() {
                e.feed(t);
            }
        }
        let block = e.block.unwrap();
        assert_eq!(block.total, Some(1));
        assert_eq!(block.runs.len(), 1);
        assert_eq!((block.runs[0].first, block.runs[0].count), (5952, 192));
        assert!(!block.incomplete());
        // A count without positions fails closed
        let mut e = ExportErrors::default();
        for t in [
            "Read errors during export:",
            "total number: 2",
            "at sector(s): somewhere",
            "ewfexport: SUCCESS",
        ] {
            e.feed(t);
        }
        assert!(e.block.unwrap().incomplete());
        // No block: nothing
        let mut e = ExportErrors::default();
        e.feed("ewfexport: SUCCESS");
        assert!(e.block.is_none());

        let mut t = ReadErrorTable::new(512, "x");
        t.push_sectors(5952, 192, RangeKind::Substituted);
        assert_eq!(zeros_within(&t, 3 << 20), 192 * 512);
        assert_eq!(zeros_within(&t, 5952 * 512 + 512), 512);
        assert_eq!(zeros_within(&t, 1000), 0);
    }

    #[test]
    fn both_libewf_lines_parse_the_same() {
        assert_eq!(
            parse_ewfinfo(EWFINFO_LEGACY_WITH_ERRORS),
            parse_ewfinfo(EWFINFO_WITH_ERRORS)
        );
        let lines: Vec<&str> = EWFACQUIRE_LEGACY_STATUS.lines().collect();
        assert_eq!(
            lines.iter().find_map(|l| parse_status_bytes(l)),
            Some((64_749_568, 209_715_200))
        );
        assert_eq!(
            lines.iter().find_map(|l| parse_status_speed(l)),
            Some(16_131_938.0)
        );
    }

    #[test]
    fn error_ranges_are_parsed_conservatively() {
        assert_eq!(
            parse_error_range("2048 - 2111 (number: 64)"),
            Some((2048, 64))
        );
        assert_eq!(
            parse_error_range("2048 - 2111 number: 64"),
            Some((2048, 64))
        );
        assert_eq!(parse_error_range("7 - 7 number: 1"), Some((7, 1)));
        // Range and count disagree: the larger
        assert_eq!(parse_error_range("0 - 9 (number: 4)"), Some((0, 10)));
        assert_eq!(parse_error_range("0 - 1 number: 64"), Some((0, 64)));
        assert_eq!(parse_error_range("garbage"), None);
        assert_eq!(parse_error_range("9 - 2 number: 1"), None);
        let info = parse_ewfinfo(
            "Read errors during acquiry:\n\ttotal number: 2\n\tat sector(s): somewhere\n",
        );
        assert_eq!(info.unparsed_errors.len(), 1);
        assert_eq!(info.read_error_total, Some(2));
    }

    #[test]
    fn ewfinfo_with_read_errors_is_parsed() {
        let info = parse_ewfinfo(EWFINFO_WITH_ERRORS);
        assert_eq!(info.case_number.as_deref(), Some("CASE"));
        assert_eq!(info.examiner.as_deref(), Some("ex"));
        assert_eq!(info.evidence_number.as_deref(), Some("ev"));
        assert_eq!(info.description.as_deref(), Some("d"));
        assert_eq!(info.notes, None);
        assert_eq!(info.media_size, Some(4_194_304));
        assert_eq!(info.bytes_per_sector, Some(512));
        assert_eq!(info.is_physical, Some(true));
        assert_eq!(
            info.stored.md5.as_deref(),
            Some("dff66e485c3b83c5234d523dff5bf008")
        );
        assert_eq!(
            info.stored.sha1.as_deref(),
            Some("ea882d0546363ce521a410a61e155cd2a8a23156")
        );
        assert_eq!(info.stored.sha256, None);
        assert_eq!(info.read_errors, vec![(2048, 64)]);
        assert_eq!(info.read_error_total, Some(1));
        let t = info.error_table("ewfinfo");
        assert_eq!(t.substituted_bytes(), 64 * 512);
        assert_eq!(t.ranges[0].offset, 2048 * 512);
        assert_eq!(t.unread_bytes(), 0);
    }

    #[test]
    fn libewf_placeholders_are_not_case_values() {
        let info = parse_ewfinfo(EWFINFO_PLACEHOLDERS);
        assert_eq!(info.media_size, Some(999_936));
        assert!(info.read_errors.is_empty());
        let mut notes = Vec::new();
        let case = header_case(&info, &mut notes);
        assert_eq!(case, CaseMetadata::default());
        assert_eq!(notes.len(), 4, "{notes:?}");
        let info = parse_ewfinfo(EWFINFO_WITH_ERRORS);
        let case = header_case(&info, &mut notes);
        assert_eq!(case.case_number, "CASE");
        assert_eq!(case.examiner, "ex");
    }

    #[test]
    fn tool_lines_are_parsed() {
        let lines: Vec<&str> = EWFACQUIRE_STDOUT.lines().collect();
        let status: Vec<(u64, u64)> = lines.iter().filter_map(|l| parse_status_bytes(l)).collect();
        assert_eq!(status, vec![(161_153_024, 314_572_800)]);
        assert_eq!(
            lines.iter().find_map(|l| parse_status_speed(l)),
            Some(44_938_971.0)
        );
        let media = lines
            .iter()
            .find(|l| l.starts_with("Media size:"))
            .and_then(|l| bytes_in_parens(l));
        assert_eq!(media, Some(314_572_800));
        let digests: Vec<_> = lines.iter().filter_map(|l| parse_digest_line(l)).collect();
        assert_eq!(
            digests,
            vec![(
                DigestOrigin::Calculated,
                HashAlgorithm::MD5,
                "c31dbec0775852c437443f39b9d5b7f3".to_string()
            )]
        );

        let v: Vec<_> = EWFVERIFY_STDOUT
            .lines()
            .filter_map(parse_digest_line)
            .collect();
        // "N/A" stored values are ignored; stored and calculated told apart
        assert_eq!(v.len(), 4);
        assert_eq!(
            v.iter()
                .filter(|(o, _, _)| *o == DigestOrigin::Stored)
                .count(),
            1
        );
        assert!(parse_digest_line("MD5 hash calculated over data:\t\tnot-hex").is_none());
        assert!(parse_digest_line("SHA256 hash calculated over data:\t\tabc").is_none());
        assert!(parse_digest_line("Something else: ab").is_none());
    }

    #[test]
    fn base_names_strip_split_ewf_and_image_extensions() {
        for (name, base) in [
            ("disk.raw", "disk"),
            ("disk.RAW", "disk"),
            ("disk.dd", "disk"),
            ("disk.img", "disk"),
            ("disk.bin", "disk"),
            ("disk.001", "disk"),
            ("disk.raw.001", "disk"),
            ("disk.E01", "disk"),
            ("disk.e01", "disk"),
            ("disk.Ex01", "disk"),
            ("case_ea01_cf01_SER.raw", "case_ea01_cf01_SER"),
            ("evidence.tar.gz", "evidence.tar.gz"),
            ("disk", "disk"),
        ] {
            assert_eq!(
                conversion_base_name(Path::new(name)).as_deref(),
                Some(base),
                "{name}"
            );
        }
        assert_eq!(conversion_base_name(Path::new(".raw")), None);
        assert_eq!(conversion_base_name(Path::new("/")), None);
    }

    #[test]
    fn ewf_segment_numbers() {
        assert_eq!(ewf_segment_number("E01"), Some(("e".into(), 1)));
        assert_eq!(ewf_segment_number("e99"), Some(("e".into(), 99)));
        assert_eq!(ewf_segment_number("EAA"), Some(("e".into(), 100)));
        assert_eq!(ewf_segment_number("EAB"), Some(("e".into(), 101)));
        assert_eq!(ewf_segment_number("EBA"), Some(("e".into(), 126)));
        assert_eq!(ewf_segment_number("Ex01"), Some(("ex".into(), 1)));
        assert_eq!(ewf_segment_number("s02"), Some(("s".into(), 2)));
        assert_eq!(ewf_segment_number("L01"), Some(("l".into(), 1)));
        assert_eq!(ewf_segment_number("E00"), None);
        assert_eq!(ewf_segment_number("E1A"), None);
        assert_eq!(ewf_segment_number("raw"), None);
        assert_eq!(ewf_segment_number("001"), None);
    }

    fn touch(dir: &Path, name: &str, len: usize) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, vec![7u8; len]).unwrap();
        p
    }

    #[test]
    fn split_raw_sets_are_complete_or_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let first = touch(d, "x.001", 1024);
        touch(d, "x.002", 1024);
        touch(d, "x.003", 512);
        touch(d, "y.004", 1024); // other stem
        touch(d, "x.0004", 1024); // other width
        let set = split_raw_segments(&first).unwrap();
        assert_eq!(set.len(), 3);
        assert_eq!(set.iter().map(|f| f.bytes).sum::<u64>(), 2560);
        // A later segment is not a start
        let e = split_raw_segments(&d.join("x.002")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Usage);
        assert!(e.message.contains("not the first segment"), "{e}");
        // A gap refuses
        touch(d, "x.005", 1024);
        let e = split_raw_segments(&first).unwrap_err();
        assert!(e.message.contains("x.004 is missing"), "{e}");
        fs::remove_file(d.join("x.005")).unwrap();
        // A short segment in the middle refuses
        touch(d, "x.004", 1024);
        let e = split_raw_segments(&first).unwrap_err();
        assert!(e.message.contains("differ in size"), "{e}");
        fs::remove_file(d.join("x.004")).unwrap();
        // A set starting at 000
        let zero = touch(d, "z.000", 512);
        touch(d, "z.001", 512);
        assert_eq!(split_raw_segments(&zero).unwrap().len(), 2);
        // A plain file is one segment
        let raw = touch(d, "p.raw", 512);
        assert_eq!(split_raw_segments(&raw).unwrap().len(), 1);
    }

    #[test]
    fn ewf_families_are_complete_or_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        touch(d, "x.E01", 10);
        touch(d, "x.E02", 10);
        touch(d, "x.E03", 10);
        touch(d, "x.raw", 10);
        let set = ewf_segments(&d.join("x.E02")).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set[0].path.ends_with("x.E01"));
        touch(d, "x.E05", 10);
        let e = ewf_segments(&d.join("x.E01")).unwrap_err();
        assert!(e.message.contains("number 4 is missing"), "{e}");
        fs::remove_file(d.join("x.E05")).unwrap();
        touch(d, "x.e02", 10);
        if fs::read_dir(d).unwrap().count() == 5 {
            // case-sensitive filesystem: two spellings of one segment
            let e = ewf_segments(&d.join("x.E01")).unwrap_err();
            assert!(e.message.contains("ambiguous"), "{e}");
        }
        let l = touch(d, "y.L01", 10);
        let e = ewf_segments(&l).unwrap_err();
        assert!(e.message.contains("logical evidence"), "{e}");
    }

    #[test]
    fn ewf_families_beyond_ezz_are_complete() {
        // C-2: 811 segments, as ewfacquire writes 811 MiB with -S 1MiB
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let names: Vec<String> = (1..=811)
            .map(|n| ewf::segment_extension("E01", n).unwrap())
            .collect();
        assert_eq!(names[774], "EZZ");
        assert_eq!(names[775], "FAA");
        assert_eq!(names[810], "FBJ");
        for ext in &names {
            touch(d, &format!("x.{ext}"), 1);
        }
        touch(d, "x.raw", 1);
        touch(d, "x.RAW", 1);
        let set = ewf_segments(&d.join("x.E01")).unwrap();
        assert_eq!(set.len(), 811);
        assert!(set[775].path.ends_with("x.FAA"));
        assert!(set[810].path.ends_with("x.FBJ"));
        let written = written_segments(d, "x");
        assert_eq!(written.len(), 811);
        assert_eq!(
            written,
            set.iter().map(|f| f.path.clone()).collect::<Vec<_>>()
        );
        // Existing late segments refuse an E01 output that can reach them,
        // never a source named like one when it cannot
        let late = existing_late_segments(d, "x", 811 << 20, Some(1 << 20));
        assert_eq!(late.len(), 811 - 775, "{late:?}");
        assert!(existing_late_segments(d, "x", 3 << 20, Some(1 << 20)).is_empty());
        assert!(existing_late_segments(d, "x", 811 << 20, None).is_empty());
    }

    #[test]
    fn existing_outputs_are_found_case_insensitively() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        touch(d, "x.raw", 1); // the source of a RAW to E01 conversion
        touch(d, "x.info", 1); // its acquisition report
        touch(d, "x.info.json", 1);
        assert!(existing_conversion_outputs(d, "x", ConversionTarget::E01).is_empty());
        assert_eq!(
            existing_conversion_outputs(d, "x", ConversionTarget::Raw).len(),
            1
        );
        touch(d, "X.e01", 1);
        assert_eq!(
            existing_conversion_outputs(d, "x", ConversionTarget::E01).len(),
            1
        );
        touch(d, "x.Conversion.Info", 1);
        assert_eq!(
            existing_conversion_outputs(d, "x", ConversionTarget::E01).len(),
            2
        );
        touch(d, "x.raw.info", 1);
        assert_eq!(
            existing_conversion_outputs(d, "x", ConversionTarget::Raw).len(),
            3
        );
        // Missing directory: nothing exists
        assert!(
            existing_conversion_outputs(&d.join("nope"), "x", ConversionTarget::E01).is_empty()
        );
    }

    #[test]
    fn case_values_merge_with_given_values_winning() {
        let report = CaseMetadata {
            case_number: "C1".into(),
            evidence_number: "E1".into(),
            examiner: "Alice".into(),
            description: "laptop".into(),
            ..Default::default()
        };
        let given = CaseMetadata {
            examiner: "Bob\tSmith".into(),
            seal_number: "S9".into(),
            ..Default::default()
        };
        let (merged, used, notes) = merge_case(&[
            (report, "acquisition report x.info.json".into()),
            (given, "given for this conversion".into()),
        ]);
        assert_eq!(merged.case_number, "C1");
        assert_eq!(merged.examiner, "Bob Smith");
        assert_eq!(merged.seal_number, "S9");
        assert_eq!(merged.description, "laptop");
        assert_eq!(used.len(), 2);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("\"Alice\""), "{notes:?}");
        // Nothing given at all
        let (merged, used, _) = merge_case(&[]);
        assert!(merged.validate_required().is_err());
        assert!(used.is_empty());
    }

    fn h(md5: &str, sha256: Option<&str>) -> HashResults {
        HashResults {
            md5: Some(md5.into()),
            sha1: None,
            sha256: sha256.map(str::to_string),
        }
    }

    const MD5_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MD5_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn comparisons_decide_the_verification() {
        let sel = HashSelection {
            md5: true,
            sha1: true,
            sha256: true,
        };
        let same = compare(
            sel,
            ("report", &h(MD5_A, None)),
            ("re-read", &h(MD5_A, Some("cc"))),
            true,
        );
        assert!(same.result.is_matched());
        let diff = compare(
            sel,
            ("report", &h(MD5_A, None)),
            ("re-read", &h(MD5_B, None)),
            true,
        );
        assert!(matches!(diff.result, VerificationResult::Mismatched { .. }));
        let none = compare(
            sel,
            ("report", &HashResults::default()),
            ("re-read", &h(MD5_A, None)),
            true,
        );
        assert!(matches!(
            none.result,
            VerificationResult::NotPossible { .. }
        ));
        let tool = compare(
            sel,
            ("tool", &h(MD5_A, None)),
            ("re-read", &h(MD5_A, None)),
            false,
        );

        // Matched needs an independent match
        assert!(overall(&[same.clone(), tool.clone()], None).is_matched());
        assert!(matches!(
            overall(&[none.clone(), tool.clone()], None),
            VerificationResult::NotPossible { .. }
        ));
        // A mismatch anywhere wins, also over a failure
        assert!(matches!(
            overall(&[same.clone(), diff.clone()], Some("x".into())),
            VerificationResult::Mismatched { .. }
        ));
        // A failure wins over a match
        assert!(matches!(
            overall(&[same, tool], Some("ewfverify failed".into())),
            VerificationResult::Failed { .. }
        ));
    }

    #[test]
    fn hashing_concatenates_files_and_stops_on_abort() {
        let tmp = tempfile::tempdir().unwrap();
        let a = touch(tmp.path(), "a", 3);
        let b = touch(tmp.path(), "b", 2);
        let sel = HashSelection {
            md5: true,
            sha1: false,
            sha256: true,
        };
        let done = AtomicU64::new(0);
        let split = hash_files(&[a.clone(), b], sel, &AtomicBool::new(false), &done).unwrap();
        let whole = touch(tmp.path(), "w", 5);
        let one = hash_files(&[whole], sel, &AtomicBool::new(false), &AtomicU64::new(0)).unwrap();
        assert_eq!(split, one);
        assert_eq!(split.sha1, None);
        assert_eq!(done.load(Ordering::Relaxed), 5);
        assert!(matches!(
            hash_files(&[a], sel, &AtomicBool::new(true), &AtomicU64::new(0)),
            Err(HashError::Aborted)
        ));
        assert!(matches!(
            hash_files(
                &[tmp.path().join("missing")],
                sel,
                &AtomicBool::new(false),
                &AtomicU64::new(0)
            ),
            Err(HashError::Io(_))
        ));
    }

    #[test]
    fn rescue_notes_say_how_many_ranges_they_list() {
        use crate::models::config::{AcquisitionConfig, EffectiveConfig};
        let config = AcquisitionConfig::rescue("/out");
        let mut report = ForensicInfoReport::new(
            EngineKind::Rescue,
            &CaseMetadata::default(),
            Default::default(),
            EffectiveConfig::build(&config, None),
        );
        let json = Path::new("/out/b.info.json");
        let mut t = ReadErrorTable::new(512, "ddrescue mapfile");
        for i in 0..25u64 {
            t.push(i * 4096, 512, RangeKind::Substituted);
        }
        report.read_errors = t;
        let notes = rescue_notes(&report, json);
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with(
                "Zero-filled sectors of the rescue (ddrescue mapfile, 512 bytes each), the first 20 of 25 ranges: 0-0, 8-8,"
            ),
            "{notes:?}"
        );
        assert!(
            notes[0].ends_with("152-152 and 5 more ranges (see b.info.json)"),
            "{notes:?}"
        );
        // All listed: no count
        report.read_errors.ranges.truncate(2);
        let notes = rescue_notes(&report, json);
        assert_eq!(
            notes[0],
            "Zero-filled sectors of the rescue (ddrescue mapfile, 512 bytes each): 0-0, 8-8"
        );
        // Both forms are found again in E01 header notes
        let header = format!(
            "Notes: x; Converted by dfdisk 0.2.0 from b.raw; 2 sectors (1 KiB) in 2 ranges {ZEROS_NOTE_MARKER}; {}",
            notes[0]
        );
        let found = zero_filled_in_notes(&header).unwrap();
        assert!(
            found.starts_with("2 sectors (1 KiB) in 2 ranges unreadable"),
            "{found}"
        );
        assert!(found.ends_with("0-0, 8-8"), "{found}");
        assert_eq!(zero_filled_in_notes("Notes: x; Converted by dfdisk"), None);
    }

    #[test]
    fn e01_notes_name_the_source_and_its_read_errors() {
        let case = CaseMetadata {
            case_number: "C".into(),
            evidence_number: "E".into(),
            examiner: "X".into(),
            notes: "seized\nat home".into(),
            ..Default::default()
        };
        let files: Vec<SourceFile> = (1..=4)
            .map(|i| SourceFile {
                path: PathBuf::from(format!("/img/x.{i:03}")),
                bytes: 512,
            })
            .collect();
        let mut errors = ReadErrorTable::new(512, "map");
        errors.push(4096, 1024, RangeKind::Substituted);
        let notes = ewf_notes(&case, &files, None, &errors, &["extra; line".into()]).unwrap();
        assert!(notes.contains("Notes: seized at home"), "{notes}");
        assert!(notes.contains("x.001 .. x.004 (4 segments)"), "{notes}");
        assert!(
            notes.contains("2 sectors (1 KiB) in 1 range unreadable"),
            "{notes}"
        );
        assert!(notes.ends_with("extra; line"), "{notes}");
        assert!(!notes.contains('\n'));
    }
}
