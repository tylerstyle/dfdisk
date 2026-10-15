//! E01 engine (§13 E01; review C1, H2, M3, M9 option fidelity, M12).
//!
//! ewfacquire reads the source once and computes every digest; afterwards
//! `ewfinfo -e` and `ewfinfo -m` read back what the image itself records, and
//! (after the session's flush and cache eviction) ewfverify re-reads the
//! image for verification. Every tool runs through [`crate::engines::process`]
//! (both streams, `LC_ALL=C`, own process group, recorded in the report).
//!
//! What the engine measures and how:
//! - **Read errors.** ewfacquire substitutes zeros for sectors it cannot read
//!   and lists them on standard output ("Errors reading device:" / "total
//!   number: N" / "at sector(s): A - B number: C (offset ...)"; B is exclusive)
//!   and in the image (`ewfinfo -e`: "at sector(s): A - B (number: C)"; B is
//!   inclusive). Both lists are parsed by first sector and count, in the
//!   tool's bytes per sector, and their union becomes the read-error table
//!   (`Substituted`); a disagreement is noted. A reported error count whose
//!   positions cannot be determined fails closed (stop reason, Incomplete).
//!   Measured with libewf 20231119: the listed ranges are exactly the sectors
//!   that are zeros in the image, with or without `-w`; they can include
//!   readable sectors around an unreadable one (error granularity, and the
//!   rest of a read request that failed).
//! - **Size.** The media size the image records (`ewfinfo -m`, else
//!   ewfacquire's own "Media size") is the number of bytes acquired; less than
//!   the probed size is a shortfall (Incomplete).
//! - **Source loss.** When the source's node disappears (or is another device
//!   now), ewfacquire stops with FAILURE (libsmdev re-checks the path after a
//!   read error). When it does not notice and zero-fills to the end of the
//!   medium, a read-error range that runs to the end together with a vanished,
//!   replaced or smaller source (checked after ewfacquire ended: presence and
//!   size) becomes "source lost at offset X" (the range is then `Unread`:
//!   those zeros are not source data). The session re-checks the
//!   identity as well. When the source ends before its probed size while it
//!   stays attached (a shrunk file, a device reporting less), ewfacquire
//!   waits for data forever: after [`SOURCE_STALL_SECS`] without progress the
//!   engine checks the source's presence and size, and when it is gone or
//!   smaller it stops ewfacquire itself (stop reason "source lost at offset
//!   X", not an abort).
//! - **Abort.** SIGINT to ewfacquire, 15 s grace, then SIGTERM/SIGKILL
//!   (process runner); the force flag kills at once. The segments are kept and
//!   the engine returns `Ok` with `aborted: true` and the last progress figure.
//!   An interrupted ewfacquire leaves an unfinalized image ("Is corrupted:
//!   yes"), which the report states.
//! - **Options.** `-g`, `-m`, `-M` and `-l <base>.ewfacquire.log` are passed
//!   as the effective config states; what ewfacquire actually applied (its
//!   "defaulting to" notices, the granularity, media type and flags the image
//!   records) replaces the requested values in the report, with a note when
//!   they differ. `-r` (0..=255) is passed only for a count other than
//!   ewfacquire's own default of 2 ([`EWFACQUIRE_DEFAULT_RETRIES`]; the
//!   report then says "-r not given"): ewfacquire 20140807 (Ubuntu 22.04's
//!   ewf-tools) and the other releases [`retries_option_crashes`] names crash
//!   on any `-r`, and the session refuses another count with them before
//!   anything is written ([`check_retries_option`]).

use crate::engines::error::AcquisitionError;
use crate::engines::process::{
    self, ProcessEvent, ProcessOutcome, ProcessSpec, StopControl, StreamTag,
};
use crate::engines::session::{EngineContext, EngineOutput};
use crate::models::config::{
    AcquisitionConfig, EffectiveConfig, EngineSettings, EwfSettings, HashSelection,
    EWFACQUIRE_DEFAULT_RETRIES, MAX_RETRIES,
};
use crate::models::identity::SourceIdentity;
use crate::models::info_report::{compare_digests, HashResults};
use crate::models::outcome::{RangeKind, ReadErrorTable, VerificationResult};
use crate::models::text::{format_iec, plural};
use dfcore::sysfs::parse_dev_num;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Seconds ewfacquire may make no progress before the engine checks whether
/// the source is still present with its size (E-1). A process-wide setting
/// so tests can lower it; 60 s otherwise.
pub static SOURCE_STALL_SECS: AtomicU64 = AtomicU64::new(60);

/// SIGINT -> SIGTERM delay when ewfacquire is aborted (§13).
pub const EWFACQUIRE_GRACE: Duration = Duration::from_secs(15);
/// SIGINT -> SIGTERM delay for ewfverify and ewfinfo.
const READER_GRACE: Duration = Duration::from_secs(5);
/// ewfinfo reads only the section headers of the image.
const EWFINFO_TIMEOUT: Duration = Duration::from_secs(300);
/// `-l`: ewfacquire's log of read errors and digests (auxiliary file).
pub const LOG_SUFFIX: &str = ".ewfacquire.log";
/// Diagnostic lines of a tool kept for the report.
const MAX_DIAGNOSTICS: usize = 40;
/// Lines of an error block that could not be parsed, kept for the report.
const MAX_UNPARSED: usize = 20;

// ---------------------------------------------------------------------------
// Parsers (pure; tested against real captured output in tests/fixtures/ewf)
// ---------------------------------------------------------------------------

/// A run of sectors as libewf lists it, in the tool's bytes per sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRun {
    pub first: u64,
    pub count: u64,
}

/// How a libewf tool says it ended (`<tool>: SUCCESS`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStatus {
    Success,
    Failure,
    Aborted,
}

impl ToolStatus {
    fn parse(line: &str, tool: &str) -> Option<Self> {
        let rest = line.strip_prefix(tool)?.strip_prefix(':')?.trim();
        match rest {
            "SUCCESS" => Some(ToolStatus::Success),
            "FAILURE" => Some(ToolStatus::Failure),
            "ABORTED" => Some(ToolStatus::Aborted),
            _ => None,
        }
    }
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// "at sector(s): A - B number: C" (ewfacquire) or "at sector(s): A - B
/// (number: C)" (ewfinfo, ewfverify): first sector and count. The end sector
/// is ignored because the two tools disagree on whether it is inclusive.
pub fn parse_sector_run(line: &str) -> Option<SectorRun> {
    static RUN: OnceLock<Regex> = OnceLock::new();
    let caps = re(
        &RUN,
        r"at sector\(s\):\s*(\d+)\s*-\s*(\d+)\s*\(?\s*number:\s*(\d+)",
    )
    .captures(line)?;
    let first = caps[1].parse().ok()?;
    let count: u64 = caps[3].parse().ok()?;
    (count > 0).then_some(SectorRun { first, count })
}

/// "... (4194304 bytes)" -> 4194304.
fn bytes_in_parens(line: &str) -> Option<u64> {
    static BYTES: OnceLock<Regex> = OnceLock::new();
    re(&BYTES, r"\((\d+) bytes\)")
        .captures(line)?
        .get(1)?
        .as_str()
        .parse()
        .ok()
}

/// "acquired 1.6 MiB (1736704 bytes) of total ..." / "verified ..." -> bytes done.
fn progress_bytes(line: &str) -> Option<u64> {
    static DONE: OnceLock<Regex> = OnceLock::new();
    re(&DONE, r"^\s*\w+ .*\((\d+) bytes\) of total ")
        .captures(line)?
        .get(1)?
        .as_str()
        .parse()
        .ok()
}

fn number_after(line: &str, prefix: &str) -> Option<u64> {
    line.trim()
        .strip_prefix(prefix)?
        .trim()
        .trim_end_matches('.')
        .parse()
        .ok()
}

/// A section heading of ewfinfo/ewfverify output: an unindented line that
/// is only a title, with (libewf 20231119) or without (20140816) a trailing
/// colon, e.g. "Media information:" -> "Media information".
fn heading(raw: &str) -> Option<&str> {
    if raw.starts_with([' ', '\t']) {
        return None;
    }
    let t = raw.trim();
    let title = t.strip_suffix(':').unwrap_or(t);
    (!title.is_empty() && !title.contains(':') && !title.contains('\t')).then_some(title)
}

/// Parse a libewf "<ALGO> hash calculated over data: <hex>" line.
pub fn parse_calculated_hash(line: &str) -> Option<(&'static str, String)> {
    parse_hash_line(line, "calculated over data")
}

/// Parse a libewf "<ALGO> hash stored in file: <hex>" line (N/A -> None).
pub fn parse_stored_hash(line: &str) -> Option<(&'static str, String)> {
    parse_hash_line(line, "stored in file")
}

fn algo_of(label: &str) -> Option<&'static str> {
    match label {
        "MD5" => Some("md5"),
        "SHA1" => Some("sha1"),
        "SHA256" => Some("sha256"),
        _ => None,
    }
}

fn valid_digest(algo: &str, value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let expected_len = match algo {
        "md5" => 32,
        "sha1" => 40,
        _ => 64,
    };
    (value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit())).then_some(value)
}

fn parse_hash_line(line: &str, kind: &str) -> Option<(&'static str, String)> {
    let (label, value) = line.split_once(':')?;
    let algo = algo_of(
        label
            .trim()
            .strip_suffix(kind)?
            .trim()
            .strip_suffix("hash")?
            .trim(),
    )?;
    Some((algo, valid_digest(algo, value)?))
}

fn set_hash(hashes: &mut HashResults, algo: &str, value: String) {
    match algo {
        "md5" => hashes.md5 = Some(value),
        "sha1" => hashes.sha1 = Some(value),
        "sha256" => hashes.sha256 = Some(value),
        _ => {}
    }
}

/// A block of sector runs ("Errors reading device:", "Read errors during
/// acquiry:", "Sector validation errors:").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunBlock {
    /// "total number: N"
    pub total: Option<u64>,
    pub runs: Vec<SectorRun>,
    /// Lines of the block that are neither the total nor a run
    pub unparsed: Vec<String>,
}

impl RunBlock {
    /// Feed one raw line of the block; `false` when the line ends the block
    /// (an empty or unindented line) and was not consumed.
    fn feed(&mut self, raw: &str) -> bool {
        let t = raw.trim();
        if t.is_empty() || !raw.starts_with([' ', '\t']) {
            return false;
        }
        if let Some(n) = number_after(t, "total number:") {
            self.total = Some(n);
        } else if let Some(run) = parse_sector_run(t) {
            self.runs.push(run);
        } else if self.unparsed.len() < MAX_UNPARSED {
            self.unparsed.push(t.to_string());
        }
        true
    }

    /// Feed one line of the block with its indentation already removed (as
    /// the converter keeps tool output): `false` when the line is neither
    /// the total nor a run, i.e. the block has ended.
    pub fn feed_trimmed(&mut self, line: &str) -> bool {
        let t = line.trim();
        if let Some(n) = number_after(t, "total number:") {
            self.total = Some(n);
        } else if let Some(run) = parse_sector_run(t) {
            self.runs.push(run);
        } else if t.starts_with("at sector(s):") {
            // A run in a form this parser does not know: fails closed
            if self.unparsed.len() < MAX_UNPARSED {
                self.unparsed.push(t.to_string());
            }
        } else {
            return false;
        }
        true
    }

    /// Positions are missing: a count was reported but fewer runs parsed,
    /// or lines of the block could not be parsed.
    pub fn incomplete(&self) -> bool {
        self.total.is_some_and(|n| n > self.runs.len() as u64) || !self.unparsed.is_empty()
    }

    /// Sectors listed.
    pub fn sectors(&self) -> u64 {
        self.runs.iter().map(|r| r.count).sum()
    }
}

/// What ewfacquire printed (standard output and standard error).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EwfacquireReport {
    /// "ewfacquire 20231119"
    pub version: Option<String>,
    /// Size of the source as ewfacquire determined it
    pub media_size: Option<u64>,
    /// Sector size of the source as ewfacquire determined it
    pub bytes_per_sector: Option<u32>,
    /// The "Errors reading device:" block, when printed
    pub errors: Option<RunBlock>,
    /// Digests computed while reading the source
    pub hashes: HashResults,
    /// Last "acquired N bytes of total" progress figure
    pub acquired_bytes: Option<u64>,
    pub status: Option<ToolStatus>,
    /// "Unsupported number of error retries defaulting to: N." (printed by
    /// ewfacquire 20231119 for every `-r`; N is the value it applies)
    pub retries_applied: Option<u32>,
    /// "Unsupported sector error granularity defaulting to: N."
    pub granularity_applied: Option<u32>,
    /// "Unsupported maximum segment size defaulting to: N." (bytes): the
    /// segment size ewfacquire applied instead of `-S`
    pub segment_bytes_applied: Option<u64>,
    /// Other standard-error lines (errors, warnings)
    pub diagnostics: Vec<String>,
}

/// Streaming parser of ewfacquire's output.
#[derive(Debug, Default)]
pub struct EwfacquireParser {
    report: EwfacquireReport,
    in_errors: bool,
}

impl EwfacquireParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, stream: StreamTag, raw: &str) {
        let t = raw.trim();
        let r = &mut self.report;
        if stream == StreamTag::Stderr {
            if let Some(n) = number_after(t, "Unsupported number of error retries defaulting to:") {
                r.retries_applied = u32::try_from(n).ok();
            } else if let Some(n) =
                number_after(t, "Unsupported sector error granularity defaulting to:")
            {
                r.granularity_applied = u32::try_from(n).ok();
            } else if let Some(n) =
                number_after(t, "Unsupported maximum segment size defaulting to:")
            {
                r.segment_bytes_applied = Some(n);
            } else if !t.is_empty() && r.diagnostics.len() < MAX_DIAGNOSTICS {
                r.diagnostics.push(t.to_string());
            }
            return;
        }
        if self.in_errors {
            if r.errors.get_or_insert_with(RunBlock::default).feed(raw) {
                return;
            }
            self.in_errors = false;
        }
        if t.is_empty() {
            return;
        }
        if r.version.is_none() && t.starts_with("ewfacquire ") && !t.contains(':') {
            r.version = Some(t.to_string());
        } else if t.starts_with("Media size:") {
            r.media_size = bytes_in_parens(t);
        } else if let Some(n) = number_after(t, "Bytes per sector:") {
            r.bytes_per_sector = u32::try_from(n).ok();
        } else if heading(raw) == Some("Errors reading device") {
            self.in_errors = true;
            r.errors.get_or_insert_with(RunBlock::default);
        } else if let Some(done) = progress_bytes(raw) {
            r.acquired_bytes = Some(r.acquired_bytes.unwrap_or(0).max(done));
        } else if let Some(status) = ToolStatus::parse(t, "ewfacquire") {
            r.status = Some(status);
        } else if let Some((algo, v)) = parse_calculated_hash(t) {
            set_hash(&mut r.hashes, algo, v);
        } else if t.to_ascii_lowercase().contains("error") {
            // A read-error report in a form this parser does not know: kept
            // as not understood, which fails closed
            let block = r.errors.get_or_insert_with(RunBlock::default);
            if block.unparsed.len() < MAX_UNPARSED {
                block.unparsed.push(t.to_string());
            }
        }
    }

    pub fn report(&self) -> &EwfacquireReport {
        &self.report
    }

    pub fn finish(self) -> EwfacquireReport {
        self.report
    }
}

/// [`EwfacquireParser`] over complete captured output.
pub fn parse_ewfacquire(stdout: &str, stderr: &str) -> EwfacquireReport {
    let mut p = EwfacquireParser::new();
    for line in stdout.lines() {
        p.feed(StreamTag::Stdout, line);
    }
    for line in stderr.lines() {
        p.feed(StreamTag::Stderr, line);
    }
    p.finish()
}

/// `ewfinfo -e`: the read errors the image records.
/// Lines other than the version line and the error block are kept as not
/// understood, so an output format this parser does not know fails closed
/// (never counts as "no errors").
pub fn parse_ewfinfo_errors(stdout: &str) -> RunBlock {
    let mut block = RunBlock::default();
    let mut inside = false;
    for raw in stdout.lines() {
        if inside {
            if block.feed(raw) {
                continue;
            }
            inside = false;
        }
        let t = raw.trim();
        if t.is_empty() || (t.starts_with("ewfinfo ") && !t.contains(':')) {
            continue;
        }
        // "Read errors during acquiry:" (20231119) or without the colon
        // (20140816, the Debian/Ubuntu ewf-tools line)
        if heading(raw) == Some("Read errors during acquiry") {
            inside = true;
        } else if block.unparsed.len() < MAX_UNPARSED {
            block.unparsed.push(t.to_string());
        }
    }
    block
}

/// `ewfinfo -m`: what the image records about the media.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EwfMediaInfo {
    pub sectors_per_chunk: Option<u64>,
    pub error_granularity: Option<u32>,
    /// "fixed disk", "removable disk", ...
    pub media_type: Option<String>,
    pub is_physical: Option<bool>,
    pub bytes_per_sector: Option<u32>,
    pub number_of_sectors: Option<u64>,
    pub media_size: Option<u64>,
    /// "Is corrupted: yes": the image was not finalized (interrupted)
    pub corrupted: bool,
    /// Digests stored in the image ("Digest hash information")
    pub stored: HashResults,
}

pub fn parse_ewfinfo_media(stdout: &str) -> EwfMediaInfo {
    let mut m = EwfMediaInfo::default();
    let mut in_digests = false;
    for raw in stdout.lines() {
        let t = raw.trim();
        if t.is_empty() {
            in_digests = false;
            continue;
        }
        if let Some(h) = heading(raw) {
            in_digests = h == "Digest hash information";
            continue;
        }
        let Some((label, value)) = t.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if in_digests {
            if let Some(algo) = algo_of(label.trim()) {
                if let Some(v) = valid_digest(algo, value) {
                    set_hash(&mut m.stored, algo, v);
                }
            }
            continue;
        }
        match label.trim() {
            "Sectors per chunk" => m.sectors_per_chunk = value.parse().ok(),
            "Error granularity" => m.error_granularity = value.parse().ok(),
            "Media type" => m.media_type = Some(value.to_string()),
            "Is physical" => m.is_physical = Some(value == "yes"),
            "Bytes per sector" => m.bytes_per_sector = value.parse().ok(),
            "Number of sectors" => m.number_of_sectors = value.parse().ok(),
            "Media size" => m.media_size = bytes_in_parens(value),
            "Is corrupted" => m.corrupted = value == "yes",
            _ => {}
        }
    }
    m
}

/// What ewfverify printed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EwfverifyReport {
    pub version: Option<String>,
    /// Digests recomputed over the media data (the only ones that count)
    pub calculated: HashResults,
    /// Digests stored in the image ("stored in file", or "Additional hash
    /// values" for an algorithm without a "stored in file" value)
    pub stored: HashResults,
    /// "Sector validation errors:" (chunk checksum failures)
    pub validation_errors: Option<RunBlock>,
    /// "Read: ... (N bytes)": media bytes ewfverify read
    pub bytes_read: Option<u64>,
    /// Last "verified N bytes of total" progress figure
    pub progress_bytes: Option<u64>,
    pub status: Option<ToolStatus>,
    pub diagnostics: Vec<String>,
}

impl EwfverifyReport {
    /// "N sectors with checksum errors", when ewfverify found any.
    pub fn validation_summary(&self) -> Option<String> {
        let b = self.validation_errors.as_ref()?;
        let n = b.sectors().max(b.total.unwrap_or(0));
        (n > 0 || !b.unparsed.is_empty()).then(|| {
            format!(
                "ewfverify found {} with checksum errors in the image",
                plural(n.max(1), "sector", "sectors")
            )
        })
    }
}

/// Streaming parser of ewfverify's output.
#[derive(Debug, Default)]
pub struct EwfverifyParser {
    report: EwfverifyReport,
    additional: HashResults,
    section: VerifySection,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum VerifySection {
    #[default]
    Main,
    Validation,
    Additional,
}

impl EwfverifyParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, stream: StreamTag, raw: &str) {
        let t = raw.trim();
        let r = &mut self.report;
        if stream == StreamTag::Stderr {
            if !t.is_empty() && r.diagnostics.len() < MAX_DIAGNOSTICS {
                r.diagnostics.push(t.to_string());
            }
            return;
        }
        match self.section {
            VerifySection::Validation => {
                if r.validation_errors
                    .get_or_insert_with(RunBlock::default)
                    .feed(raw)
                {
                    return;
                }
                self.section = VerifySection::Main;
            }
            VerifySection::Additional => {
                if let Some((label, value)) = t.split_once(':') {
                    if let Some(algo) = algo_of(label.trim()) {
                        if let Some(v) = valid_digest(algo, value) {
                            set_hash(&mut self.additional, algo, v);
                        }
                        return;
                    }
                }
                self.section = VerifySection::Main;
            }
            VerifySection::Main => {}
        }
        if t.is_empty() {
            return;
        }
        if r.version.is_none() && t.starts_with("ewfverify ") && !t.contains(':') {
            r.version = Some(t.to_string());
        } else if heading(raw) == Some("Sector validation errors") {
            self.section = VerifySection::Validation;
            r.validation_errors.get_or_insert_with(RunBlock::default);
        } else if heading(raw) == Some("Additional hash values") {
            self.section = VerifySection::Additional;
        } else if t.starts_with("Read:") {
            r.bytes_read = bytes_in_parens(t);
        } else if let Some(done) = progress_bytes(raw) {
            r.progress_bytes = Some(r.progress_bytes.unwrap_or(0).max(done));
        } else if let Some(status) = ToolStatus::parse(t, "ewfverify") {
            r.status = Some(status);
        } else if let Some((algo, v)) = parse_calculated_hash(t) {
            set_hash(&mut r.calculated, algo, v);
        } else if let Some((algo, v)) = parse_stored_hash(t) {
            set_hash(&mut r.stored, algo, v);
        }
    }

    pub fn finish(mut self) -> EwfverifyReport {
        let r = &mut self.report;
        if r.stored.md5.is_none() {
            r.stored.md5 = self.additional.md5.take();
        }
        if r.stored.sha1.is_none() {
            r.stored.sha1 = self.additional.sha1.take();
        }
        if r.stored.sha256.is_none() {
            r.stored.sha256 = self.additional.sha256.take();
        }
        self.report
    }
}

/// [`EwfverifyParser`] over complete captured output.
pub fn parse_ewfverify(stdout: &str, stderr: &str) -> EwfverifyReport {
    let mut p = EwfverifyParser::new();
    for line in stdout.lines() {
        p.feed(StreamTag::Stdout, line);
    }
    for line in stderr.lines() {
        p.feed(StreamTag::Stderr, line);
    }
    p.finish()
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Digests verified for an E01: MD5 is always calculated by ewfacquire.
pub fn ewf_selection(config: &AcquisitionConfig) -> HashSelection {
    HashSelection {
        md5: true,
        sha1: config.calc_sha1,
        sha256: config.calc_sha256,
    }
}

/// Comma-separated `-d` value. ewfacquire always calculates MD5 and only takes
/// the additional types; ewfverify takes the full list.
pub fn ewf_digest_list(selection: HashSelection, include_md5: bool) -> Option<String> {
    let list: Vec<&str> = [
        (include_md5 && selection.md5, "md5"),
        (selection.sha1, "sha1"),
        (selection.sha256, "sha256"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| *name)
    .collect();
    if list.is_empty() {
        None
    } else {
        Some(list.join(","))
    }
}

/// Bytes per sector an E01 stores: EWF images hold whole sectors.
pub const EWF_SECTOR_BYTES: u64 = 512;

/// An E01 can hold the whole source only when its size is a multiple of 512
/// bytes. Measured with libewf 20231119 and 20140816: for a 3,000,000-byte
/// regular file ewfacquire hashes all bytes but stores 5,859 whole sectors
/// (2,999,808 bytes), so the image silently lacks the last 192 bytes and
/// does not verify. Block devices always have whole sectors; this refuses
/// such sources (regular files) as a usage error before anything is written.
pub fn check_source_size(size_bytes: u64) -> Result<(), String> {
    let rest = size_bytes % EWF_SECTOR_BYTES;
    if rest == 0 {
        return Ok(());
    }
    Err(format!(
        "the source is {size_bytes} bytes, {rest} bytes more than {}; an E01 image stores whole sectors only, and ewfacquire would leave the last {rest} bytes out of the image while including them in its digests. Acquire this source with the RAW engine instead",
        crate::models::text::plural(
            size_bytes / EWF_SECTOR_BYTES,
            "whole 512-byte sector",
            "whole 512-byte sectors"
        )
    ))
}

/// The libewf release of an ewfacquire version line ("ewfacquire 20140807"
/// gives 20140807); `None` when the line names no release (eight digits).
pub fn libewf_release(version_line: &str) -> Option<u32> {
    let token = version_line
        .trim()
        .strip_prefix("ewfacquire")?
        .split_whitespace()
        .next()?;
    (token.len() == 8 && token.bytes().all(|b| b.is_ascii_digit()))
        .then(|| token.parse().ok())
        .flatten()
}

/// Whether ewfacquire of libewf `release` crashes on `-r`. Its option parser
/// hands the `-b` string to the retry setting instead of the `-r` string, so
/// `-r N` without `-b` dereferences a null pointer (SIGSEGV before anything
/// is written) and `-r N -b M` applies M retries. Determined from libewf's
/// history (ewfacquire.c, `device_handle_set_number_of_error_retries(...,
/// option_sectors_per_chunk, ...)`): introduced in 20101105, fixed upstream
/// on 2020-02-10 ("Addressed issue with error retries in ewfacquire"): in
/// libewf-legacy from 20140810 on (20140806 to 20140808 still have it) and in
/// libewf after 20200210 (whose development line restarted at 20141002 after
/// 20140608). Run with each distribution's ewf-tools: 20140608 (Ubuntu
/// 18.04), 20140804 (Debian 10) and 20140807 (Debian 11, Ubuntu 20.04 and
/// 22.04) crash on `ewfacquire -u -r 2`; 20140813 (Debian 12), 20140814
/// (Ubuntu 24.04), 20140816 (Debian 13, nixpkgs libewf-legacy) and 20231119
/// (nixpkgs libewf) apply it.
pub fn retries_option_crashes(release: u32) -> bool {
    (20101105..=20140808).contains(&release) || (20141002..=20200210).contains(&release)
}

/// `retries` read retries with the ewfacquire whose version line is
/// `version` (`None`: unknown, e.g. `ewfacquire -V` failed): the usage error
/// when that ewfacquire would be given `-r` and crashes on it. The default
/// count is never passed, so it works with every release; an unknown
/// release is not refused (a crash would fail the run before ewfacquire
/// wrote anything).
pub fn check_retries_option(retries: u32, version: Option<&str>) -> Result<(), String> {
    if retries == EWFACQUIRE_DEFAULT_RETRIES {
        return Ok(());
    }
    let Some(release) = version.and_then(libewf_release) else {
        return Ok(());
    };
    if !retries_option_crashes(release) {
        return Ok(());
    }
    Err(format!(
        "{retries} read retries need ewfacquire's -r option, and the installed ewfacquire {release} crashes on -r (libewf 20101105 to 20140808 and 20141002 to 20200210 hand the -b value to the retry setting, so -r without -b ends in a segmentation fault). Use the default of {EWFACQUIRE_DEFAULT_RETRIES} read retries (leave out --retries), or install a libewf whose ewfacquire takes -r: ewf-tools 20140813 or later (Debian 12, Ubuntu 24.04), libewf-legacy 20140810 or later, or libewf later than 20200210 (such as 20231119). Nothing was written and nothing was sent to the source"
    ))
}

/// The ewfacquire settings the session's effective config asks for.
pub fn requested_settings(ctx: &EngineContext) -> EwfSettings {
    if let EngineSettings::Ewf(e) = &ctx.effective.settings {
        return e.clone();
    }
    let mut config = ctx.config().clone();
    config.format = crate::models::config::ImageFormat::E01;
    config.rescue_mode = false;
    match EffectiveConfig::build(&config, Some(&ctx.identity)).settings {
        EngineSettings::Ewf(e) => e,
        _ => unreachable!("an E01 configuration builds E01 settings"),
    }
}

/// The ewfacquire command line (`-u`: unattended; the session guarantees
/// that no output of this base name exists).
pub fn ewfacquire_spec(ctx: &EngineContext, settings: &EwfSettings, log: &Path) -> ProcessSpec {
    let case = ctx.case();
    let config = ctx.config();
    // The same sanitised values the .info records; empty optional fields are
    // omitted (ewfacquire -u then stores nothing, measured), never filled
    // with placeholders
    let mut spec = ProcessSpec::new("ewfacquire")
        .arg("-u")
        .arg("-C")
        .arg(case.effective_case().unwrap_or_default())
        .arg("-E")
        .arg(case.effective_evidence().unwrap_or_default())
        .arg("-e")
        .arg(case.effective_examiner().unwrap_or_default());
    if let Some(description) = case.effective_description() {
        spec = spec.arg("-D").arg(description);
    }
    if let Some(notes) = case.ewf_header_notes() {
        spec = spec.arg("-N").arg(notes);
    }
    spec = spec
        .arg("-f")
        .arg(&settings.ewf_format)
        .arg("-c")
        .arg(settings.compression.as_ewf_arg())
        .arg("-S")
        .arg(config.split_size.as_ewf_arg());
    // The default count is ewfacquire's own: no -r, which some releases crash
    // on (retries_option_crashes)
    if !settings.retries_default {
        spec = spec.arg("-r").arg(settings.retries.to_string());
    }
    spec = spec
        .arg("-g")
        .arg(settings.error_granularity_sectors.to_string())
        .arg("-m")
        .arg(&settings.media_type)
        .arg("-M")
        .arg(&settings.media_flags);
    if settings.wipe_on_error {
        spec = spec.arg("-w");
    }
    if let Some(extra) = ewf_digest_list(ctx.selection, false) {
        spec = spec.arg("-d").arg(extra);
    }
    spec.arg("-l")
        .arg(log)
        .arg("-t")
        .arg(ctx.output_path(""))
        .arg(&ctx.tool_source_path)
        .grace(EWFACQUIRE_GRACE)
}

// ---------------------------------------------------------------------------
// Files and the source
// ---------------------------------------------------------------------------

/// `<base>.E01`, `.E02`... `.E99`, `.EAA`... `.EZZ`, `.FAA`... `.ZZZ` (libewf
/// segment naming), `.s01`... (SMART), any case; `.001`... is accepted for
/// compatibility with 0.1 callers.
pub fn is_ewf_segment(base_name: &str, file_name: &str) -> bool {
    let Some(ext) = file_name
        .strip_prefix(base_name)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let b = ext.as_bytes();
    if b.len() != 3 {
        return false;
    }
    let digits = b[1].is_ascii_digit() && b[2].is_ascii_digit();
    let letters = b[1].is_ascii_alphabetic() && b[2].is_ascii_alphabetic();
    match b[0] {
        b'E' | b'e' | b'S' | b's' => digits || letters,
        // Beyond .EZZ libewf continues with .FAA ... .ZZZ (upper case)
        b'F'..=b'Z' => b[1].is_ascii_uppercase() && b[2].is_ascii_uppercase(),
        b'0'..=b'9' => digits && b[0].is_ascii_digit(),
        _ => false,
    }
}

/// libewf's extension of segment `number` (1-based) in the family whose
/// first segment has the extension `first` (`E01`, `e01`, `s01`, `L01`,
/// `Ex01`, `Lx01`; the case of `first` is kept), as
/// libewf_filename_set_extension names them: 1..99 two digits (`E01` ..
/// `E99`), from 100 on two letters (`EAA` .. `EZZ`), then the lead letter
/// counts up (`FAA` .. `ZZZ`). `None` past the last name libewf can form
/// or for an extension that is no first segment.
pub fn segment_extension(first: &str, number: u32) -> Option<String> {
    let b = first.as_bytes();
    let (lead, x) = match b {
        [lead, b'0', b'1'] if lead.is_ascii_alphabetic() => (*lead, None),
        [lead, x @ (b'x' | b'X'), b'0', b'1'] if lead.is_ascii_alphabetic() => (*lead, Some(*x)),
        _ => return None,
    };
    if number == 0 {
        return None;
    }
    let (first_letter, last_lead) = if lead.is_ascii_uppercase() {
        (b'A', b'Z')
    } else {
        (b'a', b'z')
    };
    let (lead, tail) = if number <= 99 {
        (
            lead,
            [b'0' + (number / 10) as u8, b'0' + (number % 10) as u8],
        )
    } else {
        let mut n = number - 100;
        let second = first_letter + (n % 26) as u8;
        n /= 26;
        let first_of_two = first_letter + (n % 26) as u8;
        n /= 26;
        let lead = u32::from(lead) + n;
        if lead > u32::from(last_lead) {
            return None;
        }
        (lead as u8, [first_of_two, second])
    };
    let mut out = vec![lead];
    out.extend(x);
    out.extend(tail);
    String::from_utf8(out).ok()
}

/// Segment files of `base` in `dir`, in libewf order (`.E01` < `.E99` <
/// `.EAA` < `.EZZ` < `.FAA`).
pub fn find_segments(dir: &Path, base: &str) -> Vec<PathBuf> {
    let mut segments: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| is_ewf_segment(base, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    segments.sort_by_key(|p| segment_order(p));
    segments
}

fn segment_order(path: &Path) -> (u8, u8, String) {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_uppercase())
        .unwrap_or_default();
    let b = ext.as_bytes();
    match b {
        [lead, d, _] if d.is_ascii_digit() => (0, *lead, ext.clone()),
        [lead, _, _] => (1, *lead, ext.clone()),
        _ => (2, 0, ext.clone()),
    }
}

fn read_proc_rchar(pid: u32) -> Option<u64> {
    let content = fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    content
        .lines()
        .find_map(|l| l.strip_prefix("rchar:"))
        .and_then(|v| v.trim().parse().ok())
}

fn total_size(files: &[PathBuf]) -> u64 {
    files
        .iter()
        .filter_map(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .sum()
}

/// Whether the source is still what was probed at the start: `Err(reason)`
/// when its node is gone or now refers to another device (or file). Only
/// stat(2) and sysfs reads; nothing is sent to the device.
pub fn source_presence(identity: &SourceIdentity) -> Result<(), String> {
    source_presence_in(identity, Path::new("/sys/dev/block"), &block_rdev)
}

/// stat(2) of a device node: `Some((major, minor))` for a block device.
fn block_rdev(p: &Path) -> std::io::Result<Option<(u32, u32)>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let m = fs::metadata(p)?;
    Ok(m.file_type().is_block_device().then(|| {
        (
            libc::major(m.rdev() as libc::dev_t) as u32,
            libc::minor(m.rdev() as libc::dev_t) as u32,
        )
    }))
}

/// Stat of a device node: `Ok(Some((major, minor)))` for a block device,
/// `Ok(None)` for anything else.
pub type RdevOf<'a> = dyn Fn(&Path) -> std::io::Result<Option<(u32, u32)>> + 'a;

/// [`source_presence`] with an injectable `/sys/dev/block` and node stat.
pub fn source_presence_in(
    identity: &SourceIdentity,
    sys_dev_block: &Path,
    rdev_of: &RdevOf<'_>,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(&identity.path);
    if identity.is_block_device() {
        let Some(pinned) = identity.maj_min.as_deref().and_then(parse_dev_num) else {
            return Ok(());
        };
        let mm = format!("{}:{}", pinned.0, pinned.1);
        let node = sys_dev_block.join(&mm);
        if !node.exists() {
            return Err(format!(
                "the device {mm} no longer exists ({} is gone)",
                node.display()
            ));
        }
        if let Some(seq) = identity.diskseq {
            if let Ok(now) = fs::read_to_string(node.join("diskseq")) {
                if now.trim().parse::<u64>().ok() != Some(seq) {
                    return Err(format!(
                        "the device {mm} is another disk now (diskseq {} instead of {seq})",
                        now.trim()
                    ));
                }
            }
        }
        match rdev_of(path) {
            Ok(Some(dev)) if dev == pinned => Ok(()),
            Ok(Some((a, b))) => Err(format!(
                "{} refers to the device {a}:{b} now instead of {mm}",
                identity.path
            )),
            Ok(None) => Err(format!("{} is no longer a block device", identity.path)),
            Err(e) => Err(format!("{} no longer exists ({e})", identity.path)),
        }
    } else if let Some(id) = identity.file_id.as_deref() {
        match fs::metadata(path) {
            Ok(m) if m.is_file() && format!("{}:{}", m.dev(), m.ino()) == id => Ok(()),
            Ok(_) => Err(format!("{} is another file now", identity.path)),
            Err(e) => Err(format!("{} no longer exists ({e})", identity.path)),
        }
    } else {
        Ok(())
    }
}

/// Size of the source now: a regular file's length, a block device's size
/// from `<sys_dev_block>/<major:minor>/size` (512-byte units). `None` when it
/// cannot be read.
pub fn source_size_in(identity: &SourceIdentity, sys_dev_block: &Path) -> Option<u64> {
    if identity.is_block_device() {
        let mm = identity.maj_min.as_deref()?;
        let sectors: u64 = fs::read_to_string(sys_dev_block.join(mm).join("size"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        sectors.checked_mul(512)
    } else {
        fs::metadata(&identity.path).ok().map(|m| m.len())
    }
}

/// Whether the source is still present with at least `expected` bytes
/// (stat(2) and sysfs only; nothing is sent to the device).
pub fn source_still_there(
    identity: &SourceIdentity,
    expected: u64,
    sys_dev_block: &Path,
    rdev_of: &RdevOf<'_>,
) -> Result<(), String> {
    source_presence_in(identity, sys_dev_block, rdev_of)?;
    match source_size_in(identity, sys_dev_block) {
        Some(now) if now < expected => Err(format!(
            "the source has {now} bytes now, {expected} bytes when the acquisition started"
        )),
        _ => Ok(()),
    }
}

/// Watches ewfacquire's progress (E-1): after `limit` without progress it
/// asks `probe` (at most once a second) whether the source is still there.
#[derive(Debug)]
pub struct StallWatch {
    limit: Duration,
    last_done: u64,
    since: Instant,
    checked: Option<Instant>,
}

impl StallWatch {
    pub fn new(limit: Duration, now: Instant) -> Self {
        Self {
            limit,
            last_done: 0,
            since: now,
            checked: None,
        }
    }

    /// `done`: the progress figure now. `Some(why)` when there was no
    /// progress for the limit and the probe says the source is gone or
    /// smaller.
    pub fn tick(
        &mut self,
        done: u64,
        now: Instant,
        probe: impl FnOnce() -> Result<(), String>,
    ) -> Option<String> {
        if done != self.last_done {
            self.last_done = done;
            self.since = now;
            return None;
        }
        if now.duration_since(self.since) < self.limit
            || self
                .checked
                .is_some_and(|c| now.duration_since(c) < Duration::from_secs(1))
        {
            return None;
        }
        self.checked = Some(now);
        probe().err()
    }
}

// ---------------------------------------------------------------------------
// Acquisition
// ---------------------------------------------------------------------------

/// How the ewfacquire run ended (from the process runner).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunEnd {
    pub exit_code: Option<i32>,
    /// Stopped by the examiner (abort or force)
    pub stopped: bool,
    pub force_killed: bool,
    /// "exit code 1", "aborted: SIGINT", ...
    pub status_text: String,
}

impl RunEnd {
    pub fn from_outcome(o: &ProcessOutcome) -> Self {
        Self {
            exit_code: o.exit_code,
            stopped: o.aborted || o.force_killed,
            force_killed: o.force_killed,
            status_text: o.record.status_text(),
        }
    }

    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.stopped
    }
}

/// Everything [`assemble`] decides from (all measured; assemble does no I/O).
#[derive(Debug, Clone)]
pub struct EwfFacts {
    /// Probed source size at the start
    pub expected_bytes: u64,
    /// Logical sector size of the source (fallback for the error table)
    pub sector_size: u32,
    pub requested: Option<EwfSettings>,
    pub run: RunEnd,
    pub acquire: EwfacquireReport,
    pub segments: Vec<PathBuf>,
    pub log_file: Option<PathBuf>,
    /// `ewfinfo -e` (Err: why it could not be read; None: not run)
    pub info_errors: Option<Result<RunBlock, String>>,
    /// `ewfinfo -m`
    pub info_media: Option<Result<EwfMediaInfo, String>>,
    /// [`source_still_there`] after ewfacquire ended: the source is present
    /// with at least the size it had at the start (Err: why not)
    pub source_presence: Result<(), String>,
    /// dfdisk stopped ewfacquire because it made no progress and the source
    /// was gone or smaller (E-1): why ("source lost at offset X ...")
    pub stalled: Option<String>,
}

fn table_from(runs: &[SectorRun], sector_size: u32, source: &str) -> ReadErrorTable {
    let mut t = ReadErrorTable::new(sector_size, source);
    for r in runs {
        t.push_sectors(r.first, r.count, RangeKind::Substituted);
    }
    t.normalise();
    t
}

fn describe_ranges(t: &ReadErrorTable) -> String {
    if t.ranges.is_empty() {
        return "none".into();
    }
    let shown: Vec<String> = t
        .ranges
        .iter()
        .take(5)
        .map(|r| format!("{} bytes at offset {}", r.length, r.offset))
        .collect();
    let more = t.ranges.len() - shown.len();
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

fn media_type_name(info: &str) -> String {
    match info {
        "fixed disk" => "fixed".into(),
        "removable disk" => "removable".into(),
        other => other.to_string(),
    }
}

fn block_problem(what: &str, b: &RunBlock) -> String {
    let understood = match b.total {
        Some(n) => format!(
            "{what} {} but only {} could be parsed",
            plural(n, "read error", "read errors"),
            plural(b.runs.len() as u64, "position", "positions")
        ),
        None => format!("{what} read-error information that could not be parsed"),
    };
    if b.unparsed.is_empty() {
        understood
    } else {
        format!("{understood} (not understood: {})", b.unparsed.join(" | "))
    }
}

/// Derive the engine output from what was measured (pure).
pub fn assemble(f: &EwfFacts) -> Result<EngineOutput, AcquisitionError> {
    let a = &f.acquire;
    let mut notes: Vec<String> = Vec::new();
    let mut stop_reason: Option<String> = None;

    let media = match &f.info_media {
        Some(Ok(m)) => Some(m.clone()),
        Some(Err(e)) => {
            notes.push(format!(
                "ewfinfo -m could not read the media information from the image: {e}"
            ));
            None
        }
        None => None,
    };
    let corrupted = media.as_ref().is_some_and(|m| m.corrupted);

    // The sector size ewfacquire counted in
    let image_bps = media.as_ref().and_then(|m| m.bytes_per_sector);
    let sector_size = a
        .bytes_per_sector
        .or(image_bps)
        .filter(|s| *s > 0)
        .unwrap_or(f.sector_size.max(512));
    if let (Some(x), Some(y)) = (a.bytes_per_sector, image_bps) {
        if x != y {
            notes.push(format!(
                "ewfacquire read {x} bytes per sector but the image records {y}; the error table counts in {x}-byte sectors"
            ));
        }
    }
    if sector_size != f.sector_size.max(512) {
        notes.push(format!(
            "ewfacquire counted in {sector_size}-byte sectors; the source reported {}-byte logical sectors",
            f.sector_size
        ));
    }

    // Read errors: ewfacquire's list and the image's list, united
    let printed = a.errors.clone().unwrap_or_default();
    let mut table = table_from(&printed.runs, sector_size, "ewfacquire output");
    // Fail closed: read errors whose positions are not known
    let mut unlocated: Option<&str> = None;
    if printed.incomplete() {
        notes.push(block_problem("ewfacquire reported", &printed));
        unlocated = Some("ewfacquire reported read errors");
    }
    match &f.info_errors {
        Some(Ok(stored)) => {
            let from_image = table_from(&stored.runs, sector_size, "ewfinfo -e");
            if stored.incomplete() {
                notes.push(block_problem("ewfinfo -e lists", stored));
            }
            if table.ranges != from_image.ranges {
                notes.push(format!(
                    "the read errors ewfacquire printed ({}) differ from those the image records (ewfinfo -e: {}); the report lists the union of both",
                    describe_ranges(&table),
                    describe_ranges(&from_image)
                ));
            }
            // ewfacquire stated how many errors it had and the image's
            // complete list has at least that many: the positions are known.
            // Without a count (output in an unknown form) it stays unresolved
            let count_only = printed
                .total
                .is_some_and(|n| n > 0 && stored.runs.len() as u64 >= n);
            if unlocated.is_some() && count_only && !stored.incomplete() {
                unlocated = None;
            }
            if stored.incomplete() {
                unlocated = Some("the image records read errors (ewfinfo -e)");
            }
            table.merge(&from_image);
        }
        Some(Err(e)) if !corrupted => {
            notes.push(format!(
                "ewfinfo -e could not read the read-error list from the image ({e}); the ranges come from ewfacquire's output only"
            ));
        }
        _ => {}
    }
    if let Some(who) = unlocated {
        stop_reason = Some(format!(
            "{who} whose positions could not be determined from ewfacquire's output or from the image; the read-error table may be incomplete"
        ));
    }

    // Size: what the image records, else what ewfacquire saw
    let image_size = media.as_ref().and_then(|m| m.media_size);
    let media_size = image_size.or(a.media_size);
    if let (Some(x), Some(y)) = (a.media_size, image_size) {
        if x != y {
            notes.push(format!(
                "ewfacquire reported a media size of {x} bytes, the image records {y} bytes"
            ));
        }
    }

    let mut out = EngineOutput {
        expected_bytes: f.expected_bytes,
        image_files: f.segments.clone(),
        auxiliary_files: f.log_file.iter().cloned().collect(),
        acquisition_hashes: a.hashes.clone(),
        ..Default::default()
    };

    // Digests: as ewfacquire printed them; a stored one only as a fallback
    if let Some(m) = &media {
        for (label, printed_v, stored_v) in [
            ("MD5", &mut out.acquisition_hashes.md5, &m.stored.md5),
            ("SHA-1", &mut out.acquisition_hashes.sha1, &m.stored.sha1),
        ] {
            match (printed_v.as_ref(), stored_v.as_ref()) {
                (Some(p), Some(s)) if !p.eq_ignore_ascii_case(s) => notes.push(format!(
                    "the {label} ewfacquire printed ({p}) differs from the {label} stored in the image ({s})"
                )),
                (None, Some(s)) if f.run.success() => {
                    notes.push(format!(
                        "ewfacquire's output did not show the {label}; the {label} stored in the image is recorded instead"
                    ));
                    *printed_v = Some(s.clone());
                }
                _ => {}
            }
        }
    }

    // Applied settings
    let mut applied = f.requested.clone();
    if let Some(s) = applied.as_mut() {
        if let Some(b) = a.segment_bytes_applied {
            if Some(b) != s.segment_bytes {
                notes.push(format!(
                    "ewfacquire did not accept the segment size {} and applied segments of {} ({b} bytes)",
                    s.segment_size,
                    format_iec(b)
                ));
                s.segment_bytes = Some(b);
                s.segment_size = format!("{} ({b} bytes, applied by ewfacquire)", format_iec(b));
            }
        }
        if let Some(r) = a.retries_applied {
            if r != s.retries {
                notes.push(format!(
                    "ewfacquire did not accept -r {} and applied {r} read retries",
                    s.retries
                ));
                s.retries = r;
            }
        }
        let granularity = media
            .as_ref()
            .and_then(|m| m.error_granularity)
            .or(a.granularity_applied);
        if let Some(g) = granularity {
            if g != s.error_granularity_sectors {
                notes.push(format!(
                    "ewfacquire did not accept an error granularity of {} (-g) and used {}",
                    plural(u64::from(s.error_granularity_sectors), "sector", "sectors"),
                    plural(u64::from(g), "sector", "sectors")
                ));
                s.error_granularity_sectors = g;
            }
        }
        if let Some(t) = media.as_ref().and_then(|m| m.media_type.as_deref()) {
            let t = media_type_name(t);
            if t != s.media_type {
                notes.push(format!(
                    "the image records the media type {t} (requested {})",
                    s.media_type
                ));
                s.media_type = t;
            }
        }
        if let Some(p) = media.as_ref().and_then(|m| m.is_physical) {
            let flags = if p { "physical" } else { "logical" };
            if flags != s.media_flags {
                notes.push(format!(
                    "the image records the media as {flags} (requested {})",
                    s.media_flags
                ));
                s.media_flags = flags.into();
            }
        }
    }

    let lower_bound = a.acquired_bytes.unwrap_or(0).min(f.expected_bytes);
    let loss = f.source_presence.as_ref().err();
    let detail = a
        .diagnostics
        .iter()
        .take(6)
        .cloned()
        .collect::<Vec<_>>()
        .join(" / ");

    if let Some(why) = &f.stalled {
        // dfdisk stopped ewfacquire: the source ended while it waited
        if f.segments.is_empty() {
            return Err(AcquisitionError::failed(format!(
                "{why}; ewfacquire had not written a segment file"
            )));
        }
        out.bytes_acquired = lower_bound;
        stop_reason = Some(why.clone());
        notes.push(format!(
            "dfdisk stopped ewfacquire ({}) because it made no progress and the source was gone or smaller than when the acquisition started; its segment files are kept but not finalized{} and cannot be verified; {}",
            f.run.status_text,
            if corrupted { " (ewfinfo: corrupted)" } else { "" },
            match a.acquired_bytes {
                Some(n) => format!("{n} bytes had been acquired at ewfacquire's last progress report"),
                None => "ewfacquire had not reported progress yet, so the number of bytes acquired is not known (0 is recorded)".into(),
            }
        ));
    } else if f.run.stopped {
        // The examiner (or a signal) stopped ewfacquire
        if f.segments.is_empty() {
            return Err(AcquisitionError::aborted(
                "the E01 acquisition was aborted before ewfacquire wrote a segment file",
            ));
        }
        out.aborted = true;
        out.bytes_acquired = lower_bound;
        notes.push(format!(
            "ewfacquire was stopped ({}); its segment files are kept but not finalized{} and cannot be verified; {}",
            f.run.status_text,
            if corrupted { " (ewfinfo: corrupted)" } else { "" },
            match a.acquired_bytes {
                Some(n) => format!("{n} bytes had been acquired at ewfacquire's last progress report"),
                None => "ewfacquire had not reported progress yet, so the number of bytes acquired is not known (0 is recorded)".into(),
            }
        ));
    } else if !f.run.success() || a.status == Some(ToolStatus::Failure) {
        if f.segments.is_empty() {
            return Err(AcquisitionError::failed(format!(
                "ewfacquire failed ({}) before writing a segment file{}",
                f.run.status_text,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            )));
        }
        out.bytes_acquired = lower_bound;
        let at_least = match a.acquired_bytes {
            Some(n) => format!("after acquiring at least {n} bytes (last progress report)"),
            None => "before reporting progress (the number of bytes acquired is not known; 0 is recorded)".into(),
        };
        stop_reason = Some(if let Some(why) = loss {
            format!(
                "source lost during the acquisition ({why}); ewfacquire stopped with FAILURE {at_least}"
            )
        } else if a
            .diagnostics
            .iter()
            .any(|d| d.contains("No space left on device"))
        {
            format!("destination full: ewfacquire could not write the image and stopped {at_least}")
        } else {
            format!(
                "ewfacquire failed ({}) {at_least}{}",
                f.run.status_text,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            )
        });
        notes.push(format!(
            "the segment files ewfacquire left are kept{}; an image that was not finalized cannot be verified (libewf's ewfrecover may be able to recover the part that was written)",
            if corrupted { " (ewfinfo: corrupted)" } else { "" }
        ));
    } else {
        // ewfacquire completed
        if a.status != Some(ToolStatus::Success) {
            notes.push(
                "ewfacquire exited with status 0 but did not print \"ewfacquire: SUCCESS\"".into(),
            );
        }
        match media_size {
            Some(size) => {
                out.bytes_acquired = size;
                if size < f.expected_bytes {
                    notes.push(format!(
                        "the image holds {size} bytes ({}); the source had {} bytes ({}) when the acquisition started",
                        format_iec(size),
                        f.expected_bytes,
                        format_iec(f.expected_bytes)
                    ));
                } else if size > f.expected_bytes {
                    notes.push(format!(
                        "the image holds {size} bytes, more than the {} bytes the source had when it was probed",
                        f.expected_bytes
                    ));
                }
            }
            None => {
                stop_reason.get_or_insert_with(|| {
                    "the size of the acquired media could not be determined (neither ewfacquire nor ewfinfo reported it)".into()
                });
            }
        }
        if corrupted {
            stop_reason.get_or_insert_with(|| {
                "ewfinfo reports the image as corrupted although ewfacquire completed".into()
            });
        }
        // Errors up to the end of the medium: a lost source, or a medium that
        // stopped answering while it stayed attached
        let end = media_size.unwrap_or(f.expected_bytes);
        let tail = table.ranges.iter().position(|r| end > 0 && r.end() >= end);
        if let Some(i) = tail {
            let start = table.ranges[i].offset;
            if let Some(why) = loss {
                table.ranges[i].kind = RangeKind::Unread;
                table.normalise();
                out.bytes_acquired = start;
                stop_reason = Some(format!(
                    "source lost at offset {start} ({}): {why}",
                    format_iec(start)
                ));
                notes.push(format!(
                    "ewfacquire stored zeros for the {} bytes from offset {start} to the end after the source was lost or became smaller; they are not source data and are listed as not acquired",
                    end.saturating_sub(start)
                ));
            } else {
                notes.push(format!(
                    "the read errors extend from offset {start} to the end of the medium; the source was still present afterwards, with at least the {} bytes it had at the start",
                    f.expected_bytes
                ));
            }
        } else if let Some(why) = loss {
            notes.push(format!(
                "after ewfacquire finished, the source was gone or smaller than at the start: {why}"
            ));
        }
        if !detail.is_empty() {
            notes.push(format!("ewfacquire printed on standard error: {detail}"));
        }
    }

    if !table.is_empty() {
        let g = applied
            .as_ref()
            .map(|s| s.error_granularity_sectors)
            .unwrap_or(1);
        notes.push(format!(
            "ewfacquire replaced {} ({}) with zeros; the listed ranges are the sectors it zero-filled and can include readable sectors next to unreadable ones (error granularity {}, and the rest of a failed read request)",
            plural(table.sectors(), "sector", "sectors"),
            format_iec(table.substituted_bytes() + table.unread_bytes()),
            plural(u64::from(g), "sector", "sectors")
        ));
    }

    out.read_errors = table;
    out.stop_reason = stop_reason;
    out.settings = applied.map(EngineSettings::Ewf);
    out.notes = notes;
    Ok(out)
}

/// Run one ewfinfo query (`-e` or `-m`) on the first segment.
async fn ewfinfo(
    flag: &str,
    first: &Path,
    control: &StopControl,
    ctx: &EngineContext,
) -> Result<String, String> {
    let spec = ProcessSpec::new("ewfinfo")
        .arg(flag)
        .arg(first)
        .timeout(EWFINFO_TIMEOUT)
        .grace(READER_GRACE);
    let out = process::run_collect(&spec, control, Some(&ctx.provenance))
        .await
        .map_err(|e| e.to_string())?;
    if let Some(v) = process::first_line(&out.stdout) {
        if v.starts_with("ewfinfo ") && !v.contains(':') {
            ctx.provenance.set_tool_version("ewfinfo", &v);
        }
    }
    if out.outcome.success() {
        Ok(out.stdout.join("\n"))
    } else {
        let detail = out.stderr.first().cloned().unwrap_or_default();
        Err(format!("{} {detail}", out.outcome.record.status_text())
            .trim()
            .to_string())
    }
}

/// Live progress from ewfacquire's read counter and its progress lines.
struct Gauge {
    t0: Instant,
    total: u64,
    last: (u64, Instant),
    last_size_check: Instant,
}

impl Gauge {
    fn new(total: u64) -> Self {
        let now = Instant::now();
        Self {
            t0: now,
            total,
            last: (0, now),
            last_size_check: now,
        }
    }

    fn update(&mut self, ctx: &EngineContext, done: u64) {
        let total = self.total.max(1);
        let done = done.min(total);
        let now = Instant::now();
        let dt = now.duration_since(self.last.1).as_secs_f64();
        let speed = (dt >= 0.5).then(|| {
            let s = done.saturating_sub(self.last.0) as f64 / dt;
            self.last = (done, now);
            s
        });
        let written = (now.duration_since(self.last_size_check).as_secs() >= 1).then(|| {
            self.last_size_check = now;
            total_size(&find_segments(&ctx.output_dir, &ctx.base_name))
        });
        let elapsed = self.t0.elapsed().as_secs_f64();
        let full = self.total;
        ctx.progress.update(|t| {
            t.bytes_processed = done;
            t.total_bytes = full;
            t.percentage = done as f64 * 100.0 / total as f64;
            if let Some(s) = speed {
                t.speed_bps = s;
            }
            t.elapsed_secs = elapsed as u64;
            if elapsed > 0.0 {
                t.avg_speed_bps = done as f64 / elapsed;
            }
            t.eta_secs = (t.avg_speed_bps > 0.0 && total > done)
                .then(|| ((total - done) as f64 / t.avg_speed_bps) as u64);
            if let Some(w) = written.filter(|w| *w > 0 && done > 0) {
                t.compression_ratio = Some(done as f64 / w as f64);
            }
        });
    }
}

/// Acquire the source into `<base>.E01` (+ segments) with ewfacquire (step 8).
pub async fn acquire(ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
    let requested = requested_settings(ctx);
    if ctx.config().error_retries > MAX_RETRIES
        || requested.retries > MAX_RETRIES
        || requested.error_granularity_sectors == 0
    {
        return Err(AcquisitionError::usage(format!(
            "ewfacquire takes 0 to {MAX_RETRIES} read retries and an error granularity of at least 1 sector (got {} retries, granularity {})",
            ctx.config().error_retries.max(requested.retries),
            requested.error_granularity_sectors
        )));
    }
    check_source_size(ctx.expected_bytes()).map_err(AcquisitionError::usage)?;
    let log = ctx.output_path(LOG_SUFFIX);
    let spec = ewfacquire_spec(ctx, &requested, &log);
    let expected = ctx.expected_bytes();
    ctx.progress.update(|t| {
        t.total_bytes = expected;
        t.current_segment = format!("{}.E01", ctx.base_name);
        t.push_log(format!(
            "Starting ewfacquire on {} (error granularity {}, {} read retries)",
            ctx.tool_source_path,
            plural(
                u64::from(requested.error_granularity_sectors),
                "sector",
                "sectors"
            ),
            requested.retries
        ));
    });

    let mut parser = EwfacquireParser::new();
    let mut gauge = Gauge::new(expected);
    // ewfacquire stops on the examiner's abort, or when the source ended
    // while it waited (E-1); the force flag kills at once
    let stop_flag = Arc::new(AtomicBool::new(ctx.is_aborted()));
    let control = StopControl::abort(stop_flag.clone()).with_force(ctx.force.clone());
    let stall_limit = Duration::from_secs(SOURCE_STALL_SECS.load(Ordering::Relaxed));
    let mut watch = StallWatch::new(stall_limit, Instant::now());
    let mut stalled: Option<String> = None;
    let outcome = process::run(
        &spec,
        &control,
        Some(&ctx.provenance),
        |ev| match ev {
            ProcessEvent::Line { stream, text, .. } => {
                let before = parser.report().acquired_bytes;
                parser.feed(stream, text);
                let t = text.trim();
                if !t.is_empty() {
                    ctx.progress.log(t);
                }
                if let Some(done) = parser
                    .report()
                    .acquired_bytes
                    .filter(|d| Some(*d) != before)
                {
                    gauge.update(ctx, done);
                }
            }
            ProcessEvent::Tick { pid, .. } => {
                if ctx.is_aborted() {
                    stop_flag.store(true, Ordering::SeqCst);
                }
                let read = pid.and_then(read_proc_rchar).unwrap_or(0);
                let done = read.max(parser.report().acquired_bytes.unwrap_or(0));
                if done > 0 {
                    gauge.update(ctx, done);
                }
                if stalled.is_none() && !stop_flag.load(Ordering::SeqCst) {
                    let probe = || {
                        source_still_there(
                            &ctx.identity,
                            expected,
                            Path::new("/sys/dev/block"),
                            &block_rdev,
                        )
                    };
                    if let Some(why) = watch.tick(done, Instant::now(), probe) {
                        let at = parser.report().acquired_bytes.unwrap_or(0);
                        let reason = format!(
                            "source lost at offset {at} ({}): {why}; ewfacquire made no progress for {} s and was stopped by dfdisk",
                            format_iec(at),
                            stall_limit.as_secs()
                        );
                        ctx.progress.warn(reason.clone());
                        stalled = Some(reason);
                        stop_flag.store(true, Ordering::SeqCst);
                    }
                }
            }
        },
    )
    .await
    .map_err(|e| {
        AcquisitionError::failed(format!("cannot run ewfacquire (is libewf installed?): {e}"))
    })?;
    let report = parser.finish();
    if let Some(v) = &report.version {
        ctx.provenance.set_tool_version("ewfacquire", v);
    }

    let segments = find_segments(&ctx.output_dir, &ctx.base_name);
    // Read back what the image records. Not after a forced stop (the examiner
    // wants it to end now); after an abort only the force flag stops ewfinfo
    let control = StopControl::none().with_force(ctx.force.clone());
    let (info_errors, info_media) = match segments.first() {
        Some(first) if !ctx.is_forced() => {
            let e = ewfinfo("-e", first, &control, ctx)
                .await
                .map(|s| parse_ewfinfo_errors(&s));
            let m = ewfinfo("-m", first, &control, ctx)
                .await
                .map(|s| parse_ewfinfo_media(&s));
            (Some(e), Some(m))
        }
        _ => (None, None),
    };
    // dfdisk's own stop is no abort, unless the examiner stopped it too
    let stalled = stalled.filter(|_| !ctx.is_aborted() && !ctx.is_forced());
    let mut run = RunEnd::from_outcome(&outcome);
    if stalled.is_some() {
        run.stopped = false;
    }
    let facts = EwfFacts {
        expected_bytes: expected,
        sector_size: ctx.sector_size(),
        requested: Some(requested),
        run,
        acquire: report,
        segments,
        log_file: log.exists().then_some(log),
        info_errors,
        info_media,
        // E-NEW-2: presence AND size, as the stall watch checks it
        source_presence: source_still_there(
            &ctx.identity,
            expected,
            Path::new("/sys/dev/block"),
            &block_rdev,
        ),
        stalled,
    };
    let out = assemble(&facts)?;
    if !out.read_errors.is_empty() {
        let sectors = out.read_errors.sectors();
        ctx.progress.update(|t| t.bad_sectors = sectors);
        ctx.progress.warn(format!(
            "ewfacquire replaced {} with zeros ({})",
            plural(sectors, "sector", "sectors"),
            out.read_errors.source
        ));
    }
    if let Some(reason) = &out.stop_reason {
        ctx.progress.warn(reason.clone());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// The verdict on an ewfverify run (pure): recomputed digests compared with
/// the acquisition digests. Any difference is a mismatch (even when ewfverify
/// also failed); a requested digest that was not recomputed, sector checksum
/// errors or an ewfverify failure fail the verification.
pub fn evaluate_ewfverify(
    selection: HashSelection,
    acquisition: &HashResults,
    report: &EwfverifyReport,
    tool_ok: bool,
    status_text: &str,
    method: &str,
) -> VerificationResult {
    let validation = report.validation_summary();
    match compare_digests(selection, acquisition, &report.calculated, method) {
        VerificationResult::Mismatched { method, details } => VerificationResult::Mismatched {
            method,
            details: match &validation {
                Some(v) => format!("{details}; {v}"),
                None => details,
            },
        },
        VerificationResult::Failed { reason } => VerificationResult::Failed {
            reason: if tool_ok {
                reason
            } else {
                format!("{reason} (ewfverify: {status_text})")
            },
        },
        matched => {
            if let Some(v) = validation {
                VerificationResult::Failed { reason: v }
            } else if !tool_ok {
                VerificationResult::Failed {
                    reason: format!(
                        "ewfverify reported an error in the image ({status_text}){}",
                        report
                            .diagnostics
                            .first()
                            .map(|d| format!(": {d}"))
                            .unwrap_or_default()
                    ),
                }
            } else {
                matched
            }
        }
    }
}

/// Re-read the written image with ewfverify (step 11, after the session's
/// flush and cache eviction) and compare its recomputed digests with the
/// acquisition's. Returns the verdict and the recomputed image digests.
pub async fn verify(ctx: &EngineContext, out: &EngineOutput) -> (VerificationResult, HashResults) {
    let Some(first) = out.image_files.first() else {
        return (
            VerificationResult::Failed {
                reason: "ewfacquire produced no segment file".into(),
            },
            HashResults::default(),
        );
    };
    let digests = ewf_digest_list(ctx.selection, true).unwrap_or_else(|| "md5".into());
    let spec = ProcessSpec::new("ewfverify")
        .arg("-d")
        .arg(&digests)
        .arg(first)
        .grace(READER_GRACE);
    let total = total_size(&out.image_files);
    let t0 = Instant::now();
    let mut parser = EwfverifyParser::new();
    let outcome = process::run(
        &spec,
        &ctx.stop_control(),
        Some(&ctx.provenance),
        |ev| match ev {
            ProcessEvent::Line { stream, text, .. } => {
                parser.feed(stream, text);
                if stream == StreamTag::Stderr && !text.trim().is_empty() {
                    ctx.progress.log(format!("ewfverify: {}", text.trim()));
                }
            }
            ProcessEvent::Tick { pid, .. } => {
                if let Some(read) = pid.and_then(read_proc_rchar) {
                    let done = read.min(total);
                    let secs = t0.elapsed().as_secs_f64();
                    let speed = if secs > 0.0 { done as f64 / secs } else { 0.0 };
                    ctx.progress.phase_progress(done, total, speed);
                }
            }
        },
    )
    .await;
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            return (
                VerificationResult::Failed {
                    reason: format!("cannot run ewfverify (is libewf installed?): {e}"),
                },
                HashResults::default(),
            )
        }
    };
    let report = parser.finish();
    if let Some(v) = &report.version {
        ctx.provenance.set_tool_version("ewfverify", v);
    }
    if outcome.aborted || outcome.force_killed {
        return (
            VerificationResult::NotPossible {
                reason: "the verification was aborted".into(),
            },
            report.calculated,
        );
    }
    ctx.progress.phase_progress(total, total, 0.0);
    let tool_ok = outcome.success() && report.status == Some(ToolStatus::Success);
    let method = format!("ewfverify -d {digests} (image re-read)");
    let result = evaluate_ewfverify(
        ctx.selection,
        &out.acquisition_hashes,
        &report,
        tool_ok,
        &outcome.record.status_text(),
        &method,
    );
    (result, report.calculated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::session::AcquisitionRequest;
    use crate::engines::ErrorKind;
    use crate::models::case::CaseMetadata;
    use crate::models::config::CompressionLevel;
    use crate::models::device::BlockDevice;
    use crate::models::identity::SourceKind;
    use crate::models::outcome::{classify, AcquisitionFacts, Outcome};

    /// Real output of libewf 20231119 (top level) and 20140816 (`legacy/`,
    /// the Debian/Ubuntu ewf-tools line); see tests/fixtures/ewf/README.txt.
    macro_rules! fixtures {
        ($($path:literal),* $(,)?) => {
            &[$(($path, include_str!(concat!("../../tests/fixtures/ewf/", $path)))),*]
        };
    }
    const FIXTURES: &[(&str, &str)] = fixtures![
        "aborted/ewfacquire.stdout",
        "aborted/ewfinfo-e.stdout",
        "aborted/ewfinfo-m.stdout",
        "aborted/ewfverify.stderr",
        "aborted/ewfverify.stdout",
        "clean/ewfacquire.stderr",
        "clean/ewfacquire.stdout",
        "clean/ewfinfo-e.stdout",
        "clean/ewfinfo-m.stdout",
        "clean/ewfverify-sha256.stdout",
        "clean/ewfverify.stdout",
        "dying_to_end/ewfacquire.stderr",
        "dying_to_end/ewfacquire.stdout",
        "dying_to_end/ewfinfo-e.stdout",
        "dying_to_end/ewfinfo-m.stdout",
        "dying_to_end/ewfverify.stdout",
        "granularity_fallback/ewfacquire.stderr",
        "granularity_fallback/ewfacquire.stdout",
        "granularity_fallback/ewfinfo-e.stdout",
        "granularity_fallback/ewfinfo-m.stdout",
        "granularity_fallback/ewfverify.stdout",
        "legacy/aborted/ewfacquire.stdout",
        "legacy/aborted/ewfinfo-e.stdout",
        "legacy/aborted/ewfinfo-m.stdout",
        "legacy/aborted/ewfverify.stderr",
        "legacy/aborted/ewfverify.stdout",
        "legacy/clean/ewfacquire.stderr",
        "legacy/clean/ewfacquire.stdout",
        "legacy/clean/ewfinfo-e.stdout",
        "legacy/clean/ewfinfo-m.stdout",
        "legacy/clean/ewfverify-sha1-sha256.stdout",
        "legacy/clean/ewfverify-sha256.stdout",
        "legacy/clean/ewfverify.stdout",
        "legacy/dying_to_end/ewfacquire.stderr",
        "legacy/dying_to_end/ewfacquire.stdout",
        "legacy/dying_to_end/ewfinfo-e.stdout",
        "legacy/dying_to_end/ewfinfo-m.stdout",
        "legacy/dying_to_end/ewfverify.stdout",
        "legacy/granularity_fallback/ewfacquire.stderr",
        "legacy/granularity_fallback/ewfacquire.stdout",
        "legacy/granularity_fallback/ewfinfo-e.stdout",
        "legacy/granularity_fallback/ewfinfo-m.stdout",
        "legacy/granularity_fallback/ewfverify.stdout",
        "legacy/one_bad_sector/ewfacquire.stderr",
        "legacy/one_bad_sector/ewfacquire.stdout",
        "legacy/one_bad_sector/ewfinfo-e.stdout",
        "legacy/one_bad_sector/ewfinfo-m.stdout",
        "legacy/one_bad_sector/ewfverify.stdout",
        "legacy/retries256/ewfacquire.stderr",
        "legacy/retries256/ewfacquire.stdout",
        "legacy/retries256/ewfinfo-e.stdout",
        "legacy/retries256/ewfinfo-m.stdout",
        "legacy/retries256/ewfverify.stdout",
        "legacy/sector4096/ewfacquire.stderr",
        "legacy/sector4096/ewfacquire.stdout",
        "legacy/sector4096/ewfinfo-e.stdout",
        "legacy/sector4096/ewfinfo-m.stdout",
        "legacy/sector4096/ewfverify.stdout",
        "legacy/slow/ewfacquire.stdout",
        "legacy/source_vanished/ewfacquire.stderr",
        "legacy/source_vanished/ewfacquire.stdout",
        "legacy/source_vanished/ewfinfo-e.stdout",
        "legacy/source_vanished/ewfinfo-m.stdout",
        "legacy/source_vanished/ewfverify.stderr",
        "legacy/source_vanished/ewfverify.stdout",
        "legacy/tampered/ewfverify-noMD5.stderr",
        "legacy/tampered/ewfverify-noMD5.stdout",
        "legacy/tampered/ewfverify.stderr",
        "legacy/tampered/ewfverify.stdout",
        "legacy/three_ranges_g8/ewfacquire.stderr",
        "legacy/three_ranges_g8/ewfacquire.stdout",
        "legacy/three_ranges_g8/ewfinfo-e.stdout",
        "legacy/three_ranges_g8/ewfinfo-m.stdout",
        "legacy/three_ranges_g8/ewfverify.stdout",
        "one_bad_sector/ewfacquire.stderr",
        "one_bad_sector/ewfacquire.stdout",
        "one_bad_sector/ewfinfo-e.stdout",
        "one_bad_sector/ewfinfo-m.stdout",
        "one_bad_sector/ewfverify.stdout",
        "sector4096/ewfacquire.stderr",
        "sector4096/ewfacquire.stdout",
        "sector4096/ewfinfo-e.stdout",
        "sector4096/ewfinfo-m.stdout",
        "sector4096/ewfverify.stdout",
        "slow/ewfacquire.stdout",
        "slow/ewfverify.stdout",
        "source_vanished/ewfacquire.stderr",
        "source_vanished/ewfacquire.stdout",
        "source_vanished/ewfinfo-e.stdout",
        "source_vanished/ewfinfo-m.stdout",
        "source_vanished/ewfverify.stderr",
        "source_vanished/ewfverify.stdout",
        "tampered/ewfverify-sha256.stdout",
        "tampered/ewfverify.stdout",
        "three_ranges_g8/ewfacquire.stderr",
        "three_ranges_g8/ewfacquire.stdout",
        "three_ranges_g8/ewfinfo-e.stdout",
        "three_ranges_g8/ewfinfo-m.stdout",
        "three_ranges_g8/ewfverify.stdout",
    ];

    /// Fixture roots: the current libewf and the legacy line.
    const ROOTS: [&str; 2] = ["", "legacy/"];

    fn version_of(root: &str) -> &'static str {
        if root.is_empty() {
            "20231119"
        } else {
            "20140816"
        }
    }

    fn fx(root: &str, dir: &str, file: &str) -> &'static str {
        let path = format!("{root}{dir}/{file}");
        FIXTURES
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, t)| *t)
            .unwrap_or_else(|| panic!("no fixture {path}"))
    }

    /// A stream that was empty (not saved) is "".
    fn fx_opt(root: &str, dir: &str, file: &str) -> &'static str {
        let path = format!("{root}{dir}/{file}");
        FIXTURES
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, t)| *t)
            .unwrap_or("")
    }

    const MIB: u64 = 1024 * 1024;
    const SIZE: u64 = 4 * MIB;

    fn acquire_report(root: &str, dir: &str) -> EwfacquireReport {
        parse_ewfacquire(
            fx(root, dir, "ewfacquire.stdout"),
            fx_opt(root, dir, "ewfacquire.stderr"),
        )
    }

    fn requested(granularity: u32, retries: u32) -> EwfSettings {
        EwfSettings {
            ewf_format: "encase6".into(),
            compression: CompressionLevel::Fast,
            segment_size: "2.0 GiB".into(),
            segment_bytes: Some(2048 * MIB),
            retries,
            retries_default: retries == EWFACQUIRE_DEFAULT_RETRIES,
            wipe_on_error: true,
            error_granularity_sectors: granularity,
            media_type: "fixed".into(),
            media_flags: "physical".into(),
        }
    }

    fn facts(
        root: &str,
        dir: &str,
        info_e: Option<&str>,
        info_m: Option<&str>,
        exit_code: i32,
    ) -> EwfFacts {
        EwfFacts {
            expected_bytes: SIZE,
            sector_size: 512,
            requested: Some(requested(1, 2)),
            run: RunEnd {
                exit_code: Some(exit_code),
                stopped: false,
                force_killed: false,
                status_text: format!("exit {exit_code}"),
            },
            acquire: acquire_report(root, dir),
            segments: vec![PathBuf::from("/o/b.E01")],
            log_file: Some(PathBuf::from("/o/b.ewfacquire.log")),
            info_errors: info_e.map(|t| Ok(parse_ewfinfo_errors(t))),
            info_media: info_m.map(|t| Ok(parse_ewfinfo_media(t))),
            source_presence: Ok(()),
            stalled: None,
        }
    }

    /// The verdict the session would derive (image verification matched).
    fn verdict(out: &EngineOutput) -> Outcome {
        classify(&AcquisitionFacts {
            expected_bytes: out.expected_bytes,
            bytes_acquired: out.bytes_acquired,
            read_errors: out.read_errors.clone(),
            stop_reason: out.stop_reason.clone(),
            aborted: out.aborted,
            verification: VerificationResult::Matched {
                method: "ewfverify".into(),
            },
            identity_changed: false,
        })
    }

    fn ranges(out: &EngineOutput) -> Vec<(u64, u64, RangeKind)> {
        out.read_errors
            .ranges
            .iter()
            .map(|r| (r.offset, r.length, r.kind))
            .collect()
    }

    // -- parsers against real output ---------------------------------------

    #[test]
    fn ewfacquire_read_error_block_is_parsed_from_stdout() {
        for root in ROOTS {
            let r = acquire_report(root, "one_bad_sector");
            assert_eq!(r.version, Some(format!("ewfacquire {}", version_of(root))));
            assert_eq!(r.media_size, Some(SIZE));
            assert_eq!(r.bytes_per_sector, Some(512));
            assert_eq!(r.status, Some(ToolStatus::Success));
            assert_eq!(r.retries_applied, Some(2));
            assert_eq!(r.granularity_applied, None);
            let errors = r.errors.unwrap();
            assert_eq!(errors.total, Some(1));
            // "at sector(s): 2048 - 2049 number: 1": the end is exclusive here
            assert_eq!(
                errors.runs,
                vec![SectorRun {
                    first: 2048,
                    count: 1
                }]
            );
            assert!(!errors.incomplete());
            assert_eq!(
                r.hashes.md5.as_deref(),
                Some("610a9d68f92851d74b85f33bde1fe3b9")
            );
            assert_eq!(
                r.hashes.sha256.as_deref(),
                Some("c60332c5c91251bc6a9f57c7b3fa6acbc555299e9cf702963ac3e3de70206f44")
            );
            assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);

            let r = acquire_report(root, "three_ranges_g8");
            let errors = r.errors.unwrap();
            assert_eq!(errors.total, Some(3));
            assert_eq!(
                errors.runs,
                vec![
                    SectorRun {
                        first: 2048,
                        count: 8
                    },
                    SectorRun {
                        first: 4096,
                        count: 8
                    },
                    SectorRun {
                        first: 6400,
                        count: 144
                    }
                ]
            );
            assert_eq!(r.retries_applied, Some(1));
            assert!(r.hashes.sha256.is_none());
        }
    }

    #[test]
    fn ewfacquire_statuses_progress_and_notices() {
        for root in ROOTS {
            let clean = acquire_report(root, "clean");
            assert!(clean.errors.is_none());
            assert_eq!(clean.status, Some(ToolStatus::Success));
            assert_eq!(
                clean.hashes.sha1.as_deref(),
                Some("1dbbb00f9daaaab78905d7f61ef1f1865f601117")
            );

            let gone = acquire_report(root, "source_vanished");
            assert_eq!(gone.status, Some(ToolStatus::Failure));
            assert!(gone.hashes.is_empty());
            assert!(gone
                .diagnostics
                .iter()
                .any(|d| d.contains("unable to read from device file")));

            let aborted = acquire_report(root, "aborted");
            assert_eq!(aborted.status, Some(ToolStatus::Aborted));
            assert_eq!(aborted.acquired_bytes, None);

            let slow = acquire_report(root, "slow");
            // "acquired 3.8 MiB (3964928 bytes) of total 4.0 MiB (4194304
            // bytes)"; the legacy line ends with a period
            let last = if root.is_empty() {
                3_964_928
            } else {
                2_097_152
            };
            assert_eq!(slow.acquired_bytes, Some(last));
            assert_eq!(slow.media_size, Some(SIZE));

            let fallback = acquire_report(root, "granularity_fallback");
            assert_eq!(fallback.granularity_applied, Some(64));

            let big = acquire_report(root, "sector4096");
            assert_eq!(big.bytes_per_sector, Some(4096));
            assert_eq!(
                big.errors.unwrap().runs,
                vec![SectorRun {
                    first: 256,
                    count: 1
                }]
            );
        }
    }

    #[test]
    fn ewfinfo_error_list_and_media_information() {
        for root in ROOTS {
            // "at sector(s): 2048 - 2048 (number: 1)": the end is inclusive here
            let e = parse_ewfinfo_errors(fx(root, "one_bad_sector", "ewfinfo-e.stdout"));
            assert_eq!(e.total, Some(1));
            assert_eq!(
                e.runs,
                vec![SectorRun {
                    first: 2048,
                    count: 1
                }]
            );
            let e = parse_ewfinfo_errors(fx(root, "three_ranges_g8", "ewfinfo-e.stdout"));
            assert_eq!(e.runs.len(), 3);
            assert_eq!(e.runs[2].count, 144);
            assert_eq!(
                parse_ewfinfo_errors(fx(root, "clean", "ewfinfo-e.stdout")),
                RunBlock::default()
            );

            let m = parse_ewfinfo_media(fx(root, "one_bad_sector", "ewfinfo-m.stdout"));
            assert_eq!(m.error_granularity, Some(1));
            assert_eq!(m.sectors_per_chunk, Some(64));
            assert_eq!(m.media_type.as_deref(), Some("fixed disk"));
            assert_eq!(m.is_physical, Some(true));
            assert_eq!(m.bytes_per_sector, Some(512));
            assert_eq!(m.number_of_sectors, Some(8192));
            assert_eq!(m.media_size, Some(SIZE));
            assert!(!m.corrupted);
            assert_eq!(
                m.stored.md5.as_deref(),
                Some("610a9d68f92851d74b85f33bde1fe3b9")
            );
            assert_eq!(
                m.stored.sha1.as_deref(),
                Some("9749d3e2959c32a6838bb8f3699a358ca4bd1efd")
            );
            assert_eq!(m.stored.sha256, None);

            let removable = parse_ewfinfo_media(fx(root, "clean", "ewfinfo-m.stdout"));
            assert_eq!(removable.media_type.as_deref(), Some("removable disk"));
            assert_eq!(removable.is_physical, Some(false));
            let interrupted = parse_ewfinfo_media(fx(root, "aborted", "ewfinfo-m.stdout"));
            assert!(interrupted.corrupted);
            let fallback =
                parse_ewfinfo_media(fx(root, "granularity_fallback", "ewfinfo-m.stdout"));
            assert_eq!(fallback.error_granularity, Some(64));
        }
    }

    #[test]
    fn ewfverify_counts_only_calculated_digests() {
        for root in ROOTS {
            let v = parse_ewfverify(fx(root, "clean", "ewfverify.stdout"), "");
            assert_eq!(v.status, Some(ToolStatus::Success));
            assert_eq!(v.bytes_read, Some(SIZE));
            assert_eq!(
                v.calculated.md5.as_deref(),
                Some("c0ed3b46644cbdf9322e6028c84f82fc")
            );
            assert_eq!(
                v.calculated.sha256.as_deref(),
                Some("a588bfb14c390d5c3a67c2004e68c2175ba8bfae9f5f5a6c953ae9d65c3464cf")
            );
            assert_eq!(v.stored.md5, v.calculated.md5);
            assert_eq!(v.stored.sha256, None, "N/A is not a digest");

            // -d sha256 only: values under "Additional hash values" are stored
            // values, never recalculations. 20231119 then computes no MD5;
            // 20140816 always computes MD5 ("additional types besides md5")
            let v = parse_ewfverify(fx(root, "clean", "ewfverify-sha256.stdout"), "");
            if root.is_empty() {
                assert_eq!(v.calculated.md5, None);
            } else {
                assert_eq!(v.calculated.md5, v.stored.md5);
            }
            assert_eq!(v.calculated.sha1, None);
            assert_eq!(
                v.stored.sha1.as_deref(),
                Some("1dbbb00f9daaaab78905d7f61ef1f1865f601117")
            );

            let t = parse_ewfverify(fx(root, "tampered", "ewfverify.stdout"), "");
            assert_eq!(t.status, Some(ToolStatus::Failure));
            let block = t.validation_errors.clone().unwrap();
            assert_eq!(block.total, Some(1));
            assert_eq!(
                block.runs,
                vec![SectorRun {
                    first: 3840,
                    count: 64
                }]
            );
            assert_ne!(t.calculated.md5, t.stored.md5);
            assert!(t.validation_summary().unwrap().contains("64 sectors"));

            let broken = parse_ewfverify(
                fx(root, "aborted", "ewfverify.stdout"),
                fx(root, "aborted", "ewfverify.stderr"),
            );
            assert_eq!(broken.status, Some(ToolStatus::Failure));
            assert!(!broken.diagnostics.is_empty());
            if root.is_empty() {
                // 20231119 cannot read the unfinalized image at all
                assert!(broken.calculated.is_empty());
            } else {
                // 20140816 reads it and reports every chunk as invalid
                assert!(broken
                    .validation_summary()
                    .unwrap()
                    .contains("8192 sectors"));
                assert_eq!(broken.stored.md5, None);
            }
        }
    }

    #[test]
    fn hash_line_parsing() {
        assert_eq!(
            parse_calculated_hash(
                "MD5 hash calculated over data:\t\t3ece4002f6ecc0968e80e6a7e154637c"
            ),
            Some(("md5", "3ece4002f6ecc0968e80e6a7e154637c".into()))
        );
        assert_eq!(
            parse_calculated_hash("SHA256 hash stored in file:\t\tN/A"),
            None
        );
        assert_eq!(
            parse_stored_hash("SHA256 hash stored in file:\t\tN/A"),
            None
        );
        assert_eq!(
            parse_calculated_hash("MD5 hash calculated over data: nothex"),
            None
        );
        assert_eq!(
            parse_stored_hash(
                "SHA1 hash stored in file:\t\t1DBBB00F9DAAAAB78905D7F61EF1F1865F601117"
            ),
            Some(("sha1", "1dbbb00f9daaaab78905d7f61ef1f1865f601117".into()))
        );
        assert_eq!(
            parse_sector_run("at sector(s): 10 - 9 number: 0 (offset: 0x0 of size: 0)"),
            None
        );
    }

    // -- assembling the engine output ---------------------------------------

    #[test]
    fn one_bad_sector_is_an_exact_substituted_range() {
        for root in ROOTS {
            let f = facts(
                root,
                "one_bad_sector",
                Some(fx(root, "one_bad_sector", "ewfinfo-e.stdout")),
                Some(fx(root, "one_bad_sector", "ewfinfo-m.stdout")),
                0,
            );
            let out = assemble(&f).unwrap();
            assert_eq!(ranges(&out), vec![(MIB, 512, RangeKind::Substituted)]);
            assert_eq!(out.read_errors.sector_size, 512);
            assert_eq!(out.read_errors.source, "ewfacquire output + ewfinfo -e");
            assert_eq!(out.bytes_acquired, SIZE);
            assert_eq!(out.stop_reason, None);
            assert!(!out.aborted);
            assert_eq!(out.image_files, vec![PathBuf::from("/o/b.E01")]);
            assert_eq!(
                out.auxiliary_files,
                vec![PathBuf::from("/o/b.ewfacquire.log")]
            );
            assert_eq!(verdict(&out), Outcome::CompletedWithReadErrors);
            let Some(EngineSettings::Ewf(s)) = &out.settings else {
                panic!("{:?}", out.settings)
            };
            assert_eq!((s.retries, s.error_granularity_sectors), (2, 1));
            assert!(
                out.notes.iter().any(|n| n.contains("replaced 1 sector")),
                "{:?}",
                out.notes
            );
            // No disagreement between the two lists
            assert!(!out.notes.iter().any(|n| n.contains("differ")));
        }
    }

    #[test]
    fn clean_acquisition_and_removable_logical_media() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "clean",
                Some(fx(root, "clean", "ewfinfo-e.stdout")),
                Some(fx(root, "clean", "ewfinfo-m.stdout")),
                0,
            );
            f.requested = Some(EwfSettings {
                media_type: "removable".into(),
                media_flags: "logical".into(),
                ..requested(1, 2)
            });
            let out = assemble(&f).unwrap();
            assert!(out.read_errors.is_empty());
            assert_eq!(out.bytes_acquired, SIZE);
            assert_eq!(verdict(&out), Outcome::Verified);
            assert!(out.notes.is_empty(), "{:?}", out.notes);
            // Requested media as recorded: no note; a different request is noted
            f.requested = Some(requested(1, 2));
            let out = assemble(&f).unwrap();
            let Some(EngineSettings::Ewf(s)) = &out.settings else {
                panic!()
            };
            assert_eq!(
                (s.media_type.as_str(), s.media_flags.as_str()),
                ("removable", "logical")
            );
            assert!(out.notes.iter().any(|n| n.contains("media type removable")));
        }
    }

    #[test]
    fn granularity_ewfacquire_did_not_accept_is_reported_as_applied() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "granularity_fallback",
                Some(fx(root, "granularity_fallback", "ewfinfo-e.stdout")),
                Some(fx(root, "granularity_fallback", "ewfinfo-m.stdout")),
                0,
            );
            f.requested = Some(requested(128, 2));
            let out = assemble(&f).unwrap();
            let Some(EngineSettings::Ewf(s)) = &out.settings else {
                panic!()
            };
            assert_eq!(s.error_granularity_sectors, 64);
            assert!(
                out.notes
                    .iter()
                    .any(|n| n.contains("did not accept an error granularity of 128 sectors")),
                "{:?}",
                out.notes
            );
            // Without ewfinfo the notice on standard error decides
            f.info_media = None;
            let out = assemble(&f).unwrap();
            let Some(EngineSettings::Ewf(s)) = &out.settings else {
                panic!()
            };
            assert_eq!(s.error_granularity_sectors, 64);
            // A retry count ewfacquire replaced
            f.requested = Some(requested(1, 7));
            let out = assemble(&f).unwrap();
            let Some(EngineSettings::Ewf(s)) = &out.settings else {
                panic!()
            };
            assert_eq!(s.retries, 2);
            assert!(out.notes.iter().any(|n| n.contains("did not accept -r 7")));
        }
    }

    #[test]
    fn errors_in_4096_byte_sectors_are_converted_with_the_tool_sector_size() {
        for root in ROOTS {
            let f = facts(
                root,
                "sector4096",
                Some(fx(root, "sector4096", "ewfinfo-e.stdout")),
                Some(fx(root, "sector4096", "ewfinfo-m.stdout")),
                0,
            );
            let out = assemble(&f).unwrap();
            assert_eq!(out.read_errors.sector_size, 4096);
            assert_eq!(ranges(&out), vec![(MIB, 4096, RangeKind::Substituted)]);
            assert_eq!(out.read_errors.sectors(), 1);
        }
    }

    #[test]
    fn three_ranges_and_disagreeing_lists_are_united() {
        for root in ROOTS {
            let f = facts(
                root,
                "three_ranges_g8",
                Some(fx(root, "three_ranges_g8", "ewfinfo-e.stdout")),
                Some(fx(root, "three_ranges_g8", "ewfinfo-m.stdout")),
                0,
            );
            let out = assemble(&f).unwrap();
            assert_eq!(
                ranges(&out),
                vec![
                    (MIB, 4096, RangeKind::Substituted),
                    (2 * MIB, 4096, RangeKind::Substituted),
                    (6400 * 512, 144 * 512, RangeKind::Substituted)
                ]
            );
            assert_eq!(verdict(&out), Outcome::CompletedWithReadErrors);

            // The image lists a range ewfacquire did not print: union + note
            let f = facts(
                root,
                "one_bad_sector",
                Some(fx(root, "three_ranges_g8", "ewfinfo-e.stdout")),
                Some(fx(root, "one_bad_sector", "ewfinfo-m.stdout")),
                0,
            );
            let out = assemble(&f).unwrap();
            assert_eq!(out.read_errors.ranges.len(), 3);
            assert_eq!(out.read_errors.ranges[0].offset, MIB);
            assert_eq!(out.read_errors.ranges[0].length, 4096);
            assert!(
                out.notes
                    .iter()
                    .any(|n| n.contains("differ from those the image records")),
                "{:?}",
                out.notes
            );
        }
    }

    #[test]
    fn errors_without_positions_fail_closed() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "clean",
                None,
                Some(fx(root, "clean", "ewfinfo-m.stdout")),
                0,
            );
            f.acquire.errors = Some(RunBlock {
                total: Some(2),
                runs: vec![],
                unparsed: vec!["at sectors 1..2 (a future format)".into()],
            });
            f.info_errors = Some(Err("exit 1".into()));
            let out = assemble(&f).unwrap();
            assert!(out.read_errors.is_empty());
            assert!(out
                .stop_reason
                .as_deref()
                .unwrap()
                .contains("whose positions could not be determined"));
            assert_eq!(verdict(&out), Outcome::Incomplete);

            // The image's own list supplies the positions
            f.info_errors = Some(Ok(parse_ewfinfo_errors(fx(
                root,
                "three_ranges_g8",
                "ewfinfo-e.stdout",
            ))));
            f.acquire.errors.as_mut().unwrap().total = Some(3);
            let out = assemble(&f).unwrap();
            assert_eq!(out.stop_reason, None, "{:?}", out.notes);
            assert_eq!(out.read_errors.ranges.len(), 3);
            assert_eq!(verdict(&out), Outcome::CompletedWithReadErrors);
        }
    }

    #[test]
    fn media_shortfall_is_incomplete() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "clean",
                Some(fx(root, "clean", "ewfinfo-e.stdout")),
                Some(fx(root, "clean", "ewfinfo-m.stdout")),
                0,
            );
            f.expected_bytes = SIZE + 512;
            let out = assemble(&f).unwrap();
            assert_eq!(out.bytes_acquired, SIZE);
            assert_eq!(verdict(&out), Outcome::Incomplete);
            assert!(out
                .notes
                .iter()
                .any(|n| n.contains("the source had 4194816 bytes")));
            // Size unknown: never assumed
            f.info_media = Some(Err("exit 1".into()));
            f.acquire.media_size = None;
            let out = assemble(&f).unwrap();
            assert!(out
                .stop_reason
                .as_deref()
                .unwrap()
                .contains("could not be determined"));
        }
    }

    #[test]
    fn source_lost_after_zero_filling_to_the_end() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "dying_to_end",
                Some(fx(root, "dying_to_end", "ewfinfo-e.stdout")),
                Some(fx(root, "dying_to_end", "ewfinfo-m.stdout")),
                0,
            );
            // Still attached: a medium that stopped answering is a read error
            let out = assemble(&f).unwrap();
            assert_eq!(ranges(&out), vec![(MIB, 3 * MIB, RangeKind::Substituted)]);
            assert_eq!(verdict(&out), Outcome::CompletedWithReadErrors);
            assert!(out
                .notes
                .iter()
                .any(|n| n.contains("still present afterwards")));

            f.source_presence = Err("/dev/sdx no longer exists".into());
            let out = assemble(&f).unwrap();
            assert_eq!(ranges(&out), vec![(MIB, 3 * MIB, RangeKind::Unread)]);
            assert_eq!(out.bytes_acquired, MIB);
            assert_eq!(
                out.stop_reason.as_deref(),
                Some("source lost at offset 1048576 (1 MiB): /dev/sdx no longer exists")
            );
            assert_eq!(verdict(&out), Outcome::Incomplete);
        }
    }

    #[test]
    fn source_vanished_during_the_run_is_incomplete() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "source_vanished",
                Some(fx(root, "source_vanished", "ewfinfo-e.stdout")),
                Some(fx(root, "source_vanished", "ewfinfo-m.stdout")),
                1,
            );
            f.source_presence = Err("src.img no longer exists".into());
            let out = assemble(&f).unwrap();
            let reason = out.stop_reason.clone().unwrap();
            assert!(
                reason.starts_with("source lost during the acquisition (src.img no longer exists); ewfacquire stopped with FAILURE"),
                "{reason}"
            );
            assert_eq!(out.bytes_acquired, 0);
            assert!(out.notes.iter().any(|n| n.contains("ewfinfo: corrupted")));
            assert_eq!(verdict(&out), Outcome::Incomplete);

            // The same failure with the source present: a tool failure
            f.source_presence = Ok(());
            let out = assemble(&f).unwrap();
            let reason = out.stop_reason.unwrap();
            assert!(reason.starts_with("ewfacquire failed (exit 1)"), "{reason}");
            assert!(
                reason.contains("unable to read from device file"),
                "{reason}"
            );

            // Destination full
            f.acquire.diagnostics = vec!["libcfile_file_write_buffer: unable to write to file with error: No space left on device".into()];
            let out = assemble(&f).unwrap();
            assert!(out.stop_reason.unwrap().starts_with("destination full"));

            // Nothing written: the error stands
            f.segments.clear();
            f.log_file = None;
            let err = assemble(&f).unwrap_err();
            assert_eq!(err.kind, ErrorKind::Failed);
        }
    }

    #[test]
    fn abort_keeps_segments_and_records_the_last_progress() {
        for root in ROOTS {
            let mut f = facts(
                root,
                "aborted",
                Some(fx(root, "aborted", "ewfinfo-e.stdout")),
                Some(fx(root, "aborted", "ewfinfo-m.stdout")),
                1,
            );
            f.run.stopped = true;
            f.run.status_text = "exit 1 (aborted: SIGINT)".into();
            let out = assemble(&f).unwrap();
            assert!(out.aborted);
            assert_eq!(out.image_files.len(), 1);
            assert_eq!(out.bytes_acquired, 0);
            assert_eq!(out.stop_reason, None);
            assert!(out
                .notes
                .iter()
                .any(|n| n.contains("not finalized (ewfinfo: corrupted)")));
            assert_eq!(verdict(&out), Outcome::Aborted);

            f.acquire.acquired_bytes = Some(1_736_704);
            let out = assemble(&f).unwrap();
            assert_eq!(out.bytes_acquired, 1_736_704);

            f.segments.clear();
            assert_eq!(assemble(&f).unwrap_err().kind, ErrorKind::Aborted);
        }
    }

    #[test]
    fn ewfverify_verdicts() {
        for root in ROOTS {
            let sel = HashSelection {
                md5: true,
                sha1: true,
                sha256: true,
            };
            let clean = parse_ewfverify(fx(root, "clean", "ewfverify.stdout"), "");
            let acquisition = acquire_report(root, "clean").hashes;
            let r = evaluate_ewfverify(sel, &acquisition, &clean, true, "exit 0", "ewfverify");
            assert!(r.is_matched(), "{r:?}");

            // Tampered image: the recomputed digests differ -> mismatch, with the
            // checksum errors ewfverify found
            let tampered = parse_ewfverify(fx(root, "tampered", "ewfverify.stdout"), "");
            let r = evaluate_ewfverify(sel, &acquisition, &tampered, false, "exit 1", "ewfverify");
            let VerificationResult::Mismatched { details, .. } = r else {
                panic!("{r:?}")
            };
            assert!(details.contains("MD5"), "{details}");
            assert!(details.contains("checksum errors"), "{details}");

            // Matching digests but ewfverify failed: a failure, never a pass
            let r = evaluate_ewfverify(sel, &acquisition, &clean, false, "exit 1", "ewfverify");
            assert!(matches!(r, VerificationResult::Failed { .. }), "{r:?}");

            // A requested digest ewfverify did not recompute
            let only256 = parse_ewfverify(fx(root, "clean", "ewfverify-sha256.stdout"), "");
            let r = evaluate_ewfverify(sel, &acquisition, &only256, true, "exit 0", "ewfverify");
            let VerificationResult::Failed { reason } = r else {
                panic!("{r:?}")
            };
            let missing = if root.is_empty() { "MD5" } else { "SHA-1" };
            assert!(
                reason.contains(&format!("{missing} was not recomputed")),
                "{reason}"
            );

            // An unfinalized image
            let broken = parse_ewfverify(
                fx(root, "aborted", "ewfverify.stdout"),
                fx(root, "aborted", "ewfverify.stderr"),
            );
            let r = evaluate_ewfverify(sel, &acquisition, &broken, false, "exit 1", "ewfverify");
            assert!(!r.is_matched(), "{r:?}");
            if root.is_empty() {
                assert!(matches!(r, VerificationResult::Failed { .. }), "{r:?}");
            }
        }
    }

    // -- options, files, source --------------------------------------------

    fn context(dir: &Path, case: CaseMetadata, config: AcquisitionConfig) -> EngineContext {
        let device = BlockDevice {
            name: "sdx".into(),
            path: "/dev/sdx".into(),
            size_bytes: SIZE,
            serial: Some("SER1".into()),
            maj_min: Some("8:16".into()),
            logical_sector_size: 512,
            physical_sector_size: 4096,
            ..Default::default()
        };
        let identity = SourceIdentity {
            path: "/dev/sdx".into(),
            canonical_path: "/dev/sdx".into(),
            kernel_name: "sdx".into(),
            maj_min: Some("8:16".into()),
            kind: SourceKind::Partition,
            size_bytes: SIZE,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            removable: true,
            ..Default::default()
        };
        let config = AcquisitionConfig {
            output_dir: dir.to_path_buf(),
            ..config
        };
        let mut ctx = EngineContext::new(
            AcquisitionRequest::new(device, case, config),
            identity,
            "c_ea01_e_SER1",
        );
        ctx.tool_source_path = "/dev/disk/by-diskseq/9-part1".into();
        ctx
    }

    #[test]
    fn command_line_states_every_applied_option() {
        let tmp = tempfile::tempdir().unwrap();
        let case = CaseMetadata {
            case_number: "C\t1".into(),
            evidence_number: "E1".into(),
            examiner: "Ex".into(),
            ..Default::default()
        };
        let config = AcquisitionConfig {
            error_retries: 255,
            calc_sha1: false,
            ..AcquisitionConfig::ewf(tmp.path())
        };
        let ctx = context(tmp.path(), case, config);
        let settings = requested_settings(&ctx);
        // 512-byte logical / 4096-byte physical; a partition; removable
        assert_eq!(settings.error_granularity_sectors, 8);
        assert_eq!(settings.media_type, "removable");
        assert_eq!(settings.media_flags, "logical");
        let log = ctx.output_path(LOG_SUFFIX);
        let argv = ewfacquire_spec(&ctx, &settings, &log).argv();
        let pairs: Vec<(String, String)> = argv
            .windows(2)
            .map(|w| (w[0].clone(), w[1].clone()))
            .collect();
        let has = |flag: &str, value: &str| pairs.contains(&(flag.to_string(), value.to_string()));
        assert_eq!(argv[0], "ewfacquire");
        assert!(argv.contains(&"-u".to_string()));
        assert!(has("-C", "C 1"), "{argv:?}");
        assert!(has("-E", "E1") && has("-e", "Ex"));
        assert!(has("-r", "255") && has("-g", "8"));
        assert!(has("-m", "removable") && has("-M", "logical"));
        assert!(has("-d", "sha256") && has("-f", "encase6") && has("-c", "fast"));
        assert!(has("-l", &log.to_string_lossy()));
        assert!(has("-t", &ctx.output_path("").to_string_lossy()));
        assert!(argv.contains(&"-w".to_string()));
        // No placeholder for empty optional fields: no -D; -N carries the
        // effective EA only (the same values the .info records)
        assert!(!argv.contains(&"-D".to_string()));
        assert!(
            has("-N", &ctx.case().ewf_header_notes().unwrap()),
            "{argv:?}"
        );
        assert!(!argv.iter().any(|a| a.contains("not provided")), "{argv:?}");
        assert_eq!(argv.last().unwrap(), "/dev/disk/by-diskseq/9-part1");
    }

    #[test]
    fn r_is_given_only_for_a_count_other_than_ewfacquires_default() {
        let tmp = tempfile::tempdir().unwrap();
        let argv_for = |retries: u32| {
            let config = AcquisitionConfig {
                error_retries: retries,
                ..AcquisitionConfig::ewf(tmp.path())
            };
            let ctx = context(tmp.path(), CaseMetadata::default(), config);
            let settings = requested_settings(&ctx);
            assert_eq!(settings.retries, retries);
            assert_eq!(settings.retries_default, retries == 2);
            ewfacquire_spec(&ctx, &settings, &ctx.output_path(LOG_SUFFIX)).argv()
        };
        // ewfacquire 20140807 crashes on any -r; its default is 2 everywhere
        let argv = argv_for(EWFACQUIRE_DEFAULT_RETRIES);
        assert!(!argv.contains(&"-r".to_string()), "{argv:?}");
        for retries in [0, 1, 3, 255] {
            let argv = argv_for(retries);
            assert!(
                argv.windows(2)
                    .any(|w| w[0] == "-r" && w[1] == retries.to_string()),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn the_release_comes_from_the_version_line() {
        assert_eq!(libewf_release("ewfacquire 20140807"), Some(20140807));
        assert_eq!(libewf_release("ewfacquire 20231119\n"), Some(20231119));
        assert_eq!(libewf_release("  ewfacquire 20140816  "), Some(20140816));
        for odd in [
            "",
            "ewfacquire",
            "ewfacquire 2014080",
            "ewfacquire 201408077",
            "ewfacquire 20140807-2ubuntu2",
            "ewfacquire v20140807",
            "ewfexport 20140807",
            "fake-ewfacquire 0",
        ] {
            assert_eq!(libewf_release(odd), None, "{odd:?}");
        }
    }

    #[test]
    fn releases_that_crash_on_r_are_named_by_evidence() {
        // Run with each distribution's ewf-tools (SIGSEGV on -r): Ubuntu
        // 18.04, Debian 10, Debian 11 / Ubuntu 20.04 / Ubuntu 22.04
        for crashes in [20140608, 20140804, 20140807] {
            assert!(retries_option_crashes(crashes), "{crashes}");
        }
        // Run: Debian 12, Ubuntu 24.04, Debian 13 / nixpkgs libewf-legacy,
        // nixpkgs libewf
        for applies in [20140813, 20140814, 20140816, 20231119] {
            assert!(!retries_option_crashes(applies), "{applies}");
        }
        // The edges in libewf's history: the bug came with 20101105, the
        // libewf-legacy fix with 20140810, the libewf fix after 20200210
        for (release, crashes) in [
            (20101104, false),
            (20101105, true),
            (20130128, true),
            (20140806, true),
            (20140808, true),
            (20140810, false),
            (20140817, false),
            (20141002, true),
            (20171104, true),
            (20200210, true),
            (20200216, false),
            (20240506, false),
        ] {
            assert_eq!(retries_option_crashes(release), crashes, "{release}");
        }
    }

    #[test]
    fn other_retries_are_refused_only_where_r_crashes() {
        let broken = Some("ewfacquire 20140807");
        // The default needs no -r: accepted by every release
        assert_eq!(check_retries_option(2, broken), Ok(()));
        for retries in [0, 1, 3, 255] {
            let err = check_retries_option(retries, broken).unwrap_err();
            // The cause and the remedies
            assert!(err.contains("ewfacquire 20140807 crashes on -r"), "{err}");
            assert!(err.contains("segmentation fault"), "{err}");
            assert!(err.contains("default of 2 read retries"), "{err}");
            assert!(err.contains("leave out --retries"), "{err}");
            assert!(err.contains("ewf-tools 20140813 or later"), "{err}");
            assert!(err.contains("libewf later than 20200210"), "{err}");
            assert!(err.contains("Nothing was written"), "{err}");
            for fixed in ["ewfacquire 20140816", "ewfacquire 20231119"] {
                assert_eq!(check_retries_option(retries, Some(fixed)), Ok(()));
            }
            // An unknown release is not refused
            assert_eq!(check_retries_option(retries, None), Ok(()));
            assert_eq!(
                check_retries_option(retries, Some("ewfacquire custom")),
                Ok(())
            );
        }
    }

    #[test]
    fn unknown_error_reports_fail_closed() {
        for root in ROOTS {
            // An ewfinfo -e format this parser does not know
            let odd = parse_ewfinfo_errors("ewfinfo 20990101\n\nBad sectors found\n\t2048-2111\n");
            assert!(odd.incomplete(), "{odd:?}");
            let mut f = facts(
                root,
                "clean",
                None,
                Some(fx(root, "clean", "ewfinfo-m.stdout")),
                0,
            );
            f.info_errors = Some(Ok(odd));
            let out = assemble(&f).unwrap();
            assert!(out.stop_reason.is_some(), "{:?}", out.notes);
            assert_eq!(verdict(&out), Outcome::Incomplete);
            assert!(out.notes.iter().any(|n| n.contains("Bad sectors found")));

            // An error line on ewfacquire's output in an unknown form
            let mut f = facts(
                root,
                "clean",
                Some(fx(root, "clean", "ewfinfo-e.stdout")),
                Some(fx(root, "clean", "ewfinfo-m.stdout")),
                0,
            );
            let mut p = EwfacquireParser::new();
            for line in fx(root, "clean", "ewfacquire.stdout").lines() {
                if line.starts_with("MD5 hash") {
                    p.feed(StreamTag::Stdout, "Read errors: 3 (positions follow)");
                }
                p.feed(StreamTag::Stdout, line);
            }
            f.acquire = p.finish();
            let out = assemble(&f).unwrap();
            assert!(out.stop_reason.is_some(), "{:?}", out.notes);
            assert_eq!(verdict(&out), Outcome::Incomplete);
            // The known outputs stay clean
            let f = facts(
                root,
                "clean",
                Some(fx(root, "clean", "ewfinfo-e.stdout")),
                Some(fx(root, "clean", "ewfinfo-m.stdout")),
                0,
            );
            assert_eq!(assemble(&f).unwrap().stop_reason, None);
        }
    }

    #[test]
    fn sources_without_whole_sectors_are_refused() {
        assert_eq!(check_source_size(4 * MIB), Ok(()));
        assert_eq!(check_source_size(0), Ok(()));
        let err = check_source_size(3_000_000).unwrap_err();
        assert!(
            err.contains("192 bytes more than 5859 whole 512-byte sectors"),
            "{err}"
        );
        assert!(err.contains("RAW engine"), "{err}");
        let err = check_source_size(1000).unwrap_err();
        assert!(
            err.contains("488 bytes more than 1 whole 512-byte sector;"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_source_without_whole_sectors_is_a_usage_error_before_ewfacquire_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = context(
            tmp.path(),
            CaseMetadata::default(),
            AcquisitionConfig::ewf(tmp.path()),
        );
        ctx.identity.size_bytes = 3_000_000;
        let err = acquire(&ctx).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Usage);
        assert!(ctx.provenance.commands().is_empty());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn invalid_retries_are_a_usage_error_before_anything_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let config = AcquisitionConfig {
            error_retries: 256,
            ..AcquisitionConfig::ewf(tmp.path())
        };
        let ctx = context(tmp.path(), CaseMetadata::default(), config);
        let err = acquire(&ctx).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Usage);
        assert!(ctx.provenance.commands().is_empty());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn digest_lists() {
        let base = AcquisitionConfig::default();
        assert_eq!(
            ewf_digest_list(ewf_selection(&base), false).as_deref(),
            Some("sha1,sha256")
        );
        assert_eq!(
            ewf_digest_list(ewf_selection(&base), true).as_deref(),
            Some("md5,sha1,sha256")
        );
        let md5_only = AcquisitionConfig {
            calc_sha1: false,
            calc_sha256: false,
            ..Default::default()
        };
        assert_eq!(ewf_digest_list(ewf_selection(&md5_only), false), None);
        assert_eq!(
            ewf_digest_list(ewf_selection(&md5_only), true).as_deref(),
            Some("md5")
        );
    }

    #[test]
    fn segment_names_and_order() {
        let base = "case_ea01_cf01_SERIAL";
        for ok in [
            "E01", "e01", "E99", "EAA", "EZZ", "FAA", "ZZZ", "s01", "001",
        ] {
            assert!(is_ewf_segment(base, &format!("{base}.{ok}")), "{ok}");
        }
        for bad in [
            "case_ea01_cf01_SERIAL.info",
            "case_ea01_cf01_SERIAL.old",
            "case_ea01_cf01_SERIAL.E01.bak",
            "case_ea01_cf01_SERIAL.ewfacquire.log",
            "case_ea01_cf01_SERIAL_copy.E01",
            "case_ea01_cf01_SERIAL.F01",
            "other_case.E01",
        ] {
            assert!(!is_ewf_segment(base, bad), "{bad}");
        }
        let tmp = tempfile::tempdir().unwrap();
        for ext in ["FAA", "E02", "EAB", "E01", "EZZ", "EAA", "E99", "info"] {
            std::fs::write(tmp.path().join(format!("b.{ext}")), b"").unwrap();
        }
        let names: Vec<String> = find_segments(tmp.path(), "b")
            .iter()
            .map(|p| p.extension().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["E01", "E02", "E99", "EAA", "EAB", "EZZ", "FAA"]);
    }

    #[test]
    fn a_segment_size_ewfacquire_refused_is_recorded_as_applied() {
        // libewf 20231119 and 20140816 on -S 9223372036854775807B (measured)
        let r = parse_ewfacquire(
            "ewfacquire: SUCCESS\n",
            "Unsupported maximum segment size defaulting to: 1572864000.\n",
        );
        assert_eq!(r.segment_bytes_applied, Some(1_572_864_000));
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        let mut f = facts("", "clean", None, None, 0);
        f.acquire.segment_bytes_applied = Some(1_572_864_000);
        let out = assemble(&f).unwrap();
        let Some(EngineSettings::Ewf(s)) = &out.settings else {
            panic!("{:?}", out.settings)
        };
        assert_eq!(s.segment_bytes, Some(1_572_864_000));
        assert!(
            s.segment_size.contains("applied by ewfacquire"),
            "{}",
            s.segment_size
        );
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("did not accept the segment size 2.0 GiB")),
            "{:?}",
            out.notes
        );
        // The same size as requested: nothing to say
        f.acquire.segment_bytes_applied = Some(2048 * MIB);
        let out = assemble(&f).unwrap();
        assert!(!out.notes.iter().any(|n| n.contains("segment size")));
    }

    #[test]
    fn segment_extensions_follow_libewf() {
        for (n, ext) in [
            (1, "E01"),
            (9, "E09"),
            (99, "E99"),
            (100, "EAA"),
            (101, "EAB"),
            (126, "EBA"),
            (775, "EZZ"),
            (776, "FAA"),
            (811, "FBJ"),
            (14_971, "ZZZ"),
        ] {
            assert_eq!(segment_extension("E01", n).as_deref(), Some(ext), "{n}");
        }
        assert_eq!(segment_extension("E01", 14_972), None);
        assert_eq!(segment_extension("E01", 0), None);
        assert_eq!(segment_extension("e01", 776).as_deref(), Some("faa"));
        assert_eq!(segment_extension("s01", 100).as_deref(), Some("saa"));
        assert_eq!(segment_extension("s01", 776).as_deref(), Some("taa"));
        assert_eq!(segment_extension("Ex01", 2).as_deref(), Some("Ex02"));
        assert_eq!(segment_extension("Ex01", 776).as_deref(), Some("FxAA"));
        assert_eq!(segment_extension("E02", 1), None);
        assert_eq!(segment_extension("raw", 1), None);
        // The E01 engine recognises every name of the sequence, in order
        let mut previous: Option<String> = None;
        for n in 1..=2000 {
            let ext = segment_extension("E01", n).unwrap();
            assert!(is_ewf_segment("b", &format!("b.{ext}")), "{ext}");
            let key = segment_order(Path::new(&format!("b.{ext}")));
            if let Some(p) = &previous {
                assert!(
                    segment_order(Path::new(&format!("b.{p}"))) < key,
                    "{p} < {ext}"
                );
            }
            previous = Some(ext);
        }
    }

    #[test]
    fn a_stall_is_checked_only_after_the_limit_and_names_the_cause() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut w = StallWatch::new(s(60), t0);
        let lost = || Err("the source has 1048576 bytes now".to_string());
        let never = || -> Result<(), String> { panic!("probed too early") };
        // Progress resets the clock; no probe before the limit
        assert_eq!(w.tick(100, t0 + s(30), never), None);
        assert_eq!(w.tick(200, t0 + s(70), never), None);
        assert_eq!(w.tick(200, t0 + s(129), never), None);
        // No progress for the limit: probed; a present source keeps waiting
        assert_eq!(w.tick(200, t0 + s(131), || Ok(())), None);
        // ... and is probed again at most once a second
        assert_eq!(
            w.tick(200, t0 + s(131) + Duration::from_millis(500), never),
            None
        );
        assert_eq!(
            w.tick(200, t0 + s(133), lost).as_deref(),
            Some("the source has 1048576 bytes now")
        );
    }

    #[test]
    fn a_smaller_or_vanished_source_is_not_there() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        std::fs::create_dir_all(sys.join("8:16")).unwrap();
        std::fs::write(sys.join("8:16/size"), "8192\n").unwrap();
        let disk = SourceIdentity {
            path: "/dev/sdx".into(),
            maj_min: Some("8:16".into()),
            kind: SourceKind::Disk,
            ..Default::default()
        };
        let same = |_: &Path| Ok(Some((8, 16)));
        assert_eq!(source_size_in(&disk, &sys), Some(4 * MIB));
        assert_eq!(source_still_there(&disk, 4 * MIB, &sys, &same), Ok(()));
        std::fs::write(sys.join("8:16/size"), "2048\n").unwrap();
        let e = source_still_there(&disk, 4 * MIB, &sys, &same).unwrap_err();
        assert!(
            e.contains("1048576 bytes now, 4194304 bytes when the acquisition started"),
            "{e}"
        );
        let gone = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(source_still_there(&disk, MIB, &sys, &gone).is_err());
        // A regular file that was truncated
        let f = tmp.path().join("src.img");
        std::fs::write(&f, vec![1u8; 4096]).unwrap();
        let file = crate::discovery::identity::probe_file(&f.to_string_lossy()).unwrap();
        assert_eq!(source_still_there(&file, 4096, &sys, &same), Ok(()));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&f)
            .unwrap()
            .set_len(512)
            .unwrap();
        assert!(source_still_there(&file, 4096, &sys, &same)
            .unwrap_err()
            .contains("512 bytes now"));
    }

    #[test]
    fn a_stalled_ewfacquire_is_a_lost_source_not_an_abort() {
        let mut f = facts("", "aborted", None, None, 1);
        f.run.status_text = "exit 1 (aborted: SIGINT)".into();
        f.stalled = Some("source lost at offset 1048576 (1 MiB): the source has 1048576 bytes now, 4194304 bytes when the acquisition started; ewfacquire made no progress for 60 s and was stopped by dfdisk".into());
        let out = assemble(&f).unwrap();
        assert!(!out.aborted);
        assert!(out
            .stop_reason
            .as_deref()
            .unwrap()
            .starts_with("source lost at offset 1048576"));
        assert!(out
            .notes
            .iter()
            .any(|n| n.starts_with("dfdisk stopped ewfacquire (exit 1 (aborted: SIGINT))")));
        // Nothing written: an error
        f.segments.clear();
        let e = assemble(&f).unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Failed);
        assert!(e.message.contains("source lost"), "{e}");
    }

    #[test]
    fn source_presence_detects_vanished_and_replaced_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        std::fs::create_dir_all(sys.join("8:16")).unwrap();
        std::fs::write(sys.join("8:16/diskseq"), "7\n").unwrap();
        let id = SourceIdentity {
            path: "/dev/sdx".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(7),
            kind: SourceKind::Disk,
            ..Default::default()
        };
        let same = |_: &Path| Ok(Some((8, 16)));
        assert_eq!(source_presence_in(&id, &sys, &same), Ok(()));
        let other = |_: &Path| Ok(Some((8, 32)));
        assert!(source_presence_in(&id, &sys, &other)
            .unwrap_err()
            .contains("8:32 now"));
        let gone = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(source_presence_in(&id, &sys, &gone)
            .unwrap_err()
            .contains("no longer exists"));
        std::fs::write(sys.join("8:16/diskseq"), "8\n").unwrap();
        assert!(source_presence_in(&id, &sys, &same)
            .unwrap_err()
            .contains("diskseq 8 instead of 7"));
        std::fs::remove_dir_all(sys.join("8:16")).unwrap();
        assert!(source_presence_in(&id, &sys, &same)
            .unwrap_err()
            .contains("8:16 no longer exists"));

        // Regular files: same file (device and inode), or not
        let f = tmp.path().join("src.img");
        std::fs::write(&f, b"x").unwrap();
        let file = crate::discovery::identity::probe_file(&f.to_string_lossy()).unwrap();
        assert_eq!(source_presence(&file), Ok(()));
        std::fs::rename(&f, tmp.path().join("moved")).unwrap();
        assert!(source_presence(&file)
            .unwrap_err()
            .contains("no longer exists"));
        std::fs::write(&f, b"y").unwrap();
        assert!(source_presence(&file).unwrap_err().contains("another file"));
    }
}
