//! Re-verification of an existing image (§13 Verify, review M12), used by the
//! CLI (`dfdisk verify`) and the TUI.
//!
//! - **EWF** images (`.E01`, `.E02`... `.EAA`... `.FAA`..., `.Ex01`, `.s01`,
//!   `.L01`, or the EVF/LVF signature) are re-read by `ewfverify -d
//!   md5,sha1,sha256` on their first segment; the whole segment family is
//!   listed and a missing segment is refused. Only digests ewfverify
//!   *calculated* count. The digests the image stores are a reference too:
//!   an image whose stored digests ewfverify checked counts as compared.
//! - **RAW** images, including split RAW families (`x.001`, `x.002`, ... or
//!   from `x.000`), are hashed by dfdisk as one stream after asking the
//!   kernel to drop cached pages (POSIX_FADV_DONTNEED); a gap in the family
//!   is refused, never silently skipped.
//! - Expected digests come from the command line or from a dfdisk report
//!   (`<base>.info.json`, [`ExpectedHashes::from_report_json`]).
//! - `--pieces <file>` re-checks a RAW image against its piecewise SHA-256
//!   file ([`crate::engines::pieces::verify_pieces`]).
//!
//! Verdict ([`decide_against`]): any digest that differs -> Mismatch (exit
//! 5); otherwise a tool failure or a requested digest that was not computed
//! -> VerificationFailed (exit 4); nothing compared at all -> "COMPUTED —
//! nothing to compare against" (exit 9, decision 1); else VERIFIED (exit 0).
//! Never PASSED without a computed value. The result is written as an
//! addendum `<base>.verify-<UTC>.txt` next to the image and as an audit
//! `image_verification` record.

use crate::engines::audit;
use crate::engines::error::{AcquisitionError, ErrorKind};
use crate::engines::ewf::{EwfverifyParser, EwfverifyReport, ToolStatus};
use crate::engines::hasher::HashProgress;
use crate::engines::pieces::{self, PiecesReport};
use crate::engines::process::{self, ProcessEvent, ProcessSpec};
use crate::models::config::HashAlgorithm;
use crate::models::info_report::{
    sha256_file, sync_dir, ForensicInfoReport, HashResults, HashSelection,
};
use crate::models::outcome::{exit_code, Outcome, VerificationResult};
use crate::models::provenance::{
    ClockInfo, ProvenanceRecorder, DFCORE_GIT_REV, DFDISK_GIT_REV, DFDISK_VERSION,
};
use crate::models::text::{format_iec, plural, sanitize_line};
use crate::signals::StopFlags;
use chrono::{DateTime, Utc};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Digest list ewfverify recomputes.
const EWF_DIGESTS: &str = "md5,sha1,sha256";
/// Read size of the RAW hasher.
const HASH_CHUNK: usize = 4 * 1024 * 1024;
/// Verdict of a verification that compared nothing (decision 1).
pub const NOTHING_COMPARED: &str = "COMPUTED — nothing to compare against";
/// Reference label of the digests an EWF image stores.
pub const STORED_IN_IMAGE: &str = "digests stored in the EWF image";

/// How the image was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedFormat {
    /// Expert Witness Format, through ewfverify
    Ewf,
    /// Any other file (or split RAW family), hashed by dfdisk
    Raw,
}

impl VerifiedFormat {
    pub fn label(&self) -> &'static str {
        match self {
            VerifiedFormat::Ewf => "EWF (E01), decoded media data",
            VerifiedFormat::Raw => "RAW (file content)",
        }
    }
}

/// The digests an image is expected to have, and where they came from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedHashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    /// "command line", or the report they were read from
    pub source: String,
    /// Image file names the report lists (empty: not from a report)
    #[serde(default)]
    pub report_image_files: Vec<String>,
    /// Verdict of the acquisition the report describes
    #[serde(default)]
    pub report_outcome: Option<Outcome>,
    /// Pieces file the report lists, and its SHA-256
    #[serde(default)]
    pub report_pieces: Option<(String, String)>,
}

impl ExpectedHashes {
    /// Digests given by the examiner (blank values ignored).
    pub fn given(md5: Option<String>, sha1: Option<String>, sha256: Option<String>) -> Self {
        let clean = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Self {
            md5: clean(md5),
            sha1: clean(sha1),
            sha256: clean(sha256),
            source: "command line".into(),
            ..Default::default()
        }
    }

    /// The digests a report recorded: those computed while reading the source,
    /// or, when there are none (rescue), those of the image.
    pub fn from_report(report: &ForensicInfoReport, source: impl Into<String>) -> Self {
        let h = if report.acquisition_hashes.is_empty() {
            &report.image_hashes
        } else {
            &report.acquisition_hashes
        };
        Self {
            md5: h.md5.clone(),
            sha1: h.sha1.clone(),
            sha256: h.sha256.clone(),
            source: source.into(),
            report_image_files: report.image_files.clone(),
            report_outcome: Some(report.outcome),
            report_pieces: report
                .piecewise
                .as_ref()
                .map(|p| (p.file.clone(), p.file_sha256.clone())),
        }
    }

    /// [`from_report`](Self::from_report) of a `<base>.info.json`.
    pub fn from_report_json(path: &Path) -> Result<Self, AcquisitionError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            AcquisitionError::usage(format!("cannot read the report {}: {e}", path.display()))
        })?;
        let report = ForensicInfoReport::from_json(&text).map_err(|e| {
            AcquisitionError::usage(format!(
                "{} is not a dfdisk report (schema 2): {e}",
                path.display()
            ))
        })?;
        Ok(Self::from_report(&report, path.display().to_string()))
    }

    /// The digests stored in an EWF image, as a reference.
    pub fn stored_in_image(stored: &HashResults) -> Self {
        Self {
            md5: stored.md5.clone(),
            sha1: stored.sha1.clone(),
            sha256: stored.sha256.clone(),
            source: STORED_IN_IMAGE.into(),
            ..Default::default()
        }
    }

    pub fn get(&self, algorithm: HashAlgorithm) -> Option<&str> {
        match algorithm {
            HashAlgorithm::MD5 => self.md5.as_deref(),
            HashAlgorithm::SHA1 => self.sha1.as_deref(),
            HashAlgorithm::SHA256 => self.sha256.as_deref(),
        }
    }

    /// The algorithms with an expected value.
    pub fn selection(&self) -> HashSelection {
        HashSelection {
            md5: self.md5.is_some(),
            sha1: self.sha1.is_some(),
            sha256: self.sha256.is_some(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.selection().is_empty()
    }
}

/// How one expected digest compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Match,
    Mismatch,
    /// Requested but not computed: the verification fails
    NotComputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmCheck {
    pub algorithm: HashAlgorithm,
    pub expected: String,
    pub computed: Option<String>,
    pub status: CheckStatus,
    /// Where the expected value came from ("command line", a report,
    /// [`STORED_IN_IMAGE`])
    #[serde(default)]
    pub reference: String,
}

/// Compare `computed` with `expected` (pure); see [`decide_against`].
pub fn decide(
    computed: &HashResults,
    expected: &ExpectedHashes,
    tool_failure: Option<&str>,
    method: &str,
) -> (Vec<AlgorithmCheck>, VerificationResult) {
    decide_against(computed, &[expected], tool_failure, method)
}

/// Compare `computed` with every reference (pure). `tool_failure`: the
/// reader reported an error (ewfverify FAILURE, a non-zero exit). Rules, in
/// order: any difference -> Mismatched (a provable difference outweighs a
/// tool error); tool failure -> Failed; nothing compared -> NotPossible
/// ("nothing to compare against"); a requested digest that was not computed
/// -> Failed; else Matched.
pub fn decide_against(
    computed: &HashResults,
    references: &[&ExpectedHashes],
    tool_failure: Option<&str>,
    method: &str,
) -> (Vec<AlgorithmCheck>, VerificationResult) {
    let checks: Vec<AlgorithmCheck> = references
        .iter()
        .flat_map(|reference| {
            reference
                .selection()
                .algorithms()
                .into_iter()
                .map(|alg| {
                    let want = reference.get(alg).unwrap_or_default().to_string();
                    let got = computed.get(alg).map(str::to_string);
                    let status = match &got {
                        None => CheckStatus::NotComputed,
                        Some(g) if g.eq_ignore_ascii_case(&want) => CheckStatus::Match,
                        Some(_) => CheckStatus::Mismatch,
                    };
                    AlgorithmCheck {
                        algorithm: alg,
                        expected: want,
                        computed: got,
                        status,
                        reference: reference.source.clone(),
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mismatches: Vec<String> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Mismatch)
        .map(|c| {
            format!(
                "{} expected {} ({}) but computed {}",
                c.algorithm.label(),
                c.expected,
                c.reference,
                c.computed.as_deref().unwrap_or_default()
            )
        })
        .collect();
    let missing: Vec<&str> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::NotComputed)
        .map(|c| c.algorithm.label())
        .collect();
    let result = if !mismatches.is_empty() {
        VerificationResult::Mismatched {
            method: method.to_string(),
            details: match tool_failure {
                Some(f) => format!("{}; {f}", mismatches.join("; ")),
                None => mismatches.join("; "),
            },
        }
    } else if let Some(reason) = tool_failure {
        VerificationResult::Failed {
            reason: reason.to_string(),
        }
    } else if checks.is_empty() {
        VerificationResult::NotPossible {
            reason: "nothing to compare against: no expected digest was given (and the image stores none); the digests were only computed".into(),
        }
    } else if !missing.is_empty() {
        VerificationResult::Failed {
            reason: format!(
                "{} was requested but not computed by {method}",
                missing.join(", ")
            ),
        }
    } else {
        VerificationResult::Matched {
            method: method.to_string(),
        }
    };
    (checks, result)
}

/// Exit code of a verification (§2, decision 1): 0 matched, 5 mismatch, 4
/// failed, 9 nothing compared ("complete but unverified").
pub fn verification_exit_code(result: &VerificationResult) -> i32 {
    match result {
        VerificationResult::Matched { .. } => exit_code::VERIFIED,
        VerificationResult::Mismatched { .. } => exit_code::MISMATCH,
        VerificationResult::Failed { .. } => exit_code::FAILED,
        VerificationResult::NotPossible { .. } => exit_code::UNVERIFIED,
    }
}

/// Everything a verification found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVerification {
    /// The image as given
    pub image: PathBuf,
    /// The file actually read first (first EWF segment, first RAW segment)
    pub read_path: PathBuf,
    /// Every file that was read, in order (EWF segments, split RAW parts)
    #[serde(default)]
    pub segments: Vec<PathBuf>,
    pub format: VerifiedFormat,
    /// e.g. "ewfverify -d md5,sha1,sha256"
    pub method: String,
    pub computed: HashResults,
    /// Digests the EWF image stores (as ewfverify listed them)
    #[serde(default)]
    pub stored: HashResults,
    pub expected: ExpectedHashes,
    pub checks: Vec<AlgorithmCheck>,
    /// The piecewise check (`--pieces`); serialized only
    #[serde(default, skip_deserializing)]
    pub pieces: Option<PiecesReport>,
    pub result: VerificationResult,
    pub exit_code: i32,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub elapsed_seconds: f64,
    pub clock: ClockInfo,
    /// The addendum written, `<base>.verify-<UTC>.txt`
    pub addendum: Option<PathBuf>,
    pub addendum_sha256: Option<String>,
    /// Hash of the audit record
    pub audit_record: Option<String>,
    /// What could not be done (addendum, audit record), and caveats
    pub warnings: Vec<String>,
}

impl ImageVerification {
    /// Every comparison matched (exit 0). Never true when nothing was
    /// compared.
    pub fn passed(&self) -> bool {
        self.exit_code == exit_code::VERIFIED
            && matches!(self.result, VerificationResult::Matched { .. })
    }

    /// One line: "VERIFIED: ...", "COMPUTED — nothing to compare against",
    /// "HASH MISMATCH: ...", "VERIFICATION FAILED: ...".
    pub fn verdict(&self) -> String {
        match &self.result {
            VerificationResult::Matched { .. } => {
                "VERIFIED: the image matches every digest it was compared with".into()
            }
            VerificationResult::NotPossible { .. } => NOTHING_COMPARED.into(),
            VerificationResult::Mismatched { details, .. } => format!("HASH MISMATCH: {details}"),
            VerificationResult::Failed { reason } => format!("VERIFICATION FAILED: {reason}"),
        }
    }

    /// The addendum text (deterministic for a given verification).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let rule = "=".repeat(80);
        let mut row = |label: &str, value: &str| {
            out.push_str(&format!("{:<22}: {}\n", label, sanitize_line(value)));
        };
        row("Verdict", &self.verdict());
        row("Exit Code", &self.exit_code.to_string());
        row("Image", &self.image.to_string_lossy());
        if self.read_path != self.image {
            row("Read From", &self.read_path.to_string_lossy());
        }
        if self.segments.len() > 1 {
            row(
                "Segments",
                &format!(
                    "{} files, {} .. {}",
                    self.segments.len(),
                    self.segments[0].to_string_lossy(),
                    self.segments[self.segments.len() - 1].to_string_lossy()
                ),
            );
        }
        row("Format", self.format.label());
        row("Method", &self.method);
        // Same wording as the acquisition report (R9)
        let basis = if self.clock.ntp_synchronized == Some(true) {
            "NTP synchronized"
        } else {
            crate::models::provenance::LABEL_NOT_SYNCHRONIZED
        };
        row(
            "Started",
            &format!(
                "{} UTC ({basis})",
                self.started_at.format("%Y-%m-%d %H:%M:%S")
            ),
        );
        row(
            "Ended",
            &format!(
                "{} UTC ({basis})",
                self.ended_at.format("%Y-%m-%d %H:%M:%S")
            ),
        );
        row(
            "Elapsed",
            &format!("{:.1} s (monotonic clock)", self.elapsed_seconds),
        );
        if let Some(note) = &self.clock.note {
            row("Clock Note", note);
        }
        row(
            "Expected From",
            if self.expected.is_empty() {
                "(no expected digest given)"
            } else {
                &self.expected.source
            },
        );
        if let Some(outcome) = self.expected.report_outcome {
            row(
                "Report Verdict",
                &format!(
                    "{} (exit code {}) - the digests in the report describe what that acquisition read",
                    outcome.label(),
                    outcome.exit_code()
                ),
            );
        }
        for (label, digest) in self.computed.present() {
            row(&format!("Computed {label}"), digest);
        }
        for (label, digest) in self.stored.present() {
            row(&format!("Stored {label}"), digest);
        }
        for c in &self.checks {
            let status = match c.status {
                CheckStatus::Match => "MATCH".to_string(),
                CheckStatus::Mismatch => format!("MISMATCH (expected {})", c.expected),
                CheckStatus::NotComputed => format!("NOT COMPUTED (expected {})", c.expected),
            };
            row(
                &format!("Check {}", c.algorithm.label()),
                &format!("{status} [against: {}]", c.reference),
            );
        }
        if let Some(p) = &self.pieces {
            row("Pieces File", &p.pieces_file.to_string_lossy());
            row(
                "Pieces Checked",
                &format!(
                    "{} ({} of the image's {}), {} differing",
                    plural(p.pieces_checked, "piece", "pieces"),
                    format_iec(p.covered_bytes),
                    format_iec(p.image_bytes),
                    p.mismatch_count
                ),
            );
            row("Pieces Result", &p.summary());
            for m in p.mismatches.iter().take(50) {
                row(&format!("Piece {}", m.index), &m.describe());
            }
            if p.mismatch_count > 50 {
                row(
                    "Pieces",
                    &format!(
                        "... {} more differing pieces not listed here",
                        p.mismatch_count - p.mismatches.len().min(50) as u64
                    ),
                );
            }
        }
        for w in &self.warnings {
            row("Warning", w);
        }
        row(
            "dfdisk",
            &format!("{DFDISK_VERSION} (git {DFDISK_GIT_REV}, dfcore git {DFCORE_GIT_REV})"),
        );
        format!(
            "{rule}\n                   DFDISK IMAGE VERIFICATION ADDENDUM\n{rule}\n{out}{rule}\n"
        )
    }

    /// Details of the audit record.
    fn audit_details(&self) -> Map<String, serde_json::Value> {
        let mut d = Map::new();
        d.insert("read_path".into(), json!(self.read_path.to_string_lossy()));
        d.insert(
            "segments".into(),
            json!(self
                .segments
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>()),
        );
        d.insert(
            "format".into(),
            serde_json::to_value(self.format).unwrap_or_default(),
        );
        d.insert("method".into(), json!(self.method));
        d.insert("verdict".into(), json!(self.verdict()));
        d.insert("expected_from".into(), json!(self.expected.source));
        d.insert(
            "computed".into(),
            serde_json::to_value(&self.computed).unwrap_or_default(),
        );
        d.insert(
            "stored".into(),
            serde_json::to_value(&self.stored).unwrap_or_default(),
        );
        d.insert(
            "checks".into(),
            serde_json::to_value(&self.checks).unwrap_or_default(),
        );
        if let Some(p) = &self.pieces {
            d.insert(
                "pieces".into(),
                json!({
                    "file": p.pieces_file.to_string_lossy(),
                    "checked": p.pieces_checked,
                    "bytes_checked": p.bytes_checked,
                    "covered_bytes": p.covered_bytes,
                    "image_bytes": p.image_bytes,
                    "mismatches": p.mismatch_count,
                }),
            );
        }
        d.insert(
            "addendum".into(),
            json!(self
                .addendum
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())),
        );
        d.insert("addendum_sha256".into(), json!(self.addendum_sha256));
        d
    }
}

// ---------------------------------------------------------------------------
// Image families
// ---------------------------------------------------------------------------

/// Extension of an EWF segment file: E01..E99, EAA..EZZ, FAA..ZZZ, s01..,
/// L01.., Ex01.. (any case for the E/S/L leads).
fn is_ewf_extension(ext: &str) -> bool {
    let b = ext.as_bytes();
    let lead = |c: u8| matches!(c.to_ascii_lowercase(), b'e' | b's' | b'l');
    match b.len() {
        3 => {
            (lead(b[0])
                && ((b[1].is_ascii_digit() && b[2].is_ascii_digit())
                    || (b[1].is_ascii_alphabetic() && b[2].is_ascii_alphabetic())))
                || ((b'F'..=b'Z').contains(&b[0])
                    && b[1].is_ascii_uppercase()
                    && b[2].is_ascii_uppercase())
        }
        4 => {
            lead(b[0])
                && b[1].eq_ignore_ascii_case(&b'x')
                && b[2].is_ascii_digit()
                && b[3].is_ascii_digit()
        }
        _ => false,
    }
}

/// An Expert Witness Format segment: by extension (`.E01`, `.Ex01`, `.E02`,
/// `.EAA`, `.FAA`, `.s01`, `.L01`, any case) or by the EVF/LVF signature.
pub fn is_ewf_image_file(path: &Path) -> bool {
    let by_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(is_ewf_extension);
    if by_ext {
        return true;
    }
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut magic = [0u8; 6];
        if f.read_exact(&mut magic).is_ok() {
            return &magic == b"EVF\x09\x0d\x0a"
                || &magic == b"LVF\x09\x0d\x0a"
                || &magic == b"EVF2\x0d\x0a"
                || &magic == b"LEF2\x0d\x0a";
        }
    }
    false
}

/// The first segment of the EWF set `path` belongs to (`x.E05` -> `x.E01`,
/// `x.FAA` -> `x.E01`, `x.Ex02` -> `x.Ex01`), when it exists; else `path`
/// itself.
pub fn ewf_first_segment(path: &Path) -> PathBuf {
    match first_segment_name(path) {
        Some(first) if first.exists() => first,
        _ => path.to_path_buf(),
    }
}

/// Name of the first segment of the family of `path` (whether it exists or
/// not); `None` when `path` has no EWF extension.
fn first_segment_name(path: &Path) -> Option<PathBuf> {
    let ext = path.extension()?.to_str()?;
    if !is_ewf_extension(ext) {
        return None;
    }
    let b = ext.as_bytes();
    let first = if b.len() == 4 {
        format!("{}01", &ext[..2])
    } else if (b'F'..=b'Z').contains(&b[0]) {
        "E01".to_string()
    } else {
        format!("{}01", &ext[..1])
    };
    Some(path.with_extension(first))
}

/// Position of a segment extension in its family (01 = 1, ..., 99, then
/// the letter pairs), relative to the lead of the first segment.
fn segment_index(ext: &str, first_lead: u8) -> Option<u64> {
    let b = ext.as_bytes();
    match b.len() {
        3 if b[1].is_ascii_digit() && b[2].is_ascii_digit() => {
            (b[0] == first_lead).then(|| u64::from((b[1] - b'0') * 10 + (b[2] - b'0')))
        }
        3 if b[1].is_ascii_alphabetic() && b[2].is_ascii_alphabetic() => {
            let upper = first_lead.is_ascii_uppercase();
            let norm = |c: u8| {
                if upper {
                    c.is_ascii_uppercase().then_some(c)
                } else {
                    c.is_ascii_lowercase().then_some(c.to_ascii_uppercase())
                }
            };
            let lead = norm(b[0])?;
            let base = first_lead.to_ascii_uppercase();
            let (x, y) = (norm(b[1])?, norm(b[2])?);
            (lead >= base).then(|| {
                100 + u64::from(lead - base) * 676 + u64::from(x - b'A') * 26 + u64::from(y - b'A')
            })
        }
        4 if b[2].is_ascii_digit() && b[3].is_ascii_digit() => {
            (b[0] == first_lead).then(|| u64::from((b[2] - b'0') * 10 + (b[3] - b'0')))
        }
        _ => None,
    }
}

/// Every segment of the EWF family of `image`, in order. Refuses (usage)
/// a family whose first segment is missing or that has a gap.
pub fn ewf_segment_family(image: &Path) -> Result<Vec<PathBuf>, AcquisitionError> {
    let Some(first) = first_segment_name(image) else {
        // Recognised by signature only: a single file
        return Ok(vec![image.to_path_buf()]);
    };
    if !first.exists() {
        return Err(AcquisitionError::usage(format!(
            "the first segment {} of the EWF image {} is missing",
            first.display(),
            image.display()
        )));
    }
    let first_ext = first
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_string();
    let lead = first_ext.as_bytes()[0];
    let four = first_ext.len() == 4;
    let stem = first.file_stem().unwrap_or_default().to_os_string();
    let dir = first
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut found: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| AcquisitionError::failed(format!("cannot list {}: {e}", dir.display())))?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.file_stem()? != stem.as_os_str() {
                return None;
            }
            let ext = p.extension()?.to_str()?.to_string();
            if (ext.len() == 4) != four || !is_ewf_extension(&ext) {
                return None;
            }
            if four && !ext[..2].eq(&first_ext[..2]) {
                return None;
            }
            segment_index(&ext, lead).map(|i| (i, p))
        })
        .collect();
    found.sort();
    for (expected, (index, _)) in (1u64..).zip(found.iter()) {
        if *index != expected {
            return Err(AcquisitionError::usage(format!(
                "the EWF image {} has a gap: segment number {expected} is missing before {}",
                first.display(),
                found
                    .iter()
                    .find(|(i, _)| *i == *index)
                    .map(|(_, p)| p.display().to_string())
                    .unwrap_or_default()
            )));
        }
    }
    Ok(found.into_iter().map(|(_, p)| p).collect())
}

/// The parts of a split RAW image (`x.001`, `x.002`, ... or from `x.000`)
/// in order, or `[image]` for a single file. A gap is refused (usage), never
/// skipped.
pub fn raw_family(image: &Path) -> Result<Vec<PathBuf>, AcquisitionError> {
    let ext = image
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if ext.len() != 3 || !ext.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(vec![image.to_path_buf()]);
    }
    let part = |n: u32| image.with_extension(format!("{n:03}"));
    let start = if part(0).exists() { 0 } else { 1 };
    let mut parts = Vec::new();
    let mut n = start;
    while n <= 999 && part(n).is_file() {
        parts.push(part(n));
        n += 1;
    }
    if !parts.contains(&image.to_path_buf()) {
        return Err(AcquisitionError::usage(format!(
            "{} belongs to a split RAW image whose part {} is missing",
            image.display(),
            part(n).display()
        )));
    }
    if let Some(later) = (n + 1..=999).map(part).find(|p| p.exists()) {
        return Err(AcquisitionError::usage(format!(
            "the split RAW image {} has a gap: {} is missing before {}",
            part(start).display(),
            part(n).display(),
            later.display()
        )));
    }
    Ok(parts)
}

/// `<dir>/<base>.verify-<UTC>.txt` for an image `<dir>/<base>.<ext>`.
pub fn addendum_path(image: &Path, when: DateTime<Utc>) -> PathBuf {
    let dir = image.parent().unwrap_or_else(|| Path::new("."));
    let base = image
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    dir.join(format!(
        "{base}.verify-{}.txt",
        when.format("%Y%m%dT%H%M%SZ")
    ))
}

/// Write `text` to a new file (never overwriting), fsync it and its directory.
fn write_new_file(path: &Path, text: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    if let Some(dir) = path.parent() {
        sync_dir(if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        })?;
    }
    Ok(())
}

/// What a verification reports while it runs.
#[derive(Debug, Clone)]
pub enum VerifyEvent {
    /// Progress of a pass dfdisk reads itself (RAW hashing, pieces)
    Progress(HashProgress),
    /// A line ewfverify printed (stderr and progress)
    ToolOutput(String),
}

/// What [`verify_image`] writes and checks besides the digests.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Write `<base>.verify-<UTC>.txt` next to the image
    pub write_addendum: bool,
    /// Audit log for the `image_verification` record; `None`: no record
    pub audit_log: Option<PathBuf>,
    /// Records the ewfverify command line
    pub recorder: Option<ProvenanceRecorder>,
    /// Re-check a RAW image against this piecewise SHA-256 file
    /// (`<base>.pieces.tsv`, `dfdisk verify --pieces`)
    pub pieces: Option<PathBuf>,
}

impl VerifyOptions {
    /// Addendum and audit record on this host's log (CLI, TUI).
    pub fn recorded() -> Self {
        Self {
            write_addendum: true,
            audit_log: Some(audit::log_path()),
            ..Default::default()
        }
    }

    /// The same options with a pieces file to check.
    pub fn with_pieces(mut self, pieces: impl Into<PathBuf>) -> Self {
        self.pieces = Some(pieces.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// MD5, SHA-1 and SHA-256 of `files` read as one stream, after asking the
/// kernel to drop their cached pages (blocking). `progress(done, total)`.
pub fn hash_files(
    files: &[PathBuf],
    abort: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<HashResults, AcquisitionError> {
    use std::os::unix::io::AsRawFd;
    let total: u64 = files
        .iter()
        .map(|f| std::fs::metadata(f).map(|m| m.len()).unwrap_or(0))
        .sum();
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut done = 0u64;
    for path in files {
        let mut f = std::fs::File::open(path).map_err(|e| {
            AcquisitionError::failed(format!("cannot open {}: {e}", path.display()))
        })?;
        // SAFETY: advisory call on a descriptor we own
        unsafe {
            libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
        }
        loop {
            if abort.load(Ordering::SeqCst) {
                return Err(AcquisitionError::aborted("verification aborted"));
            }
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(AcquisitionError::failed(format!(
                        "cannot read {} at offset {}: {e}",
                        path.display(),
                        done
                    )))
                }
            };
            md5.update(&buf[..n]);
            sha1.update(&buf[..n]);
            sha256.update(&buf[..n]);
            done += n as u64;
            progress(done, total);
        }
    }
    Ok(HashResults {
        md5: Some(hex::encode(md5.finalize())),
        sha1: Some(hex::encode(sha1.finalize())),
        sha256: Some(hex::encode(sha256.finalize())),
    })
}

/// Run `work` on a blocking thread, forwarding `(done, total)` progress.
async fn blocking_with_progress<T: Send + 'static>(
    work: impl FnOnce(&mut dyn FnMut(u64, u64)) -> Result<T, AcquisitionError> + Send + 'static,
    on_event: &mut impl FnMut(VerifyEvent),
) -> Result<T, AcquisitionError> {
    let (tx, mut rx) = mpsc::channel::<HashProgress>(64);
    let task = tokio::task::spawn_blocking(move || {
        let t0 = Instant::now();
        let mut last: Option<Instant> = None;
        let mut report = |done: u64, total: u64| {
            if last.is_some_and(|l| l.elapsed().as_millis() < 200) && done < total {
                return;
            }
            last = Some(Instant::now());
            let secs = t0.elapsed().as_secs_f64();
            let _ = tx.try_send(HashProgress {
                bytes_hashed: done,
                total_bytes: total,
                speed_bps: if secs > 0.0 { done as f64 / secs } else { 0.0 },
                percentage: if total > 0 {
                    (done as f64 * 100.0 / total as f64).min(100.0)
                } else {
                    100.0
                },
            });
        };
        work(&mut report)
    });
    while let Some(p) = rx.recv().await {
        on_event(VerifyEvent::Progress(p));
    }
    task.await
        .map_err(|e| AcquisitionError::failed(format!("the verification task failed: {e}")))?
}

/// ewfverify over the first segment: its report and, when it failed, why.
async fn run_ewfverify(
    first: &Path,
    options: &VerifyOptions,
    stop: &StopFlags,
    on_event: &mut impl FnMut(VerifyEvent),
) -> Result<(EwfverifyReport, Option<String>), AcquisitionError> {
    let spec = ProcessSpec::new("ewfverify")
        .args(["-d", EWF_DIGESTS])
        .arg(first)
        .grace(std::time::Duration::from_secs(5));
    let mut parser = EwfverifyParser::new();
    let outcome = process::run(
        &spec,
        &stop.stop_control(),
        options.recorder.as_ref(),
        |ev| {
            if let ProcessEvent::Line { stream, text, .. } = ev {
                parser.feed(stream, text);
                let t = text.trim();
                if !t.is_empty()
                    && (stream == process::StreamTag::Stderr || t.starts_with("Status:"))
                {
                    on_event(VerifyEvent::ToolOutput(t.to_string()));
                }
            }
        },
    )
    .await
    .map_err(|e| {
        AcquisitionError::failed(format!("cannot run ewfverify (is libewf installed?): {e}"))
    })?;
    if outcome.aborted || outcome.force_killed {
        return Err(AcquisitionError::aborted("verification aborted"));
    }
    let report = parser.finish();
    if let (Some(r), Some(v)) = (&options.recorder, &report.version) {
        r.set_tool_version("ewfverify", v);
    }
    let failure = if !outcome.success() || report.status != Some(ToolStatus::Success) {
        Some(format!(
            "ewfverify reported an error in the EWF structure or media checksums ({}){}",
            outcome.record.status_text(),
            report
                .validation_summary()
                .or_else(|| report.diagnostics.first().cloned())
                .map(|d| format!(": {d}"))
                .unwrap_or_default()
        ))
    } else {
        report.validation_summary()
    };
    Ok((report, failure))
}

/// The pieces file check folded into `result`: a differing piece, or image
/// bytes the pieces file does not cover, is a mismatch; a pieces file that
/// lists nothing cannot vouch for anything (failed); a pieces file that
/// covers the image exactly and matches is a comparison.
fn with_pieces(
    result: VerificationResult,
    pieces: &PiecesReport,
    method: &mut String,
) -> VerificationResult {
    let file = pieces.pieces_file.display().to_string();
    if pieces.mismatch_count > 0 || (pieces.pieces_checked > 0 && pieces.uncovered_bytes() > 0) {
        let details = format!("piecewise SHA-256 against {file}: {}", pieces.details(10));
        return match result {
            VerificationResult::Mismatched { method, details: d } => {
                VerificationResult::Mismatched {
                    method,
                    details: format!("{d}; {details}"),
                }
            }
            _ => VerificationResult::Mismatched {
                method: method.clone(),
                details,
            },
        };
    }
    if !pieces.all_match() {
        return match result {
            VerificationResult::Mismatched { .. } => result,
            _ => VerificationResult::Failed {
                reason: format!("{file} lists no piece to check"),
            },
        };
    }
    method.push_str(&format!(
        " + piecewise SHA-256 ({} from {file})",
        plural(pieces.pieces_checked, "piece", "pieces")
    ));
    match result {
        VerificationResult::NotPossible { .. } | VerificationResult::Matched { .. } => {
            VerificationResult::Matched {
                method: method.clone(),
            }
        }
        other => other,
    }
}

/// Re-verify `image` against `expected` (and, for EWF, against the digests
/// the image stores; with `options.pieces`, against a pieces file). `Err`
/// only when the image could not be read at all (missing file, gap in a
/// segment family, pieces on an EWF image: usage; tool missing or read
/// error: failed; abort: aborted); a failing or mismatching image is an `Ok`
/// result with its exit code.
pub async fn verify_image(
    image: &Path,
    expected: &ExpectedHashes,
    options: &VerifyOptions,
    stop: &StopFlags,
    mut on_event: impl FnMut(VerifyEvent),
) -> Result<ImageVerification, AcquisitionError> {
    if !image.is_file() {
        return Err(AcquisitionError::usage(format!(
            "image not found or not a regular file: {}",
            image.display()
        )));
    }
    let ewf_image = is_ewf_image_file(image);
    if ewf_image && options.pieces.is_some() {
        return Err(AcquisitionError::usage(
            "a pieces file holds digests of a RAW image's bytes; it cannot be checked against an EWF image (convert it to RAW first)",
        ));
    }
    if let Some(p) = &options.pieces {
        if !p.is_file() {
            return Err(AcquisitionError::usage(format!(
                "pieces file not found: {}",
                p.display()
            )));
        }
    }
    let segments = if ewf_image {
        ewf_segment_family(image)?
    } else {
        raw_family(image)?
    };
    let mut warnings = Vec::new();
    if !expected.report_image_files.is_empty() {
        let name = image.file_name().map(|n| n.to_string_lossy().into_owned());
        let listed = expected.report_image_files.iter().any(|f| {
            Path::new(f)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                == name
        });
        if !listed {
            warnings.push(format!(
                "{} is not among the image files the report {} lists",
                image.display(),
                expected.source
            ));
        }
    }

    let clock = tokio::task::spawn_blocking(ClockInfo::capture_start)
        .await
        .unwrap_or_default();
    let t0 = Instant::now();
    let started_at = clock.start_utc;

    let (format, read_path, mut method, computed, stored, tool_failure) = if ewf_image {
        let first = segments[0].clone();
        let (report, failure) = run_ewfverify(&first, options, stop, &mut on_event).await?;
        (
            VerifiedFormat::Ewf,
            first,
            format!("ewfverify -d {EWF_DIGESTS}"),
            report.calculated,
            report.stored,
            failure,
        )
    } else {
        let files = segments.clone();
        let abort = stop.abort.clone();
        let computed = blocking_with_progress(
            move |progress| hash_files(&files, &abort, progress),
            &mut on_event,
        )
        .await?;
        (
            VerifiedFormat::Raw,
            segments[0].clone(),
            format!(
                "{} hashed by dfdisk (MD5, SHA-1, SHA-256) after asking the kernel to drop cached pages (POSIX_FADV_DONTNEED)",
                if segments.len() > 1 {
                    format!("{} parts read as one stream and", segments.len())
                } else {
                    "file content".to_string()
                }
            ),
            computed,
            HashResults::default(),
            None,
        )
    };

    let stored_reference = ExpectedHashes::stored_in_image(&stored);
    let mut references: Vec<&ExpectedHashes> = Vec::new();
    if !expected.is_empty() {
        references.push(expected);
    }
    if !stored_reference.is_empty() {
        references.push(&stored_reference);
    }
    let (checks, mut result) =
        decide_against(&computed, &references, tool_failure.as_deref(), &method);

    let mut pieces_report = None;
    if let Some(tsv) = &options.pieces {
        let recorded = expected
            .report_pieces
            .as_ref()
            .filter(|(file, _)| Path::new(file).file_name() == tsv.file_name());
        let file_digest = sha256_file(tsv)
            .map_err(|e| AcquisitionError::failed(format!("cannot read {}: {e}", tsv.display())))?;
        match recorded {
            Some((_, want)) if !want.eq_ignore_ascii_case(&file_digest) => {
                result = match result {
                    VerificationResult::Mismatched { .. } => result,
                    _ => VerificationResult::Failed {
                        reason: format!(
                            "the pieces file {} has SHA-256 {file_digest}, the report recorded {want}; it was not used",
                            tsv.display()
                        ),
                    },
                };
            }
            _ => {
                let files = segments.clone();
                let tsv_path = tsv.clone();
                let abort: Arc<AtomicBool> = stop.abort.clone();
                let total: u64 = files
                    .iter()
                    .map(|f| std::fs::metadata(f).map(|m| m.len()).unwrap_or(0))
                    .sum();
                let checked = blocking_with_progress(
                    move |progress| {
                        pieces::verify_pieces(&files, &tsv_path, &abort, |done| {
                            progress(done, total)
                        })
                    },
                    &mut on_event,
                )
                .await;
                match checked {
                    Ok(p) => {
                        result = with_pieces(result, &p, &mut method);
                        pieces_report = Some(p);
                    }
                    Err(e) if e.kind == ErrorKind::Aborted || stop.is_aborted() => {
                        return Err(AcquisitionError::aborted("verification aborted"))
                    }
                    Err(e) => {
                        if !matches!(result, VerificationResult::Mismatched { .. }) {
                            result = VerificationResult::Failed {
                                reason: format!(
                                    "the pieces file {} could not be checked: {}",
                                    tsv.display(),
                                    e.message
                                ),
                            };
                        }
                    }
                }
            }
        }
    }
    if expected.is_empty() && stored_reference.is_empty() && options.pieces.is_none() {
        warnings.push(
            "no expected digest was given and the image stores none: the digests were computed but not compared"
                .into(),
        );
    }

    let mut clock = clock;
    let elapsed = t0.elapsed();
    clock.finish(elapsed);
    let mut v = ImageVerification {
        image: image.to_path_buf(),
        read_path,
        segments,
        format,
        method,
        computed,
        stored,
        expected: expected.clone(),
        checks,
        pieces: pieces_report,
        exit_code: verification_exit_code(&result),
        result,
        started_at,
        ended_at: clock.end_utc.unwrap_or_else(Utc::now),
        elapsed_seconds: elapsed.as_secs_f64(),
        clock,
        addendum: None,
        addendum_sha256: None,
        audit_record: None,
        warnings,
    };

    if options.write_addendum {
        // Never overwrite: a name taken by a verification in the same second
        // waits for the next second (the name format is fixed, §9)
        let text = v.render_text();
        let mut when = v.ended_at;
        let mut result = Err(std::io::Error::other("not attempted"));
        let mut path = addendum_path(image, when);
        for _ in 0..3 {
            path = addendum_path(image, when);
            result = write_new_file(&path, &text);
            match &result {
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                    when = Utc::now();
                }
                _ => break,
            }
        }
        match result {
            Ok(()) => {
                v.addendum_sha256 = sha256_file(&path).ok();
                v.addendum = Some(path);
            }
            Err(e) => v.warnings.push(format!(
                "the addendum {} was not written: {e}",
                path.display()
            )),
        }
    }
    if let Some(log) = &options.audit_log {
        match audit::image_verification(log, image, &v.result, v.exit_code, v.audit_details()) {
            Ok(hash) => v.audit_record = Some(hash),
            Err(reason) => v
                .warnings
                .push(format!("the audit record was not written: {reason}")),
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::ewf::parse_ewfverify;

    const MD5: &str = "5eb63bbbe01eeed093cb22bb8f5acdc3";
    const SHA1: &str = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
    const SHA256: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn computed_md5_sha256() -> HashResults {
        HashResults {
            md5: Some(MD5.into()),
            sha1: None,
            sha256: Some(SHA256.into()),
        }
    }

    #[test]
    fn requested_digest_that_was_not_computed_fails() {
        // Bug fixed: SHA-1 requested, the reader did not compute it -> never PASSED
        let expected = ExpectedHashes::given(Some(MD5.into()), Some(SHA1.into()), None);
        let (checks, result) = decide(&computed_md5_sha256(), &expected, None, "ewfverify");
        assert!(
            matches!(result, VerificationResult::Failed { .. }),
            "{result:?}"
        );
        assert_eq!(verification_exit_code(&result), 4);
        assert_eq!(checks[0].status, CheckStatus::Match);
        assert_eq!(checks[1].status, CheckStatus::NotComputed);
        assert_eq!(checks[1].reference, "command line");
        let VerificationResult::Failed { reason } = result else {
            panic!()
        };
        assert!(
            reason.contains("SHA-1 was requested but not computed"),
            "{reason}"
        );
    }

    #[test]
    fn decision_rules() {
        let c = computed_md5_sha256();
        // Match, case-insensitive
        let (_, r) = decide(
            &c,
            &ExpectedHashes::given(Some(MD5.to_uppercase()), None, None),
            None,
            "m",
        );
        assert!(r.is_matched());
        assert_eq!(verification_exit_code(&r), 0);
        // Mismatch beats not computed
        let e = ExpectedHashes::given(Some("0".repeat(32)), Some(SHA1.into()), None);
        let (_, r) = decide(&c, &e, None, "m");
        assert!(matches!(r, VerificationResult::Mismatched { .. }));
        assert_eq!(verification_exit_code(&r), 5);
        // Nothing expected: computed only, nothing compared -> exit 9
        // (decision 1), never a pass
        let (checks, r) = decide(
            &c,
            &ExpectedHashes::given(None, Some("  ".into()), None),
            None,
            "m",
        );
        assert!(checks.is_empty());
        assert!(matches!(r, VerificationResult::NotPossible { .. }));
        assert_eq!(verification_exit_code(&r), 9);
        // A tool failure is a failure even when the digests match
        let (_, r) = decide(
            &c,
            &ExpectedHashes::given(Some(MD5.into()), None, None),
            Some("ewfverify FAILURE"),
            "m",
        );
        assert!(matches!(r, VerificationResult::Failed { .. }));
        // ... but a provable difference stays a mismatch
        let (_, r) = decide(
            &c,
            &ExpectedHashes::given(Some("0".repeat(32)), None, None),
            Some("ewfverify FAILURE"),
            "m",
        );
        let VerificationResult::Mismatched { details, .. } = r else {
            panic!("{r:?}")
        };
        assert!(details.contains("ewfverify FAILURE"), "{details}");
    }

    #[test]
    fn exit_code_of_every_result() {
        let cases = [
            (VerificationResult::Matched { method: "m".into() }, 0),
            (
                VerificationResult::Mismatched {
                    method: "m".into(),
                    details: "d".into(),
                },
                5,
            ),
            (VerificationResult::Failed { reason: "r".into() }, 4),
            (VerificationResult::NotPossible { reason: "r".into() }, 9),
        ];
        for (result, code) in cases {
            assert_eq!(verification_exit_code(&result), code, "{result:?}");
        }
        assert_eq!(exit_code::UNVERIFIED, 9);
    }

    #[test]
    fn stored_ewf_digests_count_as_compared() {
        // Real ewfverify output of libewf 20231119 and 20140816 (legacy)
        let clean = [
            include_str!("../../tests/fixtures/ewf/clean/ewfverify.stdout"),
            include_str!("../../tests/fixtures/ewf/legacy/clean/ewfverify.stdout"),
        ];
        let tampered = [
            include_str!("../../tests/fixtures/ewf/tampered/ewfverify.stdout"),
            include_str!("../../tests/fixtures/ewf/legacy/tampered/ewfverify.stdout"),
        ];
        for (clean, tampered) in clean.into_iter().zip(tampered) {
            let report = parse_ewfverify(clean, "");
            let stored = ExpectedHashes::stored_in_image(&report.stored);
            // EnCase 6 stores MD5 and SHA-1, never SHA-256 ("N/A")
            assert_eq!(
                stored.selection().algorithms(),
                [HashAlgorithm::MD5, HashAlgorithm::SHA1]
            );
            let (checks, r) = decide_against(&report.calculated, &[&stored], None, "ewfverify");
            assert!(r.is_matched(), "{r:?}");
            assert_eq!(checks[0].reference, STORED_IN_IMAGE);
            assert_eq!(verification_exit_code(&r), 0);

            // Tampered image: stored and recomputed differ
            let report = parse_ewfverify(tampered, "");
            let stored = ExpectedHashes::stored_in_image(&report.stored);
            let (checks, r) = decide_against(
                &report.calculated,
                &[&stored],
                Some("ewfverify FAILURE"),
                "ewfverify",
            );
            assert!(matches!(r, VerificationResult::Mismatched { .. }), "{r:?}");
            assert_eq!(verification_exit_code(&r), 5);
            assert!(checks.iter().all(|c| c.status == CheckStatus::Mismatch));
        }
    }

    #[test]
    fn ewf_segments_are_recognised() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "a.E01", "a.e01", "a.Ex01", "a.E02", "a.EAB", "a.FAA", "a.s01", "a.L01", "a.ex02",
        ] {
            assert!(is_ewf_image_file(&tmp.path().join(name)), "{name}");
        }
        for name in [
            "a.raw", "a.dd", "a.info", "a.E1", "a.E001", "a.Exx1", "a", "a.old", "a.001",
        ] {
            let p = tmp.path().join(name);
            std::fs::write(&p, b"not ewf").unwrap();
            assert!(!is_ewf_image_file(&p), "{name}");
        }
        // Signature without an EWF extension
        let p = tmp.path().join("evidence.img");
        std::fs::write(&p, b"EVF\x09\x0d\x0a\xff\x00rest").unwrap();
        assert!(is_ewf_image_file(&p));
        let p = tmp.path().join("evidence2.bin");
        std::fs::write(&p, b"EVF2\x0d\x0a\x81\x00rest").unwrap();
        assert!(is_ewf_image_file(&p));

        // Later segments resolve to the first one when it exists
        std::fs::write(tmp.path().join("x.E01"), b"").unwrap();
        assert_eq!(
            ewf_first_segment(&tmp.path().join("x.E03")),
            tmp.path().join("x.E01")
        );
        assert_eq!(
            ewf_first_segment(&tmp.path().join("x.EAB")),
            tmp.path().join("x.E01")
        );
        assert_eq!(
            ewf_first_segment(&tmp.path().join("x.FAA")),
            tmp.path().join("x.E01")
        );
        std::fs::write(tmp.path().join("y.Ex01"), b"").unwrap();
        assert_eq!(
            ewf_first_segment(&tmp.path().join("y.Ex02")),
            tmp.path().join("y.Ex01")
        );
        assert_eq!(
            ewf_first_segment(&tmp.path().join("z.E02")),
            tmp.path().join("z.E02")
        );
    }

    #[test]
    fn ewf_families_are_complete_or_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let mut names: Vec<String> = (1..=99).map(|n| format!("img.E{n:02}")).collect();
        names.extend(["img.EAA", "img.EAB"].map(String::from));
        for n in &names {
            std::fs::write(d.join(n), b"").unwrap();
        }
        std::fs::write(d.join("img.info"), b"").unwrap();
        std::fs::write(d.join("other.E02"), b"").unwrap();
        let family = ewf_segment_family(&d.join("img.E50")).unwrap();
        assert_eq!(family.len(), 101);
        assert_eq!(family[0], d.join("img.E01"));
        assert_eq!(family[99], d.join("img.EAA"));
        assert_eq!(family[100], d.join("img.EAB"));

        std::fs::remove_file(d.join("img.E07")).unwrap();
        let err = ewf_segment_family(&d.join("img.E01")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Usage);
        assert!(err.message.contains("segment number 7 is missing"), "{err}");

        let err = ewf_segment_family(&d.join("other.E02")).unwrap_err();
        assert!(err.message.contains("first segment"), "{err}");

        std::fs::write(d.join("solo.E01"), b"").unwrap();
        assert_eq!(
            ewf_segment_family(&d.join("solo.E01")).unwrap(),
            [d.join("solo.E01")]
        );
        assert_eq!(segment_index("FAA", b'E'), Some(100 + 676));
        assert_eq!(segment_index("s05", b's'), Some(5));
        assert_eq!(segment_index("Ex12", b'E'), Some(12));
    }

    #[test]
    fn split_raw_families() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for n in 1..=3 {
            std::fs::write(d.join(format!("x.{n:03}")), b"").unwrap();
        }
        let parts = raw_family(&d.join("x.002")).unwrap();
        assert_eq!(parts, [d.join("x.001"), d.join("x.002"), d.join("x.003")]);
        // A gap is refused
        std::fs::write(d.join("x.005"), b"").unwrap();
        let err = raw_family(&d.join("x.001")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Usage);
        assert!(err.message.contains("x.004 is missing"), "{err}");
        // Starting at .000
        for n in 0..=1 {
            std::fs::write(d.join(format!("y.{n:03}")), b"").unwrap();
        }
        assert_eq!(raw_family(&d.join("y.001")).unwrap().len(), 2);
        // Not a family
        assert_eq!(raw_family(&d.join("z.raw")).unwrap(), [d.join("z.raw")]);
    }

    #[test]
    fn expected_digests_from_a_report() {
        use crate::models::config::{AcquisitionConfig, EffectiveConfig, EngineKind};
        let src = crate::models::identity::SourceIdentity::default();
        let mut r = ForensicInfoReport::new(
            EngineKind::Rescue,
            &Default::default(),
            src,
            EffectiveConfig::build(&AcquisitionConfig::rescue("/o"), None),
        );
        r.image_hashes.sha256 = Some(SHA256.into());
        let e = ExpectedHashes::from_report(&r, "x.info.json");
        assert_eq!(e.sha256.as_deref(), Some(SHA256));
        assert_eq!(e.source, "x.info.json");
        assert_eq!(e.report_outcome, Some(r.outcome));
        r.acquisition_hashes.md5 = Some(MD5.into());
        r.image_files = vec!["/o/x.raw".into()];
        let e = ExpectedHashes::from_report(&r, "x.info.json");
        assert_eq!(e.md5.as_deref(), Some(MD5));
        assert_eq!(e.sha256, None);
        assert_eq!(e.report_image_files, ["/o/x.raw"]);
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("r.info.json");
        std::fs::write(&p, r.to_json()).unwrap();
        assert_eq!(
            ExpectedHashes::from_report_json(&p).unwrap().md5.as_deref(),
            Some(MD5)
        );
        std::fs::write(&p, "{}").unwrap();
        assert_eq!(
            ExpectedHashes::from_report_json(&p).unwrap_err().kind,
            ErrorKind::Usage
        );
    }

    fn opts(log: &Path) -> VerifyOptions {
        VerifyOptions {
            write_addendum: true,
            audit_log: Some(log.to_path_buf()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn raw_verification_writes_addendum_and_audit_record() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("case_ea01_ev1_SER.raw");
        std::fs::write(&image, b"hello world").unwrap();
        let log = tmp.path().join("audit.jsonl");
        let options = opts(&log);
        let expected = ExpectedHashes::given(Some(MD5.into()), None, Some(SHA256.into()));
        let mut events = 0;
        let v = verify_image(&image, &expected, &options, &StopFlags::new(), |_| {
            events += 1
        })
        .await
        .unwrap();
        assert!(v.passed(), "{:?}", v.result);
        assert_eq!(v.exit_code, 0);
        assert_eq!(v.computed.sha1.as_deref(), Some(SHA1));
        assert!(events > 0);
        let addendum = v.addendum.clone().unwrap();
        let name = addendum.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("case_ea01_ev1_SER.verify-") && name.ends_with("Z.txt"),
            "{name}"
        );
        let text = std::fs::read_to_string(&addendum).unwrap();
        assert!(text.contains("VERIFIED"), "{text}");
        assert!(text.contains("Check SHA-256"), "{text}");
        assert!(text.contains("[against: command line]"), "{text}");
        assert_eq!(
            v.addendum_sha256.as_deref(),
            Some(sha256_file(&addendum).unwrap().as_str())
        );
        let rec: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&log)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rec["action"], "image_verification");
        assert_eq!(rec["details"]["exit_code"], 0);
        assert_eq!(rec["hash"], json!(v.audit_record));

        // Mismatch: exit 5, still recorded
        let bad = ExpectedHashes::given(Some("0".repeat(32)), None, None);
        let opts = VerifyOptions {
            write_addendum: false,
            ..options
        };
        let v = verify_image(&image, &bad, &opts, &StopFlags::new(), |_| {})
            .await
            .unwrap();
        assert_eq!(v.exit_code, 5);
        assert!(!v.passed());
        assert!(v.verdict().starts_with("HASH MISMATCH"));
        // Missing image: usage error; abort: aborted
        let e = verify_image(
            &tmp.path().join("none.raw"),
            &bad,
            &opts,
            &StopFlags::new(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Usage);
        let stop = StopFlags::new();
        stop.abort.store(true, std::sync::atomic::Ordering::SeqCst);
        let e = verify_image(&image, &bad, &opts, &stop, |_| {})
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Aborted);
    }

    #[tokio::test]
    async fn nothing_to_compare_is_exit_9_and_never_passed() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("img.raw");
        std::fs::write(&image, b"hello world").unwrap();
        let log = tmp.path().join("audit.jsonl");
        let v = verify_image(
            &image,
            &ExpectedHashes::given(None, None, None),
            &opts(&log),
            &StopFlags::new(),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(v.exit_code, 9);
        assert!(!v.passed());
        assert_eq!(v.verdict(), NOTHING_COMPARED);
        assert_eq!(v.computed.md5.as_deref(), Some(MD5));
        let text = std::fs::read_to_string(v.addendum.unwrap()).unwrap();
        assert!(text.contains(NOTHING_COMPARED), "{text}");
        assert!(!text.contains("VERIFIED"), "{text}");
        let rec: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&log).unwrap().trim()).unwrap();
        assert_eq!(rec["details"]["exit_code"], 9);
        assert_eq!(rec["details"]["verdict"], NOTHING_COMPARED);
    }

    #[tokio::test]
    async fn split_raw_is_hashed_as_one_stream() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("x.001"), b"hello ").unwrap();
        std::fs::write(tmp.path().join("x.002"), b"world").unwrap();
        let expected = ExpectedHashes::given(Some(MD5.into()), Some(SHA1.into()), None);
        let options = VerifyOptions::default();
        let v = verify_image(
            &tmp.path().join("x.002"),
            &expected,
            &options,
            &StopFlags::new(),
            |_| {},
        )
        .await
        .unwrap();
        assert!(v.passed(), "{:?}", v.result);
        assert_eq!(v.segments.len(), 2);
        assert_eq!(v.read_path, tmp.path().join("x.001"));
        assert!(v.method.contains("2 parts"), "{}", v.method);
        // Pieces apply to RAW only
        std::fs::write(tmp.path().join("img.E01"), b"EVF").unwrap();
        let err = verify_image(
            &tmp.path().join("img.E01"),
            &expected,
            &VerifyOptions::default().with_pieces(tmp.path().join("p.tsv")),
            &StopFlags::new(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Usage);
    }

    #[test]
    fn pieces_fold_into_the_verdict() {
        use crate::engines::pieces::PieceMismatch;
        let ok = PiecesReport {
            pieces_file: "x.pieces.tsv".into(),
            pieces_checked: 4,
            bytes_checked: 4096,
            mismatches: vec![],
            mismatch_count: 0,
            covered_bytes: 4096,
            image_bytes: 4096,
        };
        let mut method = "file hashed".to_string();
        let r = with_pieces(
            VerificationResult::NotPossible { reason: "r".into() },
            &ok,
            &mut method,
        );
        assert!(r.is_matched(), "{r:?}");
        assert!(method.contains("4 pieces"), "{method}");
        let bad = PiecesReport {
            mismatches: vec![PieceMismatch {
                index: 2,
                offset: 2048,
                length: 1024,
                expected_sha256: "a".repeat(64),
                computed_sha256: "b".repeat(64),
                bytes_present: 1024,
            }],
            mismatch_count: 1,
            ..ok.clone()
        };
        let r = with_pieces(
            VerificationResult::Matched { method: "m".into() },
            &bad,
            &mut "m".to_string(),
        );
        let VerificationResult::Mismatched { details, .. } = r else {
            panic!("{r:?}")
        };
        assert!(details.contains("piece 2 (bytes 2048-3071)"), "{details}");
        // Image bytes after the last piece are not vouched for
        let short = PiecesReport {
            image_bytes: 5000,
            ..ok.clone()
        };
        let r = with_pieces(
            VerificationResult::NotPossible { reason: "r".into() },
            &short,
            &mut "m".to_string(),
        );
        let VerificationResult::Mismatched { details, .. } = r else {
            panic!("{r:?}")
        };
        assert!(
            details.contains("904 bytes after the last piece"),
            "{details}"
        );
        let empty = PiecesReport {
            pieces_checked: 0,
            covered_bytes: 0,
            ..ok
        };
        let r = with_pieces(
            VerificationResult::Matched { method: "m".into() },
            &empty,
            &mut "m".to_string(),
        );
        assert!(matches!(r, VerificationResult::Failed { .. }), "{r:?}");
    }
}
