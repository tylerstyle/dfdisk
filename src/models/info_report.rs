//! The forensic report of an acquisition (schema 2, §3): `<base>.info` for
//! people and its machine-readable twin `<base>.info.json`, both written
//! atomically and fsynced ([`ForensicInfoReport::write_reports`]).
//!
//! The text starts with the verdict, which comes only from
//! [`classify`](crate::models::outcome::classify) over the facts in the report
//! (P1). Every value is sanitised for terminals; "ALL HASHES MATCH" appears
//! only for [`Outcome::Verified`]; timestamps say whether the clock was
//! NTP-synchronised (R9).

use crate::models::capacity::CapacityInfo;
use crate::models::case::CaseMetadata;
use crate::models::config::{EffectiveConfig, EngineKind, HashAlgorithm};
use crate::models::device::SmartSnapshot;
use crate::models::identity::SourceIdentity;
use crate::models::outcome::{
    classify_detailed, AcquisitionFacts, Outcome, RangeKind, ReadErrorTable, VerificationResult,
};
use crate::models::protection::WriteProtection;
use crate::models::provenance::{ClockInfo, ToolProvenance};
use crate::models::text::{format_iec, plural, sanitize_line};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub use crate::models::config::HashSelection;

/// Schema of `<base>.info.json`.
pub const REPORT_SCHEMA_VERSION: u32 = 2;
/// Suffix of the text report.
pub const INFO_SUFFIX: &str = ".info";
/// Suffix of the JSON report.
pub const INFO_JSON_SUFFIX: &str = ".info.json";
/// Suffix of the space reservation file deleted right before the reports are
/// written, so a full destination still gets its report (§3, R11).
pub const RESERVE_SUFFIX: &str = ".info.reserve";
/// Size of the reservation file.
pub const RESERVE_BYTES: u64 = 1 << 20;
/// Read-error ranges listed in the text report; the JSON has all of them.
pub const TEXT_RANGE_LIMIT: usize = 200;

const RULE: &str =
    "================================================================================\n";
const LABEL_WIDTH: usize = 22;

/// Digests of one byte stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashResults {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

impl HashResults {
    pub fn get(&self, algorithm: HashAlgorithm) -> Option<&str> {
        match algorithm {
            HashAlgorithm::MD5 => self.md5.as_deref(),
            HashAlgorithm::SHA1 => self.sha1.as_deref(),
            HashAlgorithm::SHA256 => self.sha256.as_deref(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.md5.is_none() && self.sha1.is_none() && self.sha256.is_none()
    }

    /// (label, digest) of the digests present.
    pub fn present(&self) -> Vec<(&'static str, &str)> {
        [
            HashAlgorithm::MD5,
            HashAlgorithm::SHA1,
            HashAlgorithm::SHA256,
        ]
        .into_iter()
        .filter_map(|a| self.get(a).map(|d| (a.label(), d)))
        .collect()
    }
}

/// Compare the selected digests of the acquisition stream with those
/// recomputed by `method`. Unselected digests are ignored (so disabling one
/// never causes a mismatch); a selected digest missing on either side, or no
/// selected digest at all, is `Failed`; any difference is `Mismatched`.
pub fn compare_digests(
    selection: HashSelection,
    acquisition: &HashResults,
    image: &HashResults,
    method: &str,
) -> VerificationResult {
    compare_digest_sets(
        selection,
        ("acquisition", acquisition),
        ("recomputed", image),
        method,
    )
}

/// [`compare_digests`] with the two sides named by what they are (e.g.
/// `("image", ..)` and `("second read", ..)`), so a mismatch says what was
/// compared: "MD5 image <a> but second read <b>".
pub fn compare_digest_sets(
    selection: HashSelection,
    (reference_name, reference): (&str, &HashResults),
    (recomputed_name, recomputed): (&str, &HashResults),
    method: &str,
) -> VerificationResult {
    if selection.is_empty() {
        return VerificationResult::Failed {
            reason: "no digest was selected".into(),
        };
    }
    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    for alg in selection.algorithms() {
        match (reference.get(alg), recomputed.get(alg)) {
            (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => mismatches.push(format!(
                "{} {reference_name} {a} but {recomputed_name} {b}",
                alg.label(),
            )),
            (Some(_), Some(_)) => {}
            (None, _) if reference_name == "acquisition" => missing.push(format!(
                "{} was not computed during the acquisition",
                alg.label()
            )),
            (None, _) => missing.push(format!("{} has no {reference_name} digest", alg.label())),
            (_, None) if recomputed_name == "recomputed" => {
                missing.push(format!("{} was not recomputed", alg.label()))
            }
            (_, None) => missing.push(format!("{} has no {recomputed_name} digest", alg.label())),
        }
    }
    if !mismatches.is_empty() {
        VerificationResult::Mismatched {
            method: method.to_string(),
            details: mismatches.join("; "),
        }
    } else if !missing.is_empty() {
        VerificationResult::Failed {
            reason: missing.join("; "),
        }
    } else {
        VerificationResult::Matched {
            method: method.to_string(),
        }
    }
}

/// How the acquisition was verified.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationInfo {
    /// The verification as a whole: the image re-read combined with the
    /// second source read (`--verify-source`), or why there is none
    pub result: VerificationResult,
    /// e.g. "ewfverify -d md5,sha256 after flush and cache eviction"
    pub method: String,
    /// Second read of the source (`--verify-source`) against the acquisition
    pub source_reread: Option<VerificationResult>,
    /// The verification of the written image alone (its re-read, after the
    /// flush), before the second source read was taken into account; `None`
    /// in reports written before this field existed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<VerificationResult>,
}

/// Piecewise SHA-256 of a RAW acquisition (R5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiecewiseInfo {
    pub piece_size: u64,
    /// `<base>.pieces.tsv`
    pub file: String,
    pub file_sha256: String,
    pub count: u64,
}

/// A file with its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigest {
    pub path: String,
    pub sha256: String,
}

impl FileDigest {
    /// SHA-256 of the file at `path` (streamed).
    pub fn compute(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            sha256: sha256_file(path)?,
        })
    }
}

/// SHA-256 (hex) of a file's content.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// SHA-256 (hex) of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Whether the source was the selected device at the start and the end.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCheck {
    /// Probe at the start matched the selected device (and `--expect-*`)
    pub start_ok: bool,
    /// Probe at the end matched the start; `None`: not checked
    pub end_ok: Option<bool>,
    pub details: Vec<String>,
}

/// Whether the audit records of this run were written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AuditStatus {
    Written,
    NotWritten { reason: String },
}

impl Default for AuditStatus {
    fn default() -> Self {
        AuditStatus::NotWritten {
            reason: "no audit record was written".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditInfo {
    /// Hash of the "started" record; the "finished" record names this report
    pub anchor: Option<String>,
    pub status: AuditStatus,
    /// Copy of the audit log in the case directory (`audit-<boot_id>.jsonl`)
    pub export_file: Option<String>,
}

/// An earlier session of a resumed rescue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session: u32,
    /// The preserved report, `<base>.info.session-N`
    pub report_file: String,
    pub report_sha256: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub outcome: Option<Outcome>,
}

/// Paths and digests of the written reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFiles {
    pub text: PathBuf,
    pub json: PathBuf,
    pub text_sha256: String,
    pub json_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicInfoReport {
    /// [`REPORT_SCHEMA_VERSION`]
    pub schema_version: u32,
    pub tool_name: String,
    pub tool_version: String,
    pub engine: EngineKind,
    /// Derived by `classify` from the facts below; never set by an engine
    pub outcome: Outcome,
    pub exit_code: i32,
    /// Why the verdict is what it is, one sentence
    pub outcome_reason: String,
    /// Recorded (sanitised) case values
    pub case_metadata: CaseMetadata,
    /// Identity probed at the start
    pub source: SourceIdentity,
    /// Identity probed at the end
    pub identity_at_end: Option<SourceIdentity>,
    pub identity_check: IdentityCheck,
    pub capacity: Option<CapacityInfo>,
    pub write_protection: Option<WriteProtection>,
    pub smart_before: Option<SmartSnapshot>,
    pub smart_after: Option<SmartSnapshot>,
    pub effective_config: EffectiveConfig,
    pub output_dir: String,
    pub base_name: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub elapsed_seconds: u64,
    pub average_speed_bytes_sec: f64,
    /// Source size when the acquisition started
    pub expected_bytes: u64,
    /// Bytes of the source represented in the image (read or substituted)
    pub bytes_acquired: u64,
    pub stop_reason: Option<String>,
    /// Stopped by the examiner or a signal
    pub aborted: bool,
    pub read_errors: ReadErrorTable,
    /// Computed while reading the source stream
    pub acquisition_hashes: HashResults,
    /// Recomputed from the written image
    pub image_hashes: HashResults,
    pub verification: VerificationInfo,
    pub piecewise: Option<PiecewiseInfo>,
    pub image_files: Vec<String>,
    /// ddrescue map, ewfacquire log, SMART JSON, pieces file, ...
    pub auxiliary_files: Vec<FileDigest>,
    pub provenance: ToolProvenance,
    pub clock: ClockInfo,
    pub audit: AuditInfo,
    pub resume_sessions: Vec<SessionInfo>,
    pub notes: Vec<String>,
}

fn sanitize(s: &str) -> String {
    sanitize_line(s)
}

fn row(out: &mut String, label: &str, value: impl AsRef<str>) {
    out.push_str(&format!(
        "{:<width$}: {}\n",
        label,
        sanitize(value.as_ref()),
        width = LABEL_WIDTH
    ));
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn opt_bool(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

impl ForensicInfoReport {
    /// A report for an acquisition that has just started: nothing acquired
    /// yet, so its verdict is `Incomplete` until the facts are filled in and
    /// [`apply_classification`](Self::apply_classification) runs.
    pub fn new(
        engine: EngineKind,
        case: &CaseMetadata,
        source: SourceIdentity,
        effective_config: EffectiveConfig,
    ) -> Self {
        let now = Utc::now();
        let mut report = Self {
            schema_version: REPORT_SCHEMA_VERSION,
            tool_name: "dfdisk".into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            engine,
            outcome: Outcome::Incomplete,
            exit_code: Outcome::Incomplete.exit_code(),
            outcome_reason: String::new(),
            case_metadata: case.sanitized(),
            expected_bytes: source.size_bytes,
            read_errors: ReadErrorTable::new(source.logical_sector_size, ""),
            source,
            identity_at_end: None,
            identity_check: IdentityCheck::default(),
            capacity: None,
            write_protection: None,
            smart_before: None,
            smart_after: None,
            effective_config,
            output_dir: String::new(),
            base_name: String::new(),
            started_at: now,
            ended_at: now,
            elapsed_seconds: 0,
            average_speed_bytes_sec: 0.0,
            bytes_acquired: 0,
            stop_reason: None,
            aborted: false,
            acquisition_hashes: HashResults::default(),
            image_hashes: HashResults::default(),
            verification: VerificationInfo::default(),
            piecewise: None,
            image_files: Vec::new(),
            auxiliary_files: Vec::new(),
            provenance: ToolProvenance::default(),
            clock: ClockInfo::from_parts(
                now,
                &crate::models::provenance::TimedatectlInfo::default(),
                None,
                None,
                None,
            ),
            audit: AuditInfo::default(),
            resume_sessions: Vec::new(),
            notes: Vec::new(),
        };
        report.apply_classification();
        report
    }

    /// The facts the verdict is derived from, as recorded in this report.
    /// The identity counts as changed when the start check failed or the end
    /// check found a different device.
    pub fn facts(&self) -> AcquisitionFacts {
        AcquisitionFacts {
            expected_bytes: self.expected_bytes,
            bytes_acquired: self.bytes_acquired,
            read_errors: self.read_errors.clone(),
            stop_reason: self.stop_reason.clone(),
            aborted: self.aborted,
            verification: self.verification.result.clone(),
            identity_changed: self.identity_check.end_ok == Some(false),
        }
    }

    /// Record `facts` in the report and classify them.
    pub fn apply_facts(&mut self, facts: &AcquisitionFacts) {
        self.expected_bytes = facts.expected_bytes;
        self.bytes_acquired = facts.bytes_acquired;
        self.read_errors = facts.read_errors.clone();
        self.stop_reason = facts.stop_reason.clone();
        self.aborted = facts.aborted;
        self.verification.result = facts.verification.clone();
        if facts.identity_changed {
            self.identity_check.end_ok = Some(false);
        }
        self.apply_classification();
    }

    /// Set `outcome`, `exit_code` and `outcome_reason` from [`facts`](Self::facts).
    pub fn apply_classification(&mut self) {
        let c = classify_detailed(&self.facts());
        self.outcome = c.outcome;
        self.exit_code = c.outcome.exit_code();
        self.outcome_reason = c.reason;
    }

    /// The verdict banner as lines (label with exit code, explanation, key
    /// numbers, timestamp basis), shared by the report, CLI and TUI.
    pub fn verdict_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("{} (exit code {})", self.outcome.label(), self.exit_code),
            self.explanation(),
        ];
        lines.extend(self.key_numbers());
        lines.push(format!("Timestamps: {}", self.clock.label()));
        lines
    }

    /// What the verdict means for this run, in one or two sentences, chosen
    /// by what actually happened (T2): what was compared, why the run is
    /// incomplete, whether any digest exists. Falls back to
    /// [`Outcome::explanation_for`] where that is true as it stands.
    pub fn explanation(&self) -> String {
        let rescue = self.engine == EngineKind::Rescue;
        let digests = if self.acquisition_hashes.is_empty() && self.image_hashes.is_empty() {
            "no digest was computed for it"
        } else {
            "its digests cover only what was acquired"
        };
        let reread = self.verification.source_reread.as_ref();
        match self.outcome {
            Outcome::Verified
                if self.acquisition_hashes.is_empty()
                    && matches!(reread, Some(VerificationResult::Matched { .. })) =>
            {
                // No stream digest (ddrescue): the second read verified it
                format!(
                    "{} every sector of the source without read errors, and the digests of the written image equal those of a second, independent read of the source (--verify-source).",
                    if rescue {
                        "ddrescue rescued"
                    } else {
                        "dfdisk acquired"
                    }
                )
            }
            Outcome::CompleteUnverified if rescue => match reread {
                Some(VerificationResult::NotPossible { reason }) => format!(
                    "ddrescue rescued every sector of the source, but it does not compute digests while reading and the second read of the source was not possible ({reason}), so the image digests are not confirmed against the source."
                ),
                _ => self.outcome.explanation_for(self.engine).to_string(),
            },
            Outcome::Incomplete => {
                let lead = "Not all of the source was acquired:";
                if self.identity_check.end_ok == Some(false) {
                    format!(
                        "{lead} the source device changed or disappeared during the acquisition, so the image holds only what was read before that and {digests}."
                    )
                } else if rescue
                    && self.stop_reason.is_none()
                    && self.read_errors.unread_bytes() > 0
                {
                    // R12: the map really lists unread or unfinished areas
                    self.outcome.explanation_for(self.engine).to_string()
                } else if self.stop_reason.is_some()
                    && self.expected_bytes > 0
                    && self.bytes_acquired >= self.expected_bytes
                    && self.read_errors.unread_bytes() == 0
                {
                    // N1: everything was acquired, but the run ended with a
                    // problem (ddrescue's exit status, a failed fsync, ...)
                    let covered = if self.read_errors.substituted_bytes() > 0 {
                        "The image covers the whole source (its unreadable sectors are zeros in it)"
                    } else {
                        "Every byte of the source is in the image"
                    };
                    format!(
                        "{covered}, but the run did not end cleanly (the reason follows), so it is not counted as complete."
                    )
                } else if self.stop_reason.is_some() {
                    format!(
                        "{lead} the acquisition stopped before the end (the reason follows), so the image is partial and {digests}."
                    )
                } else {
                    format!(
                        "{lead} some areas of the source are not in the image, so {digests}."
                    )
                }
            }
            Outcome::Mismatch => match reread {
                Some(VerificationResult::Mismatched { .. }) if self.acquisition_hashes.is_empty() => {
                    "The digests of the written image differ from those of a second read of the source: the image does not reproduce the source as it read the second time; the image may be damaged, or the source changed or reads unstably.".to_string()
                }
                Some(VerificationResult::Mismatched { .. }) => {
                    "The digests of a second read of the source differ from those computed while reading it for the acquisition: the source changed or reads unstably, so the acquired data cannot be reproduced from it.".to_string()
                }
                _ => "A digest recomputed from the written image differs from the digest computed while reading the source: the image does not reproduce the acquired data.".to_string(),
            },
            Outcome::Aborted => {
                let lead = "The acquisition was stopped by the examiner or by a signal before it finished";
                if self.expected_bytes > 0 && self.bytes_acquired >= self.expected_bytes {
                    format!(
                        "{lead}: the whole source had been read, but the run ended before its checks were complete."
                    )
                } else {
                    format!("{lead}; the image is partial and {digests}.")
                }
            }
            outcome => outcome.explanation_for(self.engine).to_string(),
        }
    }

    /// "Digests: acquisition stream MD5 <hex>, SHA-256 <hex>; image re-read
    /// MD5 <hex>, ..." (or "No digest was computed."), for messages that
    /// must carry the digests when no report could be written.
    pub fn digest_summary(&self) -> String {
        let list = |h: &HashResults| {
            h.present()
                .iter()
                .map(|(label, digest)| format!("{label} {digest}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut parts = Vec::new();
        if !self.acquisition_hashes.is_empty() {
            parts.push(format!(
                "acquisition stream {}",
                list(&self.acquisition_hashes)
            ));
        }
        if !self.image_hashes.is_empty() {
            parts.push(format!("image re-read {}", list(&self.image_hashes)));
        }
        if parts.is_empty() {
            "No digest was computed.".to_string()
        } else {
            format!("Digests: {}.", parts.join("; "))
        }
    }

    /// The numbers behind the verdict, one sentence each.
    pub fn key_numbers(&self) -> Vec<String> {
        let mut out = Vec::new();
        let pct = if self.expected_bytes > 0 {
            // Floored to tenths: "100.0%" only when every byte was acquired
            // (rounding made 99.96% read "100.0%")
            let tenths = u128::from(self.bytes_acquired) * 1000 / u128::from(self.expected_bytes);
            format!("{}.{}%, ", tenths / 10, tenths % 10)
        } else {
            String::new()
        };
        out.push(format!(
            "Acquired {} of {} bytes ({}{}).",
            self.bytes_acquired,
            self.expected_bytes,
            pct,
            format_iec(self.bytes_acquired)
        ));
        if let Some(s) = self.read_errors.summary(RangeKind::Substituted) {
            out.push(format!(
                "{s} were unreadable and replaced by zeros; the digests below describe the image including the substituted sectors, not the original medium."
            ));
        }
        if let Some(s) = self.read_errors.summary(RangeKind::Unread) {
            out.push(format!("{s} were not read and are not in the image."));
        }
        if let Some(stop) = &self.stop_reason {
            out.push(format!("Stopped: {stop}."));
        }
        if self.identity_check.end_ok == Some(false) {
            out.push("The source changed or disappeared during the acquisition.".into());
        }
        if let Some(c) = self
            .capacity
            .as_ref()
            .filter(|c| c.hidden_area() == Some(true))
        {
            out.push(format!(
                "HIDDEN AREA on the disk of the source: {}; those sectors are not part of the image.",
                c.hidden_area_statements().join("; ")
            ));
        }
        out.push(format!(
            "Verification: {}.",
            self.verification.result.describe()
        ));
        if let Some(r) = &self.verification.source_reread {
            out.push(format!("Second source read: {}.", r.describe()));
        }
        out
    }

    /// The human-readable report (`<base>.info`).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(RULE);
        out.push_str("                       DFDISK FORENSIC ACQUISITION REPORT\n");
        out.push_str(RULE);
        self.render_verdict(&mut out);
        out.push_str(RULE);
        out.push('\n');

        out.push_str("[CASE INFORMATION]\n");
        for (label, value) in self.case_metadata.report_rows() {
            row(&mut out, label, value);
        }
        out.push('\n');

        self.render_source(&mut out);
        self.render_protection(&mut out);
        self.render_capacity_and_smart(&mut out);

        out.push_str("[ACQUISITION SETTINGS (APPLIED)]\n");
        for (label, value) in self.effective_config.rows() {
            row(&mut out, &label, value);
        }
        for note in &self.effective_config.notes {
            row(&mut out, "Note", note);
        }
        row(&mut out, "Output Directory", &self.output_dir);
        row(&mut out, "Base Name", &self.base_name);
        out.push('\n');

        self.render_time(&mut out);
        self.render_read_errors(&mut out);
        self.render_hashes(&mut out);
        self.render_files(&mut out);
        self.render_provenance(&mut out);
        self.render_audit(&mut out);
        if !self.notes.is_empty() {
            out.push_str("[NOTES]\n");
            for n in &self.notes {
                out.push_str(&format!(" - {}\n", sanitize(n)));
            }
            out.push('\n');
        }
        out.push_str(RULE);
        out
    }

    fn render_verdict(&self, out: &mut String) {
        // One sentence per line, never wrapped: phrases stay searchable
        let indent = " ".repeat(LABEL_WIDTH + 2);
        let lines = self.verdict_lines();
        let (head, rest) = lines.split_first().expect("verdict has a label");
        out.push_str(&format!(
            "{:<LABEL_WIDTH$}: {}\n",
            "VERDICT",
            sanitize(head)
        ));
        // The last verdict line is the timestamp basis, printed as its own row
        for line in &rest[..rest.len().saturating_sub(1)] {
            out.push_str(&indent);
            out.push_str(&sanitize(line));
            out.push('\n');
        }
        row(out, "Timestamps", self.clock.label());
        row(
            out,
            "Report Schema",
            format!(
                "{} (machine-readable twin: {}{})",
                self.schema_version, self.base_name, INFO_JSON_SUFFIX
            ),
        );
    }

    fn render_source(&self, out: &mut String) {
        let s = &self.source;
        out.push_str("[SOURCE IDENTITY]\n");
        row(out, "Device Node", &s.path);
        if s.canonical_path != s.path && !s.canonical_path.is_empty() {
            row(out, "Resolved Path", &s.canonical_path);
        }
        row(out, "Kind", s.kind.label());
        let mut kernel = s.kernel_name.clone();
        if let Some(mm) = &s.maj_min {
            kernel.push_str(&format!(" ({mm})"));
        }
        if let Some(seq) = s.diskseq {
            kernel.push_str(&format!(", diskseq {seq}"));
        }
        row(out, "Kernel Device", kernel);
        if !s.parent_disks.is_empty() {
            row(out, "Stored On", s.parent_disks.join(", "));
        }
        if let Some(start) = s.partition_start_sector {
            row(
                out,
                "Partition Start",
                format!("sector {start} (512-byte units)"),
            );
        }
        if let Some(uuid) = &s.dm_uuid {
            row(out, "DM UUID", uuid);
        }
        // Nothing made up: no model is "(not reported)", not a placeholder name
        row(
            out,
            "Vendor / Model",
            if s.vendor.is_none() && s.model.is_none() {
                "(not reported)".to_string()
            } else {
                s.display_name()
            },
        );
        row(
            out,
            "Firmware Revision",
            s.firmware_rev.as_deref().unwrap_or("(not reported)"),
        );
        row(out, "Serial Number", s.serial_with_provenance());
        if s.serial_candidates.len() > 1 {
            row(
                out,
                "Serial Sources",
                s.serial_candidates
                    .iter()
                    .map(|c| format!("{}: {}", c.source.label(), c.value))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        if let Some(note) = s.serial_note() {
            row(out, "Serial Note", note);
        }
        if let Some(hw) = &s.hardware_of {
            row(
                out,
                "Hardware Identity",
                format!("model, serial and WWN are those of /dev/{hw}"),
            );
        }
        row(
            out,
            "WWN / EUI",
            s.wwn.as_deref().unwrap_or("(not reported)"),
        );
        let mut attach = s
            .transport
            .as_deref()
            .map(str::to_uppercase)
            .unwrap_or_else(|| "(unknown)".into());
        if s.hotplug {
            attach.push_str(", hot-pluggable");
        }
        row(out, "Attachment", attach);
        row(out, "Removable Media", yes_no(s.removable));
        row(out, "Rotational", opt_bool(s.rotational));
        row(
            out,
            "Sector Size",
            format!(
                "logical {} bytes, physical {} bytes",
                s.logical_sector_size, s.physical_sector_size
            ),
        );
        let sectors = s.size_bytes / u64::from(s.logical_sector_size.max(1));
        row(
            out,
            "Size",
            format!(
                "{} bytes = {} sectors of {} bytes ({})",
                s.size_bytes,
                sectors,
                s.logical_sector_size.max(1),
                format_iec(s.size_bytes)
            ),
        );
        for n in &s.probe_notes {
            row(out, "Probe Note", n);
        }
        let check = &self.identity_check;
        row(
            out,
            "Identity at Start",
            if check.start_ok {
                "matches the selected device"
            } else {
                "NOT confirmed"
            },
        );
        row(
            out,
            "Identity at End",
            match check.end_ok {
                Some(true) => "same device attachment",
                Some(false) => "CHANGED OR LOST",
                None => "not checked",
            },
        );
        for d in &check.details {
            row(out, "Identity Detail", d);
        }
        out.push('\n');
    }

    fn render_protection(&self, out: &mut String) {
        out.push_str("[WRITE PROTECTION]\n");
        match &self.write_protection {
            Some(wp) => {
                for (label, value) in wp.rows() {
                    row(out, &label, value);
                }
                for n in &wp.notes {
                    row(out, "Note", n);
                }
            }
            None => row(out, "State", "(not recorded)"),
        }
        out.push('\n');
    }

    fn render_capacity_and_smart(&self, out: &mut String) {
        out.push_str("[CAPACITY / HIDDEN AREAS]\n");
        match &self.capacity {
            Some(c) => {
                row(out, "Reported Size", format!("{} bytes", c.reported_bytes));
                row(out, "Hidden Areas", c.summary());
                if let Some(dev) = &c.probed_device {
                    row(out, "Probed Device", dev);
                }
                let n = |v: Option<u64>| v.map_or_else(|| "?".to_string(), |v| v.to_string());
                if let Some(a) = &c.ata {
                    row(
                        out,
                        "ATA Max Sectors",
                        format!(
                            "visible {}, native {}, DCO real max {}{}",
                            n(a.current_max_sectors),
                            n(a.native_max_sectors),
                            n(a.dco_real_max_sectors),
                            a.sector_bytes
                                .map(|b| format!(" ({b}-byte sectors)"))
                                .unwrap_or_default()
                        ),
                    );
                }
                if let Some(ns) = &c.nvme {
                    row(
                        out,
                        "NVMe Namespace",
                        format!(
                            "size {}, capacity {}, used {} blocks of {} bytes",
                            n(ns.nsze),
                            n(ns.ncap),
                            n(ns.nuse),
                            ns.lba_bytes
                                .map_or_else(|| "?".to_string(), |b| b.to_string())
                        ),
                    );
                }
                row(out, "Method", &c.method);
                for e in &c.errors {
                    row(out, "Probe Error", e);
                }
            }
            None => row(out, "Hidden Areas", "(not probed)"),
        }
        out.push('\n');

        for (title, snap) in [
            ("SMART BEFORE", &self.smart_before),
            ("SMART AFTER", &self.smart_after),
        ] {
            let Some(snap) = snap else { continue };
            out.push_str(&format!("[{title}]\n"));
            let s = &snap.summary;
            row(out, "Policy", snap.policy.label());
            row(out, "Command", snap.command.join(" "));
            row(
                out,
                "Overall Health",
                format!("{} ({})", s.health.label(), s.assessment),
            );
            if let Some(v) = s.reallocated_sectors {
                row(out, "Reallocated Sectors", v.to_string());
            }
            if let Some(v) = s.pending_sectors {
                row(out, "Pending Sectors", v.to_string());
            }
            if let Some(v) = s.uncorrectable_errors {
                row(out, "Uncorrectable Errors", v.to_string());
            }
            if let Some(v) = s.temperature_celsius {
                row(out, "Temperature", format!("{v} °C"));
            }
            if let Some(v) = s.power_on_hours {
                row(out, "Power-on Hours", v.to_string());
            }
            if let Some(v) = s.wear_percentage {
                row(out, "Endurance Used", format!("{v} %"));
            }
            if let Some(f) = &snap.json_file {
                row(out, "Raw Output", f);
            }
            if let Some(n) = &snap.note {
                row(out, "Note", n);
            }
            out.push('\n');
        }
    }

    fn render_time(&self, out: &mut String) {
        let c = &self.clock;
        out.push_str("[TIMESTAMPS & CLOCK]\n");
        let basis = if c.ntp_synchronized == Some(true) {
            "NTP synchronized"
        } else {
            crate::models::provenance::LABEL_NOT_SYNCHRONIZED
        };
        row(
            out,
            "Started",
            format!(
                "{} UTC ({basis})",
                self.started_at.format("%Y-%m-%d %H:%M:%S")
            ),
        );
        row(
            out,
            "Ended",
            format!(
                "{} UTC ({basis})",
                self.ended_at.format("%Y-%m-%d %H:%M:%S")
            ),
        );
        row(
            out,
            "Elapsed",
            format!(
                "{} (monotonic clock)",
                crate::models::telemetry::format_duration(self.elapsed_seconds)
            ),
        );
        row(
            out,
            "Average Speed",
            format!(
                "{:.2} MiB/s{}",
                self.average_speed_bytes_sec / (1024.0 * 1024.0),
                if self.resume_sessions.is_empty() {
                    ""
                } else {
                    " (this session; see the notes)"
                }
            ),
        );
        row(
            out,
            "Time Zone",
            format!(
                "{} (UTC offset {})",
                c.timezone.as_deref().unwrap_or("unknown"),
                c.utc_offset.as_deref().unwrap_or("unknown")
            ),
        );
        row(out, "NTP Synchronized", opt_bool(c.ntp_synchronized));
        if let Some(off) = c.rtc_offset_seconds {
            row(
                out,
                "RTC Offset",
                format!("{off:+} s (RTC minus system clock)"),
            );
        }
        if let Some(note) = &c.note {
            row(out, "Clock Note", note);
        }
        out.push('\n');
    }

    fn render_read_errors(&self, out: &mut String) {
        let t = &self.read_errors;
        out.push_str("[READ ERRORS]\n");
        if t.is_empty() {
            row(out, "Unreadable Ranges", "none recorded");
        } else {
            for kind in [RangeKind::Substituted, RangeKind::Unread] {
                if let Some(s) = t.summary(kind) {
                    row(out, kind.label(), s);
                }
            }
            out.push_str(&format!(
                "  {:>5}  {:>20}  {:>16}  {:>12}  {}\n",
                "#", "offset (bytes)", "length (bytes)", "sectors", "status"
            ));
            let sector = t.effective_sector_size();
            for (i, r) in t.ranges.iter().take(TEXT_RANGE_LIMIT).enumerate() {
                out.push_str(&format!(
                    "  {:>5}  {:>20}  {:>16}  {:>12}  {}\n",
                    i + 1,
                    r.offset,
                    r.length,
                    r.sectors(sector),
                    r.kind.label()
                ));
            }
            if t.ranges.len() > TEXT_RANGE_LIMIT {
                out.push_str(&format!(
                    "  ... {} more ranges not listed here; see {}{} for the complete list\n",
                    t.ranges.len() - TEXT_RANGE_LIMIT,
                    self.base_name,
                    INFO_JSON_SUFFIX
                ));
            }
        }
        if !t.source.is_empty() {
            row(out, "Error List Source", &t.source);
        }
        row(
            out,
            "Sector Size",
            format!("{} bytes", t.effective_sector_size()),
        );
        out.push('\n');
    }

    fn render_hashes(&self, out: &mut String) {
        out.push_str("[HASHES]\n");
        out.push_str("Acquisition stream (computed while reading the source):\n");
        if self.acquisition_hashes.is_empty() {
            out.push_str("  (none: no digest was computed while reading the source)\n");
        }
        for (label, digest) in self.acquisition_hashes.present() {
            out.push_str(&format!("  {:<8}: {}\n", label, sanitize(digest)));
        }
        out.push_str("Image re-read (recomputed from the written image):\n");
        if self.image_hashes.is_empty() {
            // Why there is none: the image's own result, not the combined one
            let why = match &self.verification.image {
                Some(VerificationResult::Failed { reason }) => {
                    format!("the image re-read failed: {}", sanitize(reason))
                }
                Some(VerificationResult::NotPossible { reason }) => sanitize(reason),
                _ => "the image was not re-read".to_string(),
            };
            out.push_str(&format!("  (none: {why})\n"));
        }
        for (label, digest) in self.image_hashes.present() {
            out.push_str(&format!("  {:<8}: {}\n", label, sanitize(digest)));
        }
        out.push('\n');

        out.push_str("[VERIFICATION]\n");
        let result = if self.outcome == Outcome::Verified {
            format!(
                "VERIFIED - ALL HASHES MATCH ({})",
                match &self.verification.result {
                    VerificationResult::Matched { method } => method.as_str(),
                    _ => self.verification.method.as_str(),
                }
            )
        } else {
            format!(
                "{} (overall verdict: {})",
                self.verification.result.describe(),
                self.outcome.label()
            )
        };
        row(out, "Result", result);
        if !self.verification.method.is_empty() {
            row(out, "Method", &self.verification.method);
        }
        if let Some(r) = &self.verification.source_reread {
            row(out, "Second Source Read", r.describe());
        }
        if let Some(p) = &self.piecewise {
            row(
                out,
                "Piecewise SHA-256",
                format!(
                    "{} of up to {} in {} (SHA-256 {})",
                    plural(p.count, "piece", "pieces"),
                    format_iec(p.piece_size),
                    p.file,
                    p.file_sha256
                ),
            );
        }
        out.push('\n');
    }

    fn render_files(&self, out: &mut String) {
        out.push_str("[FILES]\n");
        if self.image_files.is_empty() {
            row(out, "Image Files", "(none)");
        }
        for f in &self.image_files {
            row(out, "Image File", f);
        }
        for f in &self.auxiliary_files {
            row(
                out,
                "Auxiliary File",
                format!("{} (SHA-256 {})", f.path, f.sha256),
            );
        }
        out.push('\n');
    }

    fn render_provenance(&self, out: &mut String) {
        let p = &self.provenance;
        out.push_str("[TOOL PROVENANCE]\n");
        row(
            out,
            "dfdisk",
            format!("{} (git {})", p.dfdisk_version, p.dfdisk_git_rev),
        );
        row(
            out,
            "dfcore",
            format!("{} (git {})", p.dfcore_version, p.dfcore_git_rev),
        );
        row(
            out,
            "dfnix Revision",
            p.dfnix_revision.as_deref().unwrap_or("(not dfnix)"),
        );
        row(out, "Kernel", p.kernel.as_deref().unwrap_or("unknown"));
        row(out, "Host", p.hostname.as_deref().unwrap_or("unknown"));
        for (tool, version) in &p.tools {
            row(out, &format!("Tool {tool}"), version);
        }
        if !p.commands.is_empty() {
            out.push_str("Commands run:\n");
            for c in &p.commands {
                out.push_str(&format!("  $ {}\n", sanitize(&c.command_line())));
                out.push_str(&format!(
                    "    {} .. {}  {}\n",
                    c.started.format("%H:%M:%S"),
                    c.ended.format("%H:%M:%S"),
                    sanitize(&c.status_text())
                ));
            }
        }
        out.push('\n');
    }

    fn render_audit(&self, out: &mut String) {
        out.push_str("[AUDIT]\n");
        row(
            out,
            "Audit Log",
            match &self.audit.status {
                AuditStatus::Written => "written".to_string(),
                AuditStatus::NotWritten { reason } => format!("NOT WRITTEN: {reason}"),
            },
        );
        if let Some(anchor) = &self.audit.anchor {
            row(out, "Audit Anchor", format!("{anchor} (dfnix audit log)"));
        }
        if let Some(f) = &self.audit.export_file {
            row(out, "Audit Log Copy", f);
        }
        for s in &self.resume_sessions {
            row(
                out,
                &format!("Earlier Session {}", s.session),
                format!(
                    "{}{}",
                    s.report_file,
                    s.report_sha256
                        .as_deref()
                        .map(|h| format!(" (SHA-256 {h})"))
                        .unwrap_or_default()
                ),
            );
        }
        out.push('\n');
    }

    /// The machine-readable report (`<base>.info.json`), pretty-printed.
    pub fn to_json(&self) -> String {
        let mut copy = self.clone();
        copy.clock.refresh_basis();
        serde_json::to_string_pretty(&copy).expect("a report always serialises")
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Write `<base>.info` and `<base>.info.json` into `dir`: the reserve
    /// file `<base>.info.reserve` is removed first (so a full destination has
    /// room), each report is written to `<name>.tmp`, fsynced and renamed,
    /// then the directory is fsynced.
    pub fn write_reports(&self, dir: &Path, base: &str) -> io::Result<ReportFiles> {
        remove_reserve_file(dir, base)?;
        let text = self.render_text();
        let json = self.to_json();
        let text_path = dir.join(format!("{base}{INFO_SUFFIX}"));
        let json_path = dir.join(format!("{base}{INFO_JSON_SUFFIX}"));
        write_atomic(&text_path, text.as_bytes())?;
        write_atomic(&json_path, json.as_bytes())?;
        sync_dir(dir)?;
        Ok(ReportFiles {
            text: text_path,
            json: json_path,
            text_sha256: sha256_hex(text.as_bytes()),
            json_sha256: sha256_hex(json.as_bytes()),
        })
    }
}

fn with_path(path: &Path, e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("cannot {what} {}: {e}", path.display()))
}

/// Write `bytes` to `<path>.tmp`, fsync, and rename it to `path`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = path.with_file_name(format!("{}.tmp", name.to_string_lossy()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| with_path(&tmp, e, "create"))?;
        f.write_all(bytes)
            .map_err(|e| with_path(&tmp, e, "write"))?;
        f.sync_all().map_err(|e| with_path(&tmp, e, "sync"))?;
        std::fs::rename(&tmp, path).map_err(|e| with_path(path, e, "rename into"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Whether an fsync error on a directory only means that the filesystem
/// cannot sync directories: exFAT, NTFS-3G, CIFS/SMB and other FUSE or
/// network filesystems answer EINVAL, ENOTSUP or ENOSYS. Those count as
/// success (the rule dfcore's audit log applies); every other errno is a
/// real error.
pub fn dir_sync_unsupported(errno: Option<i32>) -> bool {
    matches!(errno, Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS))
}

/// fsync a directory so renames and new entries in it are durable. A
/// filesystem that cannot sync directories ([`dir_sync_unsupported`]) is not
/// an error; failing to open the directory, or any other fsync error, is.
/// Every directory fsync in dfdisk goes through this function.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    let d = File::open(dir).map_err(|e| with_path(dir, e, "open directory"))?;
    match d.sync_all() {
        Ok(()) => Ok(()),
        Err(e) if dir_sync_unsupported(e.raw_os_error()) => Ok(()),
        Err(e) => Err(with_path(dir, e, "sync directory")),
    }
}

/// Path of the reservation file of `base` in `dir`.
pub fn reserve_path(dir: &Path, base: &str) -> PathBuf {
    dir.join(format!("{base}{RESERVE_SUFFIX}"))
}

/// Create `<base>.info.reserve` ([`RESERVE_BYTES`], allocated and fsynced)
/// so the reports still fit when the image fills the destination. Fails on
/// ENOSPC, EDQUOT or an existing file; a failure must refuse the acquisition
/// before anything else is written (R11).
pub fn create_reserve_file(dir: &Path, base: &str) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    let path = reserve_path(dir, base);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| with_path(&path, e, "create"))?;
    let result = (|| {
        // SAFETY: posix_fallocate on a file descriptor we own
        let rc = unsafe { libc::posix_fallocate(f.as_raw_fd(), 0, RESERVE_BYTES as libc::off_t) };
        match rc {
            0 => {}
            libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL => {
                // Filesystem without fallocate: write the bytes
                let zeros = vec![0u8; RESERVE_BYTES as usize];
                f.write_all(&zeros)?;
            }
            errno => return Err(io::Error::from_raw_os_error(errno)),
        }
        f.sync_all()
    })();
    if let Err(e) = result {
        drop(f);
        let _ = std::fs::remove_file(&path);
        return Err(with_path(&path, e, "reserve space for the report in"));
    }
    drop(f);
    if let Err(e) = sync_dir(dir) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Remove `<base>.info.reserve` if present; `Ok(true)` when one was removed.
pub fn remove_reserve_file(dir: &Path, base: &str) -> io::Result<bool> {
    let path = reserve_path(dir, base);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(with_path(&path, e, "remove")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::config::{AcquisitionConfig, ImageFormat, SplitSize};
    use crate::models::identity::SerialSource;
    use crate::models::provenance::{CommandRecord, TimedatectlInfo, LABEL_NOT_SYNCHRONIZED};

    fn source() -> SourceIdentity {
        let mut s = SourceIdentity {
            path: "/dev/sdb".into(),
            canonical_path: "/dev/sdb".into(),
            kernel_name: "sdb".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(5),
            size_bytes: 1 << 20,
            logical_sector_size: 512,
            physical_sector_size: 512,
            model: Some("Test Disk".into()),
            transport: Some("sata".into()),
            ..Default::default()
        };
        s.add_serial_candidate("SER123", SerialSource::VpdPage80);
        s
    }

    fn case() -> CaseMetadata {
        CaseMetadata {
            case_number: "CASE-1".into(),
            evidence_number: "EV1".into(),
            examiner: "Examiner\tOne".into(),
            ..Default::default()
        }
    }

    fn raw_config() -> AcquisitionConfig {
        AcquisitionConfig {
            format: ImageFormat::Raw,
            split_size: SplitSize::None,
            ..Default::default()
        }
    }

    fn hashes(md5: &str) -> HashResults {
        HashResults {
            md5: Some(md5.into()),
            sha1: None,
            sha256: Some("ab".repeat(32)),
        }
    }

    /// A RAW report of a complete, clean acquisition that verified.
    fn verified() -> ForensicInfoReport {
        let src = source();
        let eff = EffectiveConfig::build(&raw_config(), Some(&src));
        let mut r = ForensicInfoReport::new(EngineKind::Raw, &case(), src, eff);
        r.base_name = "case-1_ea01_ev1_SER123".into();
        r.bytes_acquired = 1 << 20;
        r.acquisition_hashes = hashes("aa");
        r.image_hashes = hashes("aa");
        r.identity_check.start_ok = true;
        r.identity_check.end_ok = Some(true);
        r.verification = VerificationInfo {
            result: VerificationResult::Matched {
                method: "image re-read by dfdisk".into(),
            },
            method: "image re-read by dfdisk after fsync".into(),
            source_reread: None,
            image: None,
        };
        r.apply_classification();
        r
    }

    #[test]
    fn a_new_report_claims_nothing() {
        let r = ForensicInfoReport::new(
            EngineKind::Raw,
            &case(),
            source(),
            EffectiveConfig::build(&raw_config(), None),
        );
        assert_eq!(r.outcome, Outcome::Incomplete);
        assert_eq!(r.exit_code, 6);
        assert_eq!(r.schema_version, 2);
        assert_eq!(r.expected_bytes, 1 << 20);
        assert_eq!(r.case_metadata.examiner, "Examiner One");
    }

    #[test]
    fn verdict_banner_comes_first() {
        let text = verified().render_text();
        let verdict = text.find("VERDICT").unwrap();
        let case = text.find("[CASE INFORMATION]").unwrap();
        assert!(verdict < case);
        assert!(text.contains("VERIFIED (exit code 0)"), "{text}");
        assert!(
            text.contains("Acquired 1048576 of 1048576 bytes (100.0%, 1 MiB)."),
            "{text}"
        );
        assert!(text.contains("VERIFIED - ALL HASHES MATCH"));
    }

    #[test]
    fn the_percentage_never_rounds_up_to_complete() {
        let mut r = verified();
        r.expected_bytes = 1_000_000;
        r.bytes_acquired = 999_999;
        let first = r.key_numbers().remove(0);
        assert!(first.contains("(99.9%, "), "{first}");
        r.bytes_acquired = 1_000_000;
        assert!(r.key_numbers()[0].contains("(100.0%, "));
        r.bytes_acquired = 0;
        assert!(r.key_numbers()[0].contains("(0.0%, "));
        r.expected_bytes = u64::MAX;
        r.bytes_acquired = u64::MAX - 1;
        assert!(r.key_numbers()[0].contains("(99.9%, "));
    }

    #[test]
    fn a_known_hidden_area_is_in_the_verdict_banner() {
        use crate::models::capacity::{AtaCapacity, CapacityInfo};
        let mut r = verified();
        let ata = |hpa: bool| AtaCapacity {
            native_max_sectors: Some(4096),
            current_max_sectors: Some(if hpa { 2048 } else { 4096 }),
            hpa_present: Some(hpa),
            dco_present: Some(false),
            dco_real_max_sectors: Some(4096),
            sector_bytes: Some(512),
        };
        r.capacity = Some(CapacityInfo {
            reported_bytes: 1 << 20,
            ata: Some(ata(true)),
            method: "hdparm -N".into(),
            ..Default::default()
        });
        let banner = r.verdict_lines().join("\n");
        assert!(
            banner.contains("HIDDEN AREA on the disk of the source: ")
                && banner.contains("those sectors are not part of the image."),
            "{banner}"
        );
        r.capacity.as_mut().unwrap().ata = Some(ata(false));
        assert!(!r.verdict_lines().join("\n").contains("HIDDEN AREA"));
    }

    #[test]
    fn capacity_facts_are_in_the_text() {
        use crate::models::capacity::{AtaCapacity, CapacityInfo, NvmeCapacity};
        let mut r = verified();
        r.capacity = Some(CapacityInfo {
            reported_bytes: 1 << 20,
            probed_device: Some("/dev/sdb".into()),
            ata: Some(AtaCapacity {
                native_max_sectors: Some(2048),
                current_max_sectors: Some(2048),
                hpa_present: Some(false),
                dco_present: Some(false),
                dco_real_max_sectors: Some(2048),
                sector_bytes: Some(512),
            }),
            method: "hdparm -N".into(),
            ..Default::default()
        });
        let text = r.render_text();
        assert!(text.contains("no HPA or DCO found"), "{text}");
        assert!(
            text.contains("visible 2048, native 2048, DCO real max 2048 (512-byte sectors)"),
            "{text}"
        );
        r.capacity = Some(CapacityInfo {
            nvme: Some(NvmeCapacity {
                nsze: Some(2048),
                ncap: Some(2048),
                nuse: Some(12),
                lba_bytes: Some(512),
            }),
            method: "nvme id-ns (NVMe has no HPA or DCO)".into(),
            ..Default::default()
        });
        let text = r.render_text();
        assert!(
            text.contains("size 2048, capacity 2048, used 12 blocks of 512 bytes"),
            "{text}"
        );
        assert!(text.contains("NVMe has no HPA or DCO"), "{text}");
    }

    #[test]
    fn a_source_without_a_model_names_none() {
        let mut r = verified();
        r.source.model = None;
        r.source.vendor = None;
        let text = r.render_text();
        assert!(
            text.contains("Vendor / Model        : (not reported)"),
            "{text}"
        );
        assert!(!text.contains("Unknown Drive"), "{text}");
    }

    #[test]
    fn piece_counts_are_plural_only_when_more_than_one() {
        let mut r = verified();
        r.piecewise = Some(PiecewiseInfo {
            piece_size: 1 << 30,
            file: "b.pieces.tsv".into(),
            file_sha256: "cd".repeat(32),
            count: 1,
        });
        let text = r.render_text();
        // The piece size is a maximum: a 1 MiB image has one 1 MiB piece
        assert!(
            text.contains("1 piece of up to 1 GiB in b.pieces.tsv"),
            "{text}"
        );
        assert!(!text.contains("1 piece of 1 GiB"), "{text}");
        r.piecewise.as_mut().unwrap().count = 3;
        assert!(r.render_text().contains("3 pieces of up to 1 GiB"));
    }

    #[test]
    fn all_hashes_match_only_when_verified() {
        let base = verified();
        let mut variants = Vec::new();
        let mut r = base.clone();
        r.read_errors.push(4096, 1024, RangeKind::Substituted);
        variants.push(r);
        let mut r = base.clone();
        r.bytes_acquired = 512;
        variants.push(r);
        let mut r = base.clone();
        r.verification.result = VerificationResult::Mismatched {
            method: "x".into(),
            details: "MD5 differs".into(),
        };
        variants.push(r);
        let mut r = base.clone();
        r.verification.result = VerificationResult::Failed { reason: "x".into() };
        variants.push(r);
        let mut r = base.clone();
        r.verification.result = VerificationResult::NotPossible { reason: "x".into() };
        variants.push(r);
        let mut r = base.clone();
        r.aborted = true;
        variants.push(r);
        let mut seen = std::collections::BTreeSet::new();
        for mut r in variants {
            r.apply_classification();
            assert_ne!(r.outcome, Outcome::Verified);
            seen.insert(r.exit_code);
            let text = r.render_text();
            assert!(
                !text.contains("ALL HASHES MATCH"),
                "{:?}\n{text}",
                r.outcome
            );
            assert!(text.contains(r.outcome.label()), "{text}");
        }
        assert_eq!(seen.len(), 6);
        assert!(base.render_text().contains("ALL HASHES MATCH"));
    }

    #[test]
    fn read_errors_are_explained_and_tabled() {
        let mut r = verified();
        r.read_errors.push(0, 32768, RangeKind::Substituted);
        r.read_errors.push(1 << 19, 32768, RangeKind::Substituted);
        r.read_errors.source = "raw engine".into();
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::CompletedWithReadErrors);
        assert_eq!(r.exit_code, 7);
        let text = r.render_text();
        assert!(
            text.contains("128 sectors (64 KiB) in 2 ranges were unreadable and replaced by zeros; the digests below describe the image including the substituted sectors, not the original medium."),
            "{text}"
        );
        assert!(text.contains("524288"), "{text}");
        assert!(text.contains("unreadable, zero-filled"));
        assert!(text.contains("Error List Source"));
    }

    #[test]
    fn long_error_tables_point_to_the_json() {
        let mut r = verified();
        for i in 0..250u64 {
            r.read_errors.push(i * 4096, 512, RangeKind::Substituted);
        }
        r.apply_classification();
        let text = r.render_text();
        assert!(
            text.contains("50 more ranges not listed here; see case-1_ea01_ev1_SER123.info.json"),
            "{text}"
        );
        let json: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(json["read_errors"]["ranges"].as_array().unwrap().len(), 250);
    }

    #[test]
    fn empty_case_values_and_hash_labels() {
        let text = verified().render_text();
        assert!(
            text.contains("Authority / Agency    : (not provided)"),
            "{text}"
        );
        assert!(text.contains("Location / EA         : 01"), "{text}");
        assert!(text.contains("Acquisition stream (computed while reading the source)"));
        assert!(text.contains("Image re-read (recomputed from the written image)"));
        // RAW settings never mention compression or segments
        assert!(!text.contains("Compression"));
        assert!(!text.contains("Segment"));
    }

    #[test]
    fn empty_optional_case_values_are_null_in_json() {
        let r = verified();
        let json: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        let case = &json["case_metadata"];
        for field in [
            "authority",
            "description",
            "notes",
            "seal_number",
            "seizure_time",
            "seizure_location",
        ] {
            assert!(case[field].is_null(), "{field}: {case}");
        }
        assert_eq!(case["case_number"], "CASE-1");
        assert_eq!(case["evidence_number"], "EV1");
        assert_eq!(case["examiner"], "Examiner One");
        assert_eq!(case["location_ea"], "01");
        // The text report still says "(not provided)", and the JSON reads back
        assert!(r
            .render_text()
            .contains("Seal Number           : (not provided)"));
        let back = ForensicInfoReport::from_json(&r.to_json()).unwrap();
        assert_eq!(back.case_metadata, r.case_metadata);
        assert_eq!(back.case_metadata.authority, "");
    }

    #[test]
    fn values_are_sanitised_in_text_but_exact_in_json() {
        let mut r = verified();
        r.source.model = Some("Evil\u{1b}[2J\nModel".into());
        r.notes.push("line1\nline2\ttab".into());
        let text = r.render_text();
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("Evil [2J Model"), "{text}");
        assert!(text.contains(" - line1 line2 tab"));
        for line in text.lines() {
            assert!(!line.chars().any(|c| c.is_control()), "{line:?}");
        }
        let back = ForensicInfoReport::from_json(&r.to_json()).unwrap();
        assert_eq!(back.source.model, r.source.model);
    }

    #[test]
    fn unsynchronised_clock_is_labelled() {
        let mut r = verified();
        let text = r.render_text();
        assert!(
            text.contains(&format!("Timestamps            : {LABEL_NOT_SYNCHRONIZED}")),
            "{text}"
        );
        assert!(text.contains(&format!("UTC ({LABEL_NOT_SYNCHRONIZED})")));
        let json: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(json["clock"]["timestamp_basis"], LABEL_NOT_SYNCHRONIZED);

        r.clock = ClockInfo::from_parts(
            Utc::now(),
            &TimedatectlInfo {
                ntp_synchronized: Some(true),
                ..Default::default()
            },
            None,
            None,
            None,
        );
        let text = r.render_text();
        assert!(!text.contains("NOT synchronized"), "{text}");
        assert!(text.contains("UTC (NTP synchronized)"));
    }

    #[test]
    fn json_twin_round_trips_and_carries_schema_and_outcome() {
        let mut r = verified();
        r.provenance.commands.push(CommandRecord {
            argv: vec!["ewfverify".into(), "-d".into(), "md5".into()],
            started: Utc::now(),
            ended: Utc::now(),
            exit_code: Some(0),
            signal: None,
            stop: None,
            error: None,
            stdout_tail: vec![],
            stderr_tail: vec![],
        });
        let json: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(json["schema_version"], 2);
        assert_eq!(json["outcome"], "verified");
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["verification"]["result"]["status"], "matched");
        assert_eq!(json["source"]["serial"], "SER123");
        assert_eq!(json["effective_config"]["engine"], "raw");
        let back = ForensicInfoReport::from_json(&r.to_json()).unwrap();
        assert_eq!(back.outcome, Outcome::Verified);
        assert_eq!(back.render_text(), r.render_text());
        assert!(r.render_text().contains("$ ewfverify -d md5"));
    }

    #[test]
    fn apply_facts_records_and_classifies() {
        let mut r = verified();
        let mut facts = r.facts();
        facts.identity_changed = true;
        facts.stop_reason = Some("source lost at offset 4096".into());
        r.apply_facts(&facts);
        assert_eq!(r.outcome, Outcome::Incomplete);
        assert_eq!(r.identity_check.end_ok, Some(false));
        assert!(r.outcome_reason.contains("source lost at offset 4096"));
        let text = r.render_text();
        assert!(text.contains("CHANGED OR LOST"));
        assert!(text.contains("Stopped: source lost at offset 4096."));
    }

    #[test]
    fn rescue_wording_follows_r12() {
        let src = source();
        let config = AcquisitionConfig {
            rescue_mode: true,
            ..raw_config()
        };
        let mut r = ForensicInfoReport::new(
            EngineKind::Rescue,
            &case(),
            src.clone(),
            EffectiveConfig::build(&config, Some(&src)),
        );
        r.bytes_acquired = r.expected_bytes;
        r.read_errors.push(8192, 4096, RangeKind::Unread);
        r.verification.result = VerificationResult::NotPossible {
            reason: "ddrescue does not hash the source".into(),
        };
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::Incomplete);
        let text = r.render_text();
        assert!(text.contains("run the rescue again"), "{text}");
        assert!(
            text.contains("8 sectors (4 KiB) in 1 range were not read"),
            "{text}"
        );
        assert!(text.contains("ddrescue Retries"));
    }

    /// A rescue report with the given facts applied.
    fn rescue_report(f: impl FnOnce(&mut ForensicInfoReport)) -> ForensicInfoReport {
        let src = source();
        let config = AcquisitionConfig {
            rescue_mode: true,
            ..raw_config()
        };
        let mut r = ForensicInfoReport::new(
            EngineKind::Rescue,
            &case(),
            src.clone(),
            EffectiveConfig::build(&config, Some(&src)),
        );
        r.bytes_acquired = r.expected_bytes;
        r.image_hashes = hashes("aa");
        r.verification.result = VerificationResult::NotPossible {
            reason: "ddrescue does not hash the source".into(),
        };
        f(&mut r);
        r.apply_classification();
        r
    }

    #[test]
    fn explanations_follow_what_happened() {
        const MAP_TEXT: &str = "the ddrescue map still lists areas";
        // R-3: ddrescue ended abnormally with a finished map: the stop reason,
        // not the map, is the cause
        let r = rescue_report(|r| {
            r.stop_reason = Some("ddrescue ended abnormally (exit status 1)".into());
        });
        assert_eq!(r.outcome, Outcome::Incomplete);
        let e = r.explanation();
        assert!(!e.contains(MAP_TEXT), "{e}");
        // N1: every byte is in the image; the run is incomplete only because
        // it did not end cleanly, and the image is not called partial
        assert_eq!(r.bytes_acquired, r.expected_bytes);
        assert_eq!(
            e,
            "Every byte of the source is in the image, but the run did not end cleanly (the reason follows), so it is not counted as complete."
        );
        // ... with bad sectors: the image covers the source, with zeros
        let r = rescue_report(|r| {
            r.stop_reason = Some("ddrescue ended abnormally (ended by signal 9)".into());
            r.read_errors.push(4096, 4096, RangeKind::Substituted);
        });
        assert_eq!(r.outcome, Outcome::Incomplete);
        let e = r.explanation();
        assert!(
            e.starts_with("The image covers the whole source (its unreadable sectors are zeros in it), but the run did not end cleanly"),
            "{e}"
        );
        assert!(!e.contains("partial"), "{e}");
        // ... also for a RAW run whose image could not be fsynced
        let mut r = verified();
        r.stop_reason = Some("fsync of the image failed".into());
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::Incomplete);
        assert!(r.explanation().starts_with(
            "Every byte of the source is in the image, but the run did not end cleanly"
        ));
        // A stop before the end: partial
        r.bytes_acquired = 512;
        r.apply_classification();
        let e = r.explanation();
        assert!(e.contains("stopped before the end"), "{e}");
        assert!(e.contains("the image is partial"), "{e}");
        // ... also when the map has unread areas besides the stop reason
        let r = rescue_report(|r| {
            r.stop_reason = Some("ddrescue ended abnormally (exit status 1)".into());
            r.read_errors.push(0, 4096, RangeKind::Unread);
        });
        assert!(!r.explanation().contains(MAP_TEXT));
        assert!(r.explanation().contains("stopped before the end"));
        // The identity changed: that is the cause
        let r = rescue_report(|r| {
            r.read_errors.push(0, 4096, RangeKind::Unread);
            r.identity_check.end_ok = Some(false);
        });
        let e = r.explanation();
        assert!(e.contains("changed or disappeared"), "{e}");
        assert!(!e.contains(MAP_TEXT), "{e}");
        // Only unfinished map areas: the R12 sentence with its remedy
        let r = rescue_report(|r| r.read_errors.push(0, 4096, RangeKind::Unread));
        assert!(r.explanation().contains(MAP_TEXT));

        // Rescue VERIFIED: what was compared is a second read, not a stream
        // digest (no such digest exists)
        let r = rescue_report(|r| {
            r.verification.source_reread = Some(VerificationResult::Matched {
                method: "second read of the source".into(),
            });
            r.verification.result = VerificationResult::Matched {
                method: "second read of the source".into(),
            };
        });
        assert_eq!(r.outcome, Outcome::Verified);
        let e = r.explanation();
        assert!(
            e.contains("equal those of a second, independent read of the source"),
            "{e}"
        );
        assert!(!e.contains("computed while reading the source"), "{e}");

        // ABORTED: "its digests" only when there are digests (T7)
        let mut r = verified();
        r.bytes_acquired = 512;
        r.aborted = true;
        r.apply_classification();
        assert!(r
            .explanation()
            .contains("its digests cover only what was acquired"));
        r.acquisition_hashes = HashResults::default();
        r.image_hashes = HashResults::default();
        let e = r.explanation();
        assert!(e.contains("no digest was computed for it"), "{e}");
        assert!(!e.contains("its digests"), "{e}");
        // ... and "partial" only when the image is
        r.bytes_acquired = r.expected_bytes;
        let e = r.explanation();
        assert!(!e.contains("partial"), "{e}");
        assert!(e.contains("the whole source had been read"), "{e}");

        // A MISMATCH of the image itself
        let mut r = verified();
        r.verification.result = VerificationResult::Mismatched {
            method: "image re-read".into(),
            details: "MD5 acquisition aa but recomputed bb".into(),
        };
        r.apply_classification();
        assert!(r
            .explanation()
            .starts_with("A digest recomputed from the written image differs"));
        // Every explanation is a sentence
        for o in Outcome::ALL {
            let mut r = verified();
            r.outcome = o;
            assert!(r.explanation().ends_with('.'), "{o:?}");
        }
    }

    #[test]
    fn compare_digests_semantics() {
        let all = HashSelection {
            md5: true,
            sha1: true,
            sha256: true,
        };
        let md5_sha256 = HashSelection {
            md5: true,
            sha1: false,
            sha256: true,
        };
        let a = hashes("aa");
        let upper = HashResults {
            md5: Some("AA".into()),
            ..hashes("aa")
        };
        assert!(compare_digests(md5_sha256, &a, &upper, "m").is_matched());
        // A selected digest missing on one side is a failure, never a pass
        assert!(matches!(
            compare_digests(all, &a, &a, "m"),
            VerificationResult::Failed { .. }
        ));
        // An unselected extra digest is ignored
        let extra = HashResults {
            sha1: Some("ff".repeat(20)),
            ..hashes("aa")
        };
        assert!(compare_digests(md5_sha256, &a, &extra, "m").is_matched());
        let VerificationResult::Mismatched { details, method } =
            compare_digests(md5_sha256, &a, &hashes("bb"), "ewfverify")
        else {
            panic!()
        };
        assert_eq!(method, "ewfverify");
        assert!(
            details.contains("MD5 acquisition aa but recomputed bb"),
            "{details}"
        );
        // Named sides say what was compared (R-4)
        let VerificationResult::Mismatched { details, .. } = compare_digest_sets(
            md5_sha256,
            ("image", &a),
            ("second read", &hashes("bb")),
            "m",
        ) else {
            panic!()
        };
        assert!(
            details.contains("MD5 image aa but second read bb"),
            "{details}"
        );
        let VerificationResult::Failed { reason } = compare_digest_sets(
            md5_sha256,
            ("image", &HashResults::default()),
            ("second read", &a),
            "m",
        ) else {
            panic!()
        };
        assert!(reason.contains("MD5 has no image digest"), "{reason}");
        assert!(matches!(
            compare_digests(HashSelection::default(), &a, &a, "m"),
            VerificationResult::Failed { .. }
        ));
    }

    #[test]
    fn reports_are_written_atomically_and_the_reserve_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let base = "case-1_ea01_ev1_SER123";
        let reserve = create_reserve_file(dir.path(), base).unwrap();
        assert_eq!(std::fs::metadata(&reserve).unwrap().len(), RESERVE_BYTES);
        // A second reservation for the same base is refused
        assert!(create_reserve_file(dir.path(), base).is_err());

        let r = verified();
        let files = r.write_reports(dir.path(), base).unwrap();
        assert!(!reserve.exists());
        assert_eq!(files.text, dir.path().join(format!("{base}.info")));
        assert_eq!(files.json, dir.path().join(format!("{base}.info.json")));
        let text = std::fs::read(&files.text).unwrap();
        let json = std::fs::read(&files.json).unwrap();
        assert_eq!(files.text_sha256, sha256_hex(&text));
        assert_eq!(files.json_sha256, sha256_hex(&json));
        assert_eq!(text, r.render_text().into_bytes());
        // No temporary files are left behind
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(!remove_reserve_file(dir.path(), base).unwrap());
        // Rewriting replaces both reports
        let mut r2 = r.clone();
        r2.notes.push("second".into());
        let again = r2.write_reports(dir.path(), base).unwrap();
        assert_ne!(again.text_sha256, files.text_sha256);
        // An unwritable destination is an error
        assert!(r.write_reports(&dir.path().join("missing"), base).is_err());
    }

    #[test]
    fn directory_sync_tolerates_filesystems_that_cannot_sync_directories() {
        // exFAT, NTFS-3G, CIFS/SMB, FUSE
        for errno in [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS] {
            assert!(dir_sync_unsupported(Some(errno)), "{errno}");
        }
        // Real failures stay failures
        for errno in [
            libc::EIO,
            libc::ENOSPC,
            libc::EDQUOT,
            libc::EROFS,
            libc::EBADF,
        ] {
            assert!(!dir_sync_unsupported(Some(errno)), "{errno}");
        }
        assert!(!dir_sync_unsupported(None));
        let dir = tempfile::tempdir().unwrap();
        assert!(sync_dir(dir.path()).is_ok());
        assert!(sync_dir(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn file_digests() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("map");
        std::fs::write(&p, b"hello world").unwrap();
        let d = FileDigest::compute(&p).unwrap();
        assert_eq!(
            d.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert!(FileDigest::compute(&dir.path().join("none")).is_err());
    }
}
