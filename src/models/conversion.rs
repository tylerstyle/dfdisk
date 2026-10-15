//! Request and result of an image conversion (§13 Converter, review H3).
//!
//! A conversion turns a RAW image (one file or a split `.001`, `.002`, ...
//! set) into an E01, or an E01 segment family into one RAW file. It is held
//! to the rigour of an acquisition: required case values, existing-output
//! refusal, destination checks, audit records, and a report of its own
//! (`<base>.conversion.info` and `<base>.conversion.info.json`, next to the
//! output) whose verdict comes from
//! [`classify`](crate::models::outcome::classify) over measured facts (P1).
//!
//! The verdict of a conversion describes the output as evidence: the read
//! errors and the incompleteness of the acquisition the source image came
//! from are inherited (a conversion cannot repair them), and an output is
//! only "verified" when its digests match digests that lead back to the
//! acquisition of the medium.
//!
//! The CLI (`dfdisk convert`, `--rescue-to-e01`) and the TUI build a
//! [`ConversionRequest`] and call
//! [`engines::converter::convert`](crate::engines::converter::convert).

use crate::models::case::{CaseMetadata, NOT_PROVIDED};
use crate::models::config::{CompressionLevel, HashAlgorithm, SplitSize};
use crate::models::info_report::{
    remove_reserve_file, sha256_hex, sync_dir, write_atomic, AuditInfo, AuditStatus, FileDigest,
    HashResults, ReportFiles, REPORT_SCHEMA_VERSION, TEXT_RANGE_LIMIT,
};
use crate::models::outcome::{
    classify_detailed, AcquisitionFacts, Outcome, RangeKind, ReadErrorTable, VerificationResult,
};
use crate::models::provenance::{ClockInfo, ToolProvenance, LABEL_NOT_SYNCHRONIZED};
use crate::models::text::{format_iec, sanitize_line};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// `report_kind` of a conversion report (acquisition reports have none).
pub const CONVERSION_REPORT_KIND: &str = "conversion";
/// Stem every conversion report file adds to the base name: the reports are
/// `<base>.conversion.info` / `.info.json`, the reservation
/// `<base>.conversion.info.reserve`. Distinct from an acquisition's
/// `<base>.info`, so a conversion next to its source acquisition never
/// touches that report.
pub const CONVERSION_STEM: &str = ".conversion";
/// Text report suffix.
pub const CONVERSION_INFO_SUFFIX: &str = ".conversion.info";
/// JSON report suffix.
pub const CONVERSION_INFO_JSON_SUFFIX: &str = ".conversion.info.json";
/// Log the libewf tool writes (`-l`): its read errors and digests.
pub const CONVERSION_LOG_SUFFIX: &str = ".conversion.log";
/// Longest suffix a conversion writes after the base name
/// (`.conversion.info.json.tmp`), for the 255-byte file name limit.
pub const LONGEST_CONVERSION_SUFFIX: &str = ".conversion.info.json.tmp";

const RULE: &str =
    "================================================================================\n";
const LABEL_WIDTH: usize = 22;

/// Format the converter produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionTarget {
    /// RAW (or split RAW) image to E01
    #[default]
    E01,
    /// E01 segment family to one RAW image
    Raw,
}

impl ConversionTarget {
    pub fn label(&self) -> &'static str {
        match self {
            ConversionTarget::E01 => "RAW to E01",
            ConversionTarget::Raw => "E01 to RAW",
        }
    }

    /// Extension of the (first) output file.
    pub fn extension(&self) -> &'static str {
        match self {
            ConversionTarget::E01 => "E01",
            ConversionTarget::Raw => "raw",
        }
    }
}

/// One conversion as the CLI or the TUI asks for it.
#[derive(Debug, Clone, Default)]
pub struct ConversionRequest {
    /// The image to convert: a RAW file, the first segment of a split RAW
    /// image (`.001`) or the first segment of an EWF family (`.E01`)
    pub source: PathBuf,
    pub target: ConversionTarget,
    pub output_dir: PathBuf,
    /// Case fields given by the examiner. They are merged over the values of
    /// the source's acquisition report (`<base>.info.json` next to the
    /// source, or `source_report`) and, for an E01 source, its header:
    /// every non-empty given field wins. Without case number, evidence
    /// number and examiner from any of them the conversion is a usage error.
    pub case: Option<CaseMetadata>,
    /// E01 target only
    pub compression: CompressionLevel,
    /// E01 target only
    pub split_size: SplitSize,
    /// Extra lines for the target's notes and report, e.g. the read-error
    /// summary of the rescue run an E01 is made from. (The converter itself
    /// adds the source report's verdict and read-error summary.)
    pub notes: Vec<String>,
    /// Report of the acquisition (or conversion) the source came from,
    /// referenced in the conversion report (and its digests used for the
    /// comparison). `None`: `<base>.info.json` next to the source is used
    /// when it lists the source image. A given report that does not list
    /// the source image is a usage error.
    pub source_report: Option<PathBuf>,
    /// Accept a destination in memory (tmpfs/ramfs), as `--allow-tmpfs`
    pub allow_tmpfs: bool,
    /// E01 target: accept less free space than the source size (compression
    /// may make it fit), as `--allow-low-space`
    pub allow_low_space: bool,
}

impl ConversionRequest {
    /// A request with the defaults: case values from the source report, fast
    /// compression, 2 GiB segments (E01), no extra notes.
    pub fn new(
        source: impl Into<PathBuf>,
        target: ConversionTarget,
        output_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source: source.into(),
            target,
            output_dir: output_dir.into(),
            ..Default::default()
        }
    }
}

/// One input file of the conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub bytes: u64,
}

/// The report the source image came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReportRef {
    /// The `.info.json` that was read
    pub path: PathBuf,
    pub sha256: String,
    /// "acquisition" or "conversion"
    pub kind: String,
    /// Engine of an acquisition report ("e01", "raw", "rescue")
    pub engine: Option<String>,
    pub base_name: String,
    pub outcome: Outcome,
    pub exit_code: i32,
    pub outcome_reason: String,
    /// The digests the report states for the image content
    pub hashes: HashResults,
    /// What those digests are, e.g. "computed while reading the source medium"
    pub hashes_basis: String,
    /// Whether the report's own verification matched
    pub verified: bool,
}

/// One digest comparison made to verify the conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestComparison {
    /// Where the reference digests come from
    pub reference: String,
    pub reference_hashes: HashResults,
    /// What was compared with them
    pub compared: String,
    pub compared_hashes: HashResults,
    /// The reference was not produced by the conversion tool itself (only an
    /// independent comparison can verify the output)
    pub independent: bool,
    pub result: VerificationResult,
}

/// What the conversion applied (only settings that apply to the target).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionSettings {
    /// "ewfacquire" or "ewfexport"
    pub tool: String,
    /// "EWF (EnCase 6, .E01)" or "RAW (one file)"
    pub output_format: String,
    /// E01 only
    pub compression: Option<CompressionLevel>,
    /// E01 only: the segment size given to ewfacquire (`None` = one segment)
    pub segment_bytes: Option<u64>,
    /// Digests computed and compared
    pub digests: Vec<HashAlgorithm>,
    /// Sector size of the image (E01 header, size rule)
    pub bytes_per_sector: u32,
    /// E01 only: "fixed" or "removable"
    pub media_type: Option<String>,
    /// E01 only: "physical" or "logical"
    pub media_flags: Option<String>,
    /// E01 only: the notes written into the E01 header
    pub ewf_header_notes: Option<String>,
    /// Why values were chosen (e.g. defaults without an acquisition report)
    pub notes: Vec<String>,
}

impl ConversionSettings {
    /// (label, value) rows for the text report.
    pub fn rows(&self, target: ConversionTarget) -> Vec<(String, String)> {
        let mut rows = vec![
            ("Tool".to_string(), self.tool.clone()),
            ("Output Format".to_string(), self.output_format.clone()),
        ];
        if target == ConversionTarget::E01 {
            if let Some(c) = self.compression {
                rows.push(("Compression".into(), c.as_ewf_arg().to_string()));
            }
            rows.push((
                "Segment Size".into(),
                match self.segment_bytes {
                    Some(b) => format!("{} ({b} bytes)", format_iec(b)),
                    None => "one segment (no split)".into(),
                },
            ));
        }
        rows.push((
            "Digests".into(),
            self.digests
                .iter()
                .map(|d| d.label())
                .collect::<Vec<_>>()
                .join(", "),
        ));
        rows.push(("Bytes per Sector".into(), self.bytes_per_sector.to_string()));
        if let Some(t) = &self.media_type {
            rows.push(("Media Type".into(), t.clone()));
        }
        if let Some(f) = &self.media_flags {
            rows.push(("Media Flags".into(), f.clone()));
        }
        if let Some(n) = &self.ewf_header_notes {
            rows.push(("E01 Header Notes".into(), n.clone()));
        }
        rows
    }
}

/// What a conversion produced and how it was verified: the content of the
/// conversion report (`<base>.conversion.info` / `.info.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionReport {
    /// The source image as given (first segment)
    pub source: PathBuf,
    pub target: ConversionTarget,
    /// Image files written (E01 segments, or the RAW file)
    pub output_files: Vec<PathBuf>,
    /// Digests of the source image content the output was compared with
    /// (independent reference: the source report, the digests stored in the
    /// E01, or computed by dfdisk while reading the RAW image)
    pub source_hashes: HashResults,
    /// Digests recomputed from the written output after fsync and page-cache
    /// eviction (ewfverify for an E01, dfdisk for a RAW file)
    pub output_hashes: HashResults,
    /// Overall verification (from [`comparisons`](Self::comparisons))
    pub verification: VerificationResult,
    /// Derived by `classify` from the facts below; never set by hand
    pub outcome: Outcome,
    pub report_file: PathBuf,
    pub report_json_file: PathBuf,
    pub notes: Vec<String>,

    /// [`REPORT_SCHEMA_VERSION`]
    pub schema_version: u32,
    /// [`CONVERSION_REPORT_KIND`]
    pub report_kind: String,
    pub tool_name: String,
    pub tool_version: String,
    pub exit_code: i32,
    /// Why the verdict is what it is, one sentence
    pub outcome_reason: String,
    /// Recorded (sanitised) case values
    pub case_metadata: CaseMetadata,
    /// Where the case values came from, in the order they were applied
    pub case_sources: Vec<String>,
    /// "RAW image", "split RAW image (4 segments)", "EWF image (3 segments)"
    pub source_format: String,
    pub source_files: Vec<SourceFile>,
    pub source_report: Option<SourceReportRef>,
    pub output_dir: PathBuf,
    /// Outputs are `<output_dir>/<base_name>.<ext>`, the reports
    /// `<base_name>.conversion.info(.json)`
    pub base_name: String,
    pub settings: ConversionSettings,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub elapsed_seconds: u64,
    pub average_speed_bytes_sec: f64,
    /// Bytes of the source image (media data)
    pub expected_bytes: u64,
    /// Bytes of media data the output holds
    pub bytes_converted: u64,
    pub stop_reason: Option<String>,
    /// Stopped by the examiner or a signal
    pub aborted: bool,
    /// Ranges of the source image that do not hold data read from the
    /// medium, inherited from its acquisition (the source report, and for an
    /// E01 source the error list stored in the E01)
    pub read_errors: ReadErrorTable,
    /// What is known about unreadable ranges the table cannot list, e.g. an
    /// E01 whose header notes alone record zero-filled sectors
    #[serde(default)]
    pub read_errors_note: Option<String>,
    /// Sectors of the source image the conversion tool could not read and
    /// wrote as zeros into the output (ewfexport's "Read errors during
    /// export"); empty when it read every sector
    #[serde(default)]
    pub conversion_errors: ReadErrorTable,
    pub comparisons: Vec<DigestComparison>,
    /// How the output was verified, one line
    pub verification_method: String,
    /// Tool log, ewfexport's `.raw.info`, ...
    pub auxiliary_files: Vec<FileDigest>,
    pub provenance: ToolProvenance,
    pub clock: ClockInfo,
    pub audit: AuditInfo,
    /// SHA-256 of the written text report (not part of the report itself)
    #[serde(skip)]
    pub report_sha256: Option<String>,
    /// SHA-256 of the written JSON report (not part of the report itself)
    #[serde(skip)]
    pub report_json_sha256: Option<String>,
}

fn row(out: &mut String, label: &str, value: impl AsRef<str>) {
    out.push_str(&format!(
        "{:<width$}: {}\n",
        label,
        sanitize_line(value.as_ref()),
        width = LABEL_WIDTH
    ));
}

/// One sentence saying what a conversion verdict means.
pub fn conversion_explanation(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Verified => {
            "The whole source image was converted, and the digests recomputed from the written output match independent digests of the source image (its acquisition report, the digests stored in the E01, or dfdisk's own hash of the image)."
        }
        Outcome::CompleteUnverified => {
            "The whole source image was converted, but the output could not be compared with independent digests of the source image, or the source image itself was never verified against its medium (or its verification failed or found a mismatch), so the output is not confirmed to reproduce the medium's data."
        }
        Outcome::CompletedWithReadErrors => {
            "The whole source image was converted, but its acquisition could not read some sectors of the medium and the image holds zeros there; the output reproduces those zeros, so its digests describe the image including the substituted sectors, not the original medium."
        }
        Outcome::Incomplete => {
            "The output does not hold all of the source medium: the conversion stopped early, or the source image itself is incomplete (its acquisition stopped or left areas unread); the digests cover only what the output holds."
        }
        Outcome::Mismatch => {
            "A digest of the output differs from a digest of the source image, or the source image no longer matches its acquisition report: the output does not reproduce the acquired data."
        }
        Outcome::VerificationFailed => {
            "The conversion finished, but its verification could not be run or completed, so the output is not confirmed to reproduce the source image."
        }
        Outcome::Aborted => {
            "The conversion was stopped by the examiner or by a signal before it finished; the output files are partial and must not be used."
        }
    }
}

impl ConversionReport {
    /// An empty report for a conversion of `source` that is starting:
    /// nothing converted yet, so its verdict is `Incomplete` until the facts
    /// are filled in and [`apply_classification`](Self::apply_classification)
    /// runs.
    pub fn new(source: PathBuf, target: ConversionTarget, clock: ClockInfo) -> Self {
        let mut report = Self {
            source,
            target,
            output_files: Vec::new(),
            source_hashes: HashResults::default(),
            output_hashes: HashResults::default(),
            verification: VerificationResult::default(),
            outcome: Outcome::Incomplete,
            report_file: PathBuf::new(),
            report_json_file: PathBuf::new(),
            notes: Vec::new(),
            schema_version: REPORT_SCHEMA_VERSION,
            report_kind: CONVERSION_REPORT_KIND.into(),
            tool_name: "dfdisk".into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            exit_code: Outcome::Incomplete.exit_code(),
            outcome_reason: String::new(),
            case_metadata: CaseMetadata::default(),
            case_sources: Vec::new(),
            source_format: String::new(),
            source_files: Vec::new(),
            source_report: None,
            output_dir: PathBuf::new(),
            base_name: String::new(),
            settings: ConversionSettings::default(),
            started_at: clock.start_utc,
            ended_at: clock.start_utc,
            elapsed_seconds: 0,
            average_speed_bytes_sec: 0.0,
            expected_bytes: 0,
            bytes_converted: 0,
            stop_reason: None,
            aborted: false,
            read_errors: ReadErrorTable::default(),
            read_errors_note: None,
            conversion_errors: ReadErrorTable::default(),
            comparisons: Vec::new(),
            verification_method: String::new(),
            auxiliary_files: Vec::new(),
            provenance: ToolProvenance::default(),
            clock,
            audit: AuditInfo::default(),
            report_sha256: None,
            report_json_sha256: None,
        };
        report.apply_classification();
        report
    }

    pub fn exit_code(&self) -> i32 {
        self.outcome.exit_code()
    }

    /// The facts the verdict is derived from.
    pub fn facts(&self) -> AcquisitionFacts {
        AcquisitionFacts {
            expected_bytes: self.expected_bytes,
            bytes_acquired: self.bytes_converted,
            read_errors: self.read_errors.clone(),
            stop_reason: self.stop_reason.clone(),
            aborted: self.aborted,
            verification: self.verification.clone(),
            identity_changed: false,
        }
    }

    /// Set `outcome`, `exit_code` and `outcome_reason` from
    /// [`facts`](Self::facts) (the only way the verdict is set).
    pub fn apply_classification(&mut self) {
        let c = classify_detailed(&self.facts());
        self.outcome = c.outcome;
        self.exit_code = c.outcome.exit_code();
        self.outcome_reason = c.reason;
    }

    /// Base of the report files: `<base_name>.conversion`.
    pub fn report_base(&self) -> String {
        format!("{}{CONVERSION_STEM}", self.base_name)
    }

    /// The numbers behind the verdict, one sentence each.
    pub fn key_numbers(&self) -> Vec<String> {
        let mut out = Vec::new();
        let pct = if self.expected_bytes > 0 {
            format!("{}%, ", percent(self.bytes_converted, self.expected_bytes))
        } else {
            String::new()
        };
        out.push(format!(
            "Converted {} of {} bytes ({}{}).",
            self.bytes_converted,
            self.expected_bytes,
            pct,
            format_iec(self.bytes_converted)
        ));
        if let Some(s) = self.read_errors.summary(RangeKind::Substituted) {
            out.push(format!(
                "{s} of the source medium were unreadable during its acquisition and are zeros in the image and in the output."
            ));
        }
        if let Some(s) = self.read_errors.summary(RangeKind::Unread) {
            out.push(format!(
                "{s} of the source medium were never read by its acquisition and are not in the image."
            ));
        }
        if let Some(s) = self.conversion_errors.summary(RangeKind::Substituted) {
            out.push(format!(
                "{s} of the source image could not be read by the conversion and are zeros in the output, not data of the image."
            ));
        }
        if let Some(stop) = &self.stop_reason {
            out.push(format!("Stopped: {stop}."));
        }
        out.push(format!("Verification: {}.", self.verification.describe()));
        out
    }

    /// The verdict banner as lines (label with exit code, explanation, key
    /// numbers, timestamp basis), shared by the report, CLI and TUI.
    pub fn verdict_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "{} (exit code {})",
                self.outcome.label(),
                self.outcome.exit_code()
            ),
            conversion_explanation(self.outcome).to_string(),
        ];
        lines.extend(self.key_numbers());
        lines.push(format!("Timestamps: {}", self.clock.label()));
        lines
    }

    /// The human-readable report (`<base>.conversion.info`).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(RULE);
        out.push_str("                        DFDISK IMAGE CONVERSION REPORT\n");
        out.push_str(RULE);
        self.render_verdict(&mut out);
        out.push_str(RULE);
        out.push('\n');

        out.push_str("[CASE INFORMATION]\n");
        for (label, value) in self.case_metadata.report_rows() {
            row(&mut out, label, value);
        }
        row(
            &mut out,
            "Values Taken From",
            if self.case_sources.is_empty() {
                NOT_PROVIDED.to_string()
            } else {
                self.case_sources.join("; ")
            },
        );
        out.push('\n');

        self.render_source(&mut out);

        out.push_str("[CONVERSION SETTINGS (APPLIED)]\n");
        row(&mut out, "Conversion", self.target.label());
        for (label, value) in self.settings.rows(self.target) {
            row(&mut out, &label, value);
        }
        for n in &self.settings.notes {
            row(&mut out, "Note", n);
        }
        row(
            &mut out,
            "Output Directory",
            self.output_dir.to_string_lossy(),
        );
        row(&mut out, "Base Name", &self.base_name);
        out.push('\n');

        self.render_time(&mut out);
        self.render_read_errors(&mut out);
        self.render_conversion_errors(&mut out);
        self.render_verification(&mut out);
        self.render_files(&mut out);
        self.render_provenance(&mut out);
        self.render_audit(&mut out);
        if !self.notes.is_empty() {
            out.push_str("[NOTES]\n");
            for n in &self.notes {
                out.push_str(&format!(" - {}\n", sanitize_line(n)));
            }
            out.push('\n');
        }
        out.push_str(RULE);
        out
    }

    fn render_verdict(&self, out: &mut String) {
        let indent = " ".repeat(LABEL_WIDTH + 2);
        let lines = self.verdict_lines();
        let (head, rest) = lines.split_first().expect("verdict has a label");
        out.push_str(&format!(
            "{:<LABEL_WIDTH$}: {}\n",
            "VERDICT",
            sanitize_line(head)
        ));
        // The last verdict line is the timestamp basis, printed as its own row
        for line in &rest[..rest.len().saturating_sub(1)] {
            out.push_str(&indent);
            out.push_str(&sanitize_line(line));
            out.push('\n');
        }
        row(out, "Timestamps", self.clock.label());
        row(
            out,
            "Report Schema",
            format!(
                "{} conversion report (machine-readable twin: {}{})",
                self.schema_version, self.base_name, CONVERSION_INFO_JSON_SUFFIX
            ),
        );
    }

    fn render_source(&self, out: &mut String) {
        out.push_str("[SOURCE IMAGE]\n");
        row(out, "Image", self.source.to_string_lossy());
        row(out, "Format", &self.source_format);
        for f in &self.source_files {
            row(
                out,
                "File",
                format!("{} ({} bytes)", f.path.to_string_lossy(), f.bytes),
            );
        }
        row(
            out,
            "Media Data",
            format!(
                "{} bytes ({})",
                self.expected_bytes,
                format_iec(self.expected_bytes)
            ),
        );
        match &self.source_report {
            Some(r) => {
                row(
                    out,
                    "Source Report",
                    format!("{} (SHA-256 {})", r.path.to_string_lossy(), r.sha256),
                );
                row(
                    out,
                    "Its Verdict",
                    format!(
                        "{} (exit code {}): {}",
                        r.outcome.label(),
                        r.exit_code,
                        r.outcome_reason
                    ),
                );
                if let Some(engine) = &r.engine {
                    row(out, "Its Engine", engine);
                }
                row(out, "Its Digests", &r.hashes_basis);
            }
            None => row(
                out,
                "Source Report",
                "none: this report says nothing about the medium the image was made from",
            ),
        }
        out.push('\n');
    }

    fn render_time(&self, out: &mut String) {
        let c = &self.clock;
        out.push_str("[TIMESTAMPS & CLOCK]\n");
        let basis = if c.ntp_synchronized == Some(true) {
            "NTP synchronized"
        } else {
            LABEL_NOT_SYNCHRONIZED
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
                "{:.2} MiB/s",
                self.average_speed_bytes_sec / (1024.0 * 1024.0)
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
        row(
            out,
            "NTP Synchronized",
            match c.ntp_synchronized {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            },
        );
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
        out.push_str("[READ ERRORS OF THE SOURCE ACQUISITION]\n");
        if t.is_empty() {
            let known = self.source_report.is_some() || self.target == ConversionTarget::Raw;
            row(
                out,
                "Unreadable Ranges",
                match &self.read_errors_note {
                    Some(note) => note.as_str(),
                    None if known => "none recorded",
                    None => "unknown (no acquisition report)",
                },
            );
        } else {
            for kind in [RangeKind::Substituted, RangeKind::Unread] {
                if let Some(s) = t.summary(kind) {
                    row(out, kind.label(), s);
                }
            }
            self.render_ranges(out, t);
        }
        if !t.source.is_empty() {
            row(out, "Error List Source", &t.source);
        }
        out.push('\n');
    }

    /// The table of `t`'s ranges (the first [`TEXT_RANGE_LIMIT`]).
    fn render_ranges(&self, out: &mut String, t: &ReadErrorTable) {
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
                CONVERSION_INFO_JSON_SUFFIX
            ));
        }
    }

    /// Sectors the conversion itself could not read (only when there are).
    fn render_conversion_errors(&self, out: &mut String) {
        let t = &self.conversion_errors;
        if t.is_empty() {
            return;
        }
        out.push_str("[READ ERRORS OF THIS CONVERSION]\n");
        if let Some(s) = t.summary(RangeKind::Substituted) {
            row(
                out,
                "Zeros in the Output",
                format!("{s}: the source image could not be read there"),
            );
        }
        self.render_ranges(out, t);
        if !t.source.is_empty() {
            row(out, "Error List Source", &t.source);
        }
        out.push('\n');
    }

    fn render_verification(&self, out: &mut String) {
        out.push_str("[HASHES]\n");
        out.push_str("Source image (reference):\n");
        if self.source_hashes.is_empty() {
            out.push_str("  (none: no reference digest of the source image)\n");
        }
        for (label, digest) in self.source_hashes.present() {
            out.push_str(&format!("  {:<8}: {}\n", label, sanitize_line(digest)));
        }
        out.push_str("Output (recomputed from the written output):\n");
        if self.output_hashes.is_empty() {
            out.push_str("  (none: the output was not re-read)\n");
        }
        for (label, digest) in self.output_hashes.present() {
            out.push_str(&format!("  {:<8}: {}\n", label, sanitize_line(digest)));
        }
        out.push('\n');

        out.push_str("[VERIFICATION]\n");
        let result = if self.outcome == Outcome::Verified {
            format!(
                "VERIFIED - ALL COMPARED DIGESTS MATCH ({})",
                self.verification_method
            )
        } else {
            format!(
                "{} (overall verdict: {})",
                self.verification.describe(),
                self.outcome.label()
            )
        };
        row(out, "Result", result);
        if !self.verification_method.is_empty() {
            row(out, "Method", &self.verification_method);
        }
        for (i, c) in self.comparisons.iter().enumerate() {
            row(
                out,
                &format!("Comparison {}", i + 1),
                format!(
                    "{} vs {}{}: {}",
                    c.reference,
                    c.compared,
                    if c.independent {
                        ""
                    } else {
                        " (consistency check of the tool, not independent)"
                    },
                    comparison_status(&c.result)
                ),
            );
        }
        out.push('\n');
    }

    fn render_files(&self, out: &mut String) {
        out.push_str("[FILES]\n");
        if self.output_files.is_empty() {
            row(out, "Output Files", "(none)");
        }
        for f in &self.output_files {
            row(out, "Output File", f.to_string_lossy());
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
                out.push_str(&format!("  $ {}\n", sanitize_line(&c.command_line())));
                out.push_str(&format!(
                    "    {} .. {}  {}\n",
                    c.started.format("%H:%M:%S"),
                    c.ended.format("%H:%M:%S"),
                    sanitize_line(&c.status_text())
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
            row(
                out,
                "Audit Anchor",
                format!("{anchor} (\"conversion_started\" record)"),
            );
        }
        if let Some(f) = &self.audit.export_file {
            row(out, "Audit Log Copy", f);
        }
        out.push('\n');
    }

    /// The machine-readable report, pretty-printed.
    pub fn to_json(&self) -> String {
        let mut copy = self.clone();
        copy.clock.refresh_basis();
        serde_json::to_string_pretty(&copy).expect("a report always serialises")
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Write `<base>.conversion.info` and `<base>.conversion.info.json` into
    /// `output_dir` (reservation removed first, each written to `.tmp`,
    /// fsynced and renamed, then the directory fsynced) and record their
    /// paths and digests in the report.
    pub fn write_reports(&mut self) -> io::Result<ReportFiles> {
        let dir = self.output_dir.clone();
        let base = self.report_base();
        self.report_file = dir.join(format!("{}{CONVERSION_INFO_SUFFIX}", self.base_name));
        self.report_json_file = conversion_report_json_path(&dir, &self.base_name);
        remove_reserve_file(&dir, &base)?;
        let text = self.render_text();
        let json = self.to_json();
        write_atomic(&self.report_file, text.as_bytes())?;
        write_atomic(&self.report_json_file, json.as_bytes())?;
        sync_dir(&dir)?;
        let files = ReportFiles {
            text: self.report_file.clone(),
            json: self.report_json_file.clone(),
            text_sha256: sha256_hex(text.as_bytes()),
            json_sha256: sha256_hex(json.as_bytes()),
        };
        self.report_sha256 = Some(files.text_sha256.clone());
        self.report_json_sha256 = Some(files.json_sha256.clone());
        Ok(files)
    }
}

/// `done` of `total` as a percentage with one decimal, rounded down: "100.0"
/// only when everything is done.
fn percent(done: u64, total: u64) -> String {
    if total == 0 || done >= total {
        return "100.0".into();
    }
    let tenths = (u128::from(done) * 1000 / u128::from(total)) as u64;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// A comparison's result without repeating what was compared: "matched
/// (MD5, SHA-256)", "MISMATCH: ...", "not possible: ...", "FAILED: ...".
fn comparison_status(result: &VerificationResult) -> String {
    match result {
        VerificationResult::Matched { method } => format!(
            "matched{}",
            method
                .rfind(" (")
                .filter(|_| method.ends_with(')'))
                .map(|i| &method[i..])
                .unwrap_or("")
        ),
        VerificationResult::Mismatched { details, .. } => format!("MISMATCH: {details}"),
        other => other.describe(),
    }
}

/// `<dir>/<base>.conversion.info.json`.
pub fn conversion_report_json_path(dir: &Path, base: &str) -> PathBuf {
    dir.join(format!("{base}{CONVERSION_INFO_JSON_SUFFIX}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::outcome::exit_code;

    fn report() -> ConversionReport {
        let mut r = ConversionReport::new(
            "/img/x.raw".into(),
            ConversionTarget::E01,
            ClockInfo::default(),
        );
        r.base_name = "x".into();
        r.output_dir = "/out".into();
        r.expected_bytes = 4096;
        r.bytes_converted = 4096;
        r.source_format = "RAW image".into();
        r
    }

    fn matched() -> VerificationResult {
        VerificationResult::Matched {
            method: "ewfverify".into(),
        }
    }

    #[test]
    fn verdict_comes_from_the_facts() {
        let mut r = report();
        r.verification = matched();
        r.verification_method = "ewfverify".into();
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::Verified);
        assert_eq!(r.exit_code(), exit_code::VERIFIED);
        assert!(r
            .render_text()
            .contains("VERIFIED - ALL COMPARED DIGESTS MATCH"));

        // Inherited substituted sectors: never "verified", even when matched
        r.read_errors = ReadErrorTable::new(512, "acquisition report x.info.json");
        r.read_errors.push(1024, 512, RangeKind::Substituted);
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::CompletedWithReadErrors);
        assert_eq!(r.exit_code, exit_code::READ_ERRORS);
        let text = r.render_text();
        assert!(!text.contains("ALL COMPARED DIGESTS MATCH"), "{text}");
        assert!(
            text.contains("zeros in the image and in the output"),
            "{text}"
        );

        // Short output
        let mut r = report();
        r.verification = matched();
        r.bytes_converted = 2048;
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::Incomplete);

        // Abort wins
        r.aborted = true;
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::Aborted);
        assert!(r.verdict_lines()[1].contains("must not be used"));

        // Nothing to compare with
        let mut r = report();
        r.verification = VerificationResult::NotPossible {
            reason: "nothing independent".into(),
        };
        r.apply_classification();
        assert_eq!(r.outcome, Outcome::CompleteUnverified);
        assert_eq!(r.exit_code, exit_code::UNVERIFIED);
    }

    #[test]
    fn json_round_trip_and_report_names() {
        let tmp = tempfile::tempdir().unwrap();
        let mut r = report();
        r.output_dir = tmp.path().to_path_buf();
        r.notes.push("line\nwith control\u{1b}[31m chars".into());
        r.verification = matched();
        r.apply_classification();
        // A reservation exists before the reports are written
        crate::models::info_report::create_reserve_file(tmp.path(), &r.report_base()).unwrap();
        let files = r.write_reports().unwrap();
        assert_eq!(files.text, tmp.path().join("x.conversion.info"));
        assert_eq!(files.json, tmp.path().join("x.conversion.info.json"));
        assert!(!tmp.path().join("x.conversion.info.reserve").exists());
        let json = std::fs::read_to_string(&files.json).unwrap();
        assert_eq!(files.json_sha256, sha256_hex(json.as_bytes()));
        let back = ConversionReport::from_json(&json).unwrap();
        assert_eq!(back.outcome, Outcome::Verified);
        assert_eq!(back.report_kind, CONVERSION_REPORT_KIND);
        assert_eq!(back.report_file, files.text);
        assert_eq!(r.report_sha256.as_deref(), Some(files.text_sha256.as_str()));
        let text = std::fs::read_to_string(&files.text).unwrap();
        assert!(!text.contains('\u{1b}'));
        assert!(text.starts_with(RULE));
    }

    #[test]
    fn missing_case_values_print_as_not_provided() {
        let mut r = report();
        r.case_metadata = CaseMetadata {
            case_number: "C1".into(),
            evidence_number: "E1".into(),
            examiner: "Ex".into(),
            ..Default::default()
        }
        .sanitized();
        let text = r.render_text();
        assert!(
            text.contains("Description           : (not provided)"),
            "{text}"
        );
        assert!(
            text.contains("Values Taken From     : (not provided)"),
            "{text}"
        );
        assert!(text.contains("unknown (no acquisition report)"), "{text}");
    }

    #[test]
    fn settings_rows_only_name_what_applies() {
        let s = ConversionSettings {
            tool: "ewfexport".into(),
            output_format: "RAW (one file)".into(),
            compression: Some(CompressionLevel::Best),
            segment_bytes: Some(1 << 30),
            digests: vec![HashAlgorithm::MD5, HashAlgorithm::SHA256],
            bytes_per_sector: 512,
            ..Default::default()
        };
        let rows = s.rows(ConversionTarget::Raw);
        assert!(rows
            .iter()
            .all(|(l, _)| l != "Compression" && l != "Segment Size"));
        let rows = s.rows(ConversionTarget::E01);
        assert!(rows
            .iter()
            .any(|(l, v)| l == "Segment Size" && v.contains("1 GiB")));
    }
}
