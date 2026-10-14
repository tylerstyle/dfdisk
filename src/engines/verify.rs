//! Re-verification of an existing image (§13 Verify), used by the CLI
//! (`dfdisk verify`) and the TUI.
//!
//! EWF images (`.E01`, `.Ex01`, `.E02`..., `.s01`, or the EVF signature) are
//! re-read by `ewfverify -d md5,sha1,sha256` on their first segment; anything
//! else is hashed by dfdisk. The digests are compared with the expected ones
//! (given, or taken from a report `.info.json`): every requested digest must
//! have been computed and must match; a requested digest that was not
//! computed is a failed verification, never a pass. The result is written as
//! an addendum `<base>.verify-<UTC>.txt` next to the image and as an audit
//! `image_verification` record.

use crate::engines::audit;
use crate::engines::error::AcquisitionError;
use crate::engines::ewf::parse_calculated_hash;
use crate::engines::hasher::{HashProgress, MultiHasher};
use crate::engines::process::{self, ProcessEvent, ProcessSpec, StreamTag};
use crate::models::config::HashAlgorithm;
use crate::models::info_report::{
    sha256_file, sync_dir, ForensicInfoReport, HashResults, HashSelection,
};
use crate::models::outcome::{exit_code, VerificationResult};
use crate::models::provenance::{
    ClockInfo, ProvenanceRecorder, DFCORE_GIT_REV, DFDISK_GIT_REV, DFDISK_VERSION,
};
use crate::models::text::sanitize_line;
use crate::signals::StopFlags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::sync::mpsc;

/// Digest list ewfverify recomputes.
const EWF_DIGESTS: &str = "md5,sha1,sha256";

/// How the image was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedFormat {
    /// Expert Witness Format, through ewfverify
    Ewf,
    /// Any other file, hashed by dfdisk
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
}

/// Compare `computed` with `expected` (pure). `tool_failure`: the reader
/// reported an error (ewfverify FAILURE or a non-zero exit). Rules, in order:
/// tool failure -> Failed; nothing expected -> NotPossible (digests only
/// computed); any difference -> Mismatched; a requested digest that was not
/// computed -> Failed; else Matched.
pub fn decide(
    computed: &HashResults,
    expected: &ExpectedHashes,
    tool_failure: Option<&str>,
    method: &str,
) -> (Vec<AlgorithmCheck>, VerificationResult) {
    let checks: Vec<AlgorithmCheck> = expected
        .selection()
        .algorithms()
        .into_iter()
        .map(|alg| {
            let want = expected.get(alg).unwrap_or_default().to_string();
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
            }
        })
        .collect();
    let result = if let Some(reason) = tool_failure {
        VerificationResult::Failed {
            reason: reason.to_string(),
        }
    } else if checks.is_empty() {
        VerificationResult::NotPossible {
            reason: "no expected digest was given; the digests were only computed".into(),
        }
    } else {
        let mismatches: Vec<String> = checks
            .iter()
            .filter(|c| c.status == CheckStatus::Mismatch)
            .map(|c| {
                format!(
                    "{} expected {} but computed {}",
                    c.algorithm.label(),
                    c.expected,
                    c.computed.as_deref().unwrap_or_default()
                )
            })
            .collect();
        let missing: Vec<&str> = checks
            .iter()
            .filter(|c| c.status == CheckStatus::NotComputed)
            .map(|c| c.algorithm.label())
            .collect();
        if !mismatches.is_empty() {
            VerificationResult::Mismatched {
                method: method.to_string(),
                details: mismatches.join("; "),
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
        }
    };
    (checks, result)
}

/// Exit code of a verification: 0 matched (or digests only computed), 5
/// mismatch, 4 failed.
pub fn verification_exit_code(result: &VerificationResult) -> i32 {
    match result {
        VerificationResult::Matched { .. } | VerificationResult::NotPossible { .. } => {
            exit_code::VERIFIED
        }
        VerificationResult::Mismatched { .. } => exit_code::MISMATCH,
        VerificationResult::Failed { .. } => exit_code::FAILED,
    }
}

/// Everything a verification found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVerification {
    /// The image as given
    pub image: PathBuf,
    /// The file actually read (first EWF segment)
    pub read_path: PathBuf,
    pub format: VerifiedFormat,
    /// e.g. "ewfverify -d md5,sha1,sha256"
    pub method: String,
    pub computed: HashResults,
    pub expected: ExpectedHashes,
    pub checks: Vec<AlgorithmCheck>,
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
    /// What could not be done (addendum, audit record)
    pub warnings: Vec<String>,
}

impl ImageVerification {
    /// Matched, or digests only computed.
    pub fn passed(&self) -> bool {
        self.exit_code == exit_code::VERIFIED
    }

    /// One line: "VERIFIED (...)", "HASH MISMATCH: ...", ...
    pub fn verdict(&self) -> String {
        match &self.result {
            VerificationResult::Matched { .. } => {
                "VERIFIED: every expected digest matches the image".into()
            }
            VerificationResult::NotPossible { .. } => {
                "DIGESTS COMPUTED: no expected digest was given, nothing was compared".into()
            }
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
        for (label, digest) in self.computed.present() {
            row(&format!("Computed {label}"), digest);
        }
        for c in &self.checks {
            let status = match c.status {
                CheckStatus::Match => "MATCH".to_string(),
                CheckStatus::Mismatch => format!("MISMATCH (expected {})", c.expected),
                CheckStatus::NotComputed => format!("NOT COMPUTED (expected {})", c.expected),
            };
            row(&format!("Check {}", c.algorithm.label()), &status);
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
            "format".into(),
            serde_json::to_value(self.format).unwrap_or_default(),
        );
        d.insert("method".into(), json!(self.method));
        d.insert("expected_from".into(), json!(self.expected.source));
        d.insert(
            "computed".into(),
            serde_json::to_value(&self.computed).unwrap_or_default(),
        );
        d.insert(
            "checks".into(),
            serde_json::to_value(&self.checks).unwrap_or_default(),
        );
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

/// Extension of an EWF segment file: E01..E99, EAA..EZZ, s01.., Ex01.. (any case).
fn is_ewf_extension(ext: &str) -> bool {
    let b = ext.as_bytes();
    let lead = |c: u8| matches!(c.to_ascii_lowercase(), b'e' | b's' | b'l');
    match b.len() {
        3 => {
            lead(b[0])
                && ((b[1].is_ascii_digit() && b[2].is_ascii_digit())
                    || (b[1].is_ascii_alphabetic() && b[2].is_ascii_alphabetic()))
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
/// `.EAA`, `.s01`, `.L01`, any case) or by the EVF/LVF signature.
pub fn is_ewf_image_file(path: &Path) -> bool {
    let by_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(is_ewf_extension);
    if by_ext {
        return true;
    }
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
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
/// `x.Ex02` -> `x.Ex01`), when it exists; else `path` itself.
pub fn ewf_first_segment(path: &Path) -> PathBuf {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return path.to_path_buf();
    };
    if !is_ewf_extension(ext) {
        return path.to_path_buf();
    }
    let keep = if ext.len() == 4 { 2 } else { 1 };
    let first = path.with_extension(format!("{}01", &ext[..keep]));
    if first.exists() {
        first
    } else {
        path.to_path_buf()
    }
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
    /// Hashing progress of a RAW image
    Progress(HashProgress),
    /// A line ewfverify printed (stderr and progress)
    ToolOutput(String),
}

/// What [`verify_image`] writes besides its result.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Write `<base>.verify-<UTC>.txt` next to the image
    pub write_addendum: bool,
    /// Audit log for the `image_verification` record; `None`: no record
    pub audit_log: Option<PathBuf>,
    /// Records the ewfverify command line
    pub recorder: Option<ProvenanceRecorder>,
}

impl VerifyOptions {
    /// Addendum and audit record on this host's log (CLI, TUI).
    pub fn recorded() -> Self {
        Self {
            write_addendum: true,
            audit_log: Some(audit::log_path()),
            recorder: None,
        }
    }
}

/// Re-verify `image` against `expected`. `Err` only when the image could not
/// be read at all (missing file: usage; tool missing or read error: failed;
/// abort: aborted); a failing or mismatching image is an `Ok` result with
/// its exit code.
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
    let clock = tokio::task::spawn_blocking(ClockInfo::capture_start)
        .await
        .unwrap_or_default();
    let t0 = Instant::now();
    let started_at = clock.start_utc;

    let (format, read_path, method, computed, tool_failure) = if is_ewf_image_file(image) {
        let first = ewf_first_segment(image);
        let spec = ProcessSpec::new("ewfverify")
            .args(["-d", EWF_DIGESTS])
            .arg(&first)
            .grace(std::time::Duration::from_secs(5));
        let mut computed = HashResults::default();
        let mut success = false;
        let outcome = process::run(
            &spec,
            &stop.stop_control(),
            options.recorder.as_ref(),
            |ev| {
                if let ProcessEvent::Line { stream, text, .. } = ev {
                    let text = text.trim();
                    if text.is_empty() {
                        return;
                    }
                    if stream == StreamTag::Stdout {
                        if text.contains("ewfverify: SUCCESS") {
                            success = true;
                        }
                        match parse_calculated_hash(text) {
                            Some(("md5", v)) => computed.md5 = Some(v),
                            Some(("sha1", v)) => computed.sha1 = Some(v),
                            Some(("sha256", v)) => computed.sha256 = Some(v),
                            _ => {}
                        }
                    } else {
                        on_event(VerifyEvent::ToolOutput(text.to_string()));
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
        let failure = (!outcome.success() || !success).then(|| {
            format!(
                "ewfverify reported an error in the EWF structure or media checksums ({})",
                outcome.record.status_text()
            )
        });
        (
            VerifiedFormat::Ewf,
            first,
            format!("ewfverify -d {EWF_DIGESTS}"),
            computed,
            failure,
        )
    } else {
        let (tx, mut rx) = mpsc::channel::<HashProgress>(64);
        let path = image.to_path_buf();
        let abort = stop.abort.clone();
        let task = tokio::spawn(async move {
            MultiHasher::hash_stream_with_abort(&path, true, true, true, Some(tx), Some(abort))
                .await
        });
        while let Some(p) = rx.recv().await {
            on_event(VerifyEvent::Progress(p));
        }
        let computed = task
            .await
            .map_err(|e| AcquisitionError::failed(format!("hashing task failed: {e}")))?
            .map_err(|e| {
                if stop.is_aborted() {
                    AcquisitionError::aborted("verification aborted")
                } else {
                    AcquisitionError::failed(e)
                }
            })?;
        (
            VerifiedFormat::Raw,
            image.to_path_buf(),
            "file hashed by dfdisk (MD5, SHA-1, SHA-256)".to_string(),
            computed,
            None,
        )
    };

    let (checks, result) = decide(&computed, expected, tool_failure.as_deref(), &method);
    let mut clock = clock;
    let elapsed = t0.elapsed();
    clock.finish(elapsed);
    let mut v = ImageVerification {
        image: image.to_path_buf(),
        read_path,
        format,
        method,
        computed,
        expected: expected.clone(),
        checks,
        exit_code: verification_exit_code(&result),
        result,
        started_at,
        ended_at: clock.end_utc.unwrap_or_else(Utc::now),
        elapsed_seconds: elapsed.as_secs_f64(),
        clock,
        addendum: None,
        addendum_sha256: None,
        audit_record: None,
        warnings: Vec::new(),
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
        // Nothing expected: computed only (exit 0, as in 0.1)
        let (checks, r) = decide(
            &c,
            &ExpectedHashes::given(None, Some("  ".into()), None),
            None,
            "m",
        );
        assert!(checks.is_empty());
        assert!(matches!(r, VerificationResult::NotPossible { .. }));
        assert_eq!(verification_exit_code(&r), 0);
        // A tool failure is a failure even when the digests match
        let (_, r) = decide(
            &c,
            &ExpectedHashes::given(Some(MD5.into()), None, None),
            Some("ewfverify FAILURE"),
            "m",
        );
        assert!(matches!(r, VerificationResult::Failed { .. }));
    }

    #[test]
    fn ewf_segments_are_recognised() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "a.E01", "a.e01", "a.Ex01", "a.E02", "a.EAB", "a.s01", "a.L01", "a.ex02",
        ] {
            assert!(is_ewf_image_file(&tmp.path().join(name)), "{name}");
        }
        for name in ["a.raw", "a.dd", "a.info", "a.E1", "a.E001", "a.Exx1", "a"] {
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
        r.acquisition_hashes.md5 = Some(MD5.into());
        let e = ExpectedHashes::from_report(&r, "x.info.json");
        assert_eq!(e.md5.as_deref(), Some(MD5));
        assert_eq!(e.sha256, None);
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
            crate::engines::ErrorKind::Usage
        );
    }

    #[tokio::test]
    async fn raw_verification_writes_addendum_and_audit_record() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("case_ea01_ev1_SER.raw");
        std::fs::write(&image, b"hello world").unwrap();
        let log = tmp.path().join("audit.jsonl");
        let options = VerifyOptions {
            write_addendum: true,
            audit_log: Some(log.clone()),
            recorder: None,
        };
        let expected = ExpectedHashes::given(Some(MD5.into()), None, Some(SHA256.into()));
        let mut events = 0;
        let v = verify_image(&image, &expected, &options, &StopFlags::new(), |_| {
            events += 1
        })
        .await
        .unwrap();
        assert!(v.passed(), "{:?}", v.result);
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
        assert_eq!(e.kind, crate::engines::ErrorKind::Usage);
        let stop = StopFlags::new();
        stop.abort.store(true, std::sync::atomic::Ordering::SeqCst);
        let e = verify_image(&image, &bad, &opts, &stop, |_| {})
            .await
            .unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Aborted);
    }
}
