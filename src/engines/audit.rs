//! dfdisk's records in the dfnix audit log (dfcore): every acquisition writes
//! "acquisition_started" before the source is read (its hash is the report's
//! audit anchor) and "acquisition_finished" on every path afterwards, carrying
//! the outcome, exit code, read-error summary, every known digest, the SHA-256
//! of both reports and the files ([`FinishedGuard`] writes it even when the run
//! ends by an error, a cancellation or a panic, or when the report could not
//! be written). Refusals are recorded by their
//! [`ErrorKind`](crate::engines::ErrorKind), never by message text. The
//! top-level outcome of a record with a verdict is `error` for MISMATCH,
//! INCOMPLETE, ABORTED and VERIFICATION FAILED ([`outcome_for_exit_code`]).
//!
//! A refusal before "started" (identity, source safety, destination) is one
//! "acquisition_refused" record ([`refused`]). Further records: [`unmount`],
//! [`image_verification`],
//! [`conversion_started`] / [`conversion_finished`].
//!
//! Every function takes the log path (normally [`log_path`], which honours
//! `DFNIX_AUDIT_LOG`), so tests use their own logs. On dfnix (protected-device
//! registry present) a "started" record that cannot be written refuses the
//! acquisition; elsewhere it is a warning in the report and the UI. Warnings
//! never go to stderr: a TUI may own the terminal.

use crate::engines::error::AcquisitionError;
use crate::engines::preflight::DestinationFacts;
use crate::engines::progress::ProgressSink;
use crate::models::case::CaseMetadata;
use crate::models::config::{EffectiveConfig, EngineKind};
use crate::models::identity::SourceIdentity;
use crate::models::info_report::{AuditInfo, AuditStatus, ForensicInfoReport, ReportFiles};
use crate::models::outcome::{RangeKind, VerificationResult};
use crate::models::protection::RegistryPresence;
use dfcore::audit::{Event, Outcome};
use dfcore::lsblk::DeviceIdentity;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

/// Tool name in every record.
pub const TOOL: &str = "dfdisk";
/// dfdisk version in every record.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Record actions written by dfdisk.
pub mod action {
    pub const ACQUISITION_STARTED: &str = "acquisition_started";
    pub const ACQUISITION_FINISHED: &str = "acquisition_finished";
    pub const ACQUISITION_REFUSED: &str = "acquisition_refused";
    pub const UNMOUNT: &str = "unmount";
    pub const IMAGE_VERIFICATION: &str = "image_verification";
    pub const CONVERSION_STARTED: &str = "conversion_started";
    pub const CONVERSION_FINISHED: &str = "conversion_finished";
    pub const CONVERSION_REFUSED: &str = "conversion_refused";
}

/// The audit log of this host (`DFNIX_AUDIT_LOG` or /run/dfnix/audit.jsonl).
pub fn log_path() -> PathBuf {
    dfcore::audit::path()
}

/// Append `event` to the log at `log`: the record's hash, or why it was not
/// written.
pub fn append(log: &Path, event: Event) -> Result<String, String> {
    match dfcore::audit::append_to(log, event) {
        Ok(rec) => rec.hash.ok_or_else(|| "the record has no hash".to_string()),
        Err(e) => Err(format!("{e:#}")),
    }
}

/// What the "acquisition_started" record states.
#[derive(Debug, Clone, Copy)]
pub struct StartedRecord<'a> {
    pub engine: EngineKind,
    /// Identity probed at the start (maj:min, diskseq, serial, ...)
    pub identity: &'a SourceIdentity,
    pub case: &'a CaseMetadata,
    pub effective: &'a EffectiveConfig,
    pub output_dir: &'a Path,
    pub base_name: &'a str,
    /// Path external tools read the source through (R3)
    pub tool_source_path: &'a str,
    pub destination: Option<&'a DestinationFacts>,
    pub registry: &'a RegistryPresence,
}

/// The "acquisition_started" event (pure).
pub fn started_event(r: &StartedRecord<'_>) -> Event {
    let case = r.case.sanitized();
    let id = r.identity;
    Event::new(TOOL, VERSION, action::ACQUISITION_STARTED)
        .device(id.device_identity())
        .detail("engine", r.engine.tag())
        .detail("base_name", r.base_name)
        .detail("output_dir", r.output_dir.to_string_lossy().into_owned())
        .detail("tool_source_path", r.tool_source_path)
        .detail(
            "case",
            json!({
                "case_number": case.case_number,
                "evidence_number": case.evidence_number,
                "examiner": case.examiner,
            }),
        )
        .detail(
            "source",
            json!({
                "path": id.path,
                "kind": id.kind.label(),
                "maj_min": id.maj_min,
                "diskseq": id.diskseq,
                "size_bytes": id.size_bytes,
                "serial": id.serial,
                "serial_source": id.serial_source().map(|s| s.label()),
                "wwn": id.wwn,
                "parent_disks": id.parent_disks,
            }),
        )
        .detail(
            "effective_config",
            serde_json::to_value(r.effective).unwrap_or_default(),
        )
        .detail(
            "destination",
            r.destination
                .map(|d| serde_json::to_value(d).unwrap_or_default())
                .unwrap_or(Value::Null),
        )
        .detail("dfnix_registry", r.registry.label())
}

/// Write "acquisition_started" (§4 step 7, R7). Returns the report's audit
/// info: the anchor when written; when it cannot be written, `NotWritten` off
/// dfnix (the caller must warn), and a refusal on dfnix (registry present),
/// where no evidence may be read unrecorded.
pub fn started(log: &Path, record: &StartedRecord<'_>) -> Result<AuditInfo, AcquisitionError> {
    match append(log, started_event(record)) {
        Ok(hash) => Ok(AuditInfo {
            anchor: Some(hash),
            status: AuditStatus::Written,
            export_file: None,
        }),
        Err(reason) => {
            if *record.registry != RegistryPresence::Absent {
                Err(AcquisitionError::refused(format!(
                    "the dfnix audit log {} cannot be written ({reason}); on dfnix every acquisition is recorded before the source is read",
                    log.display()
                )))
            } else {
                Ok(AuditInfo {
                    anchor: None,
                    status: AuditStatus::NotWritten {
                        reason: format!(
                            "the audit log {} cannot be written: {reason}",
                            log.display()
                        ),
                    },
                    export_file: None,
                })
            }
        }
    }
}

fn read_error_summary(report: &ForensicInfoReport) -> Value {
    let t = &report.read_errors;
    json!({
        "source": t.source,
        "sector_size": t.effective_sector_size(),
        "ranges": t.ranges.len(),
        "substituted_ranges": t.count(RangeKind::Substituted),
        "unread_ranges": t.count(RangeKind::Unread),
        "substituted_bytes": t.substituted_bytes(),
        "unread_bytes": t.unread_bytes(),
        "substituted_sectors": t.substituted_sectors(),
        "unread_sectors": t.unread_sectors(),
    })
}

/// The top-level outcome of a record of a run that ended with a verdict
/// (acquisition, conversion, verification): `error` for exit codes 4
/// (verification failed), 5 (mismatch), 6 (incomplete) and 8 (aborted), `ok`
/// for 0 (verified), 7 (completed with read errors) and 9 (complete, not
/// verified); any other code is an error.
pub fn outcome_for_exit_code(code: i32) -> Outcome {
    use crate::models::outcome::exit_code as x;
    match code {
        x::VERIFIED | x::READ_ERRORS | x::UNVERIFIED => Outcome::Ok,
        _ => Outcome::Error,
    }
}

/// "VERIFIED (exit code 0)": the record message of a verdict.
fn verdict_message(outcome: crate::models::outcome::Outcome, exit_code: i32) -> String {
    format!("{} (exit code {exit_code})", outcome.label())
}

/// Details of the "acquisition_finished" record of a run with a report
/// (pure): outcome, exit code, read-error summary, every digest, the report
/// digests (null when the report could not be written, `files` = `None`)
/// and the files.
pub fn finished_details(
    report: &ForensicInfoReport,
    files: Option<&ReportFiles>,
) -> Map<String, Value> {
    let mut d = Map::new();
    let mut put = |k: &str, v: Value| {
        d.insert(k.to_string(), v);
    };
    put("engine", json!(report.engine.tag()));
    put("anchor", json!(report.audit.anchor));
    put(
        "outcome",
        serde_json::to_value(report.outcome).unwrap_or_default(),
    );
    put("exit_code", json!(report.exit_code));
    put("outcome_reason", json!(report.outcome_reason));
    put("bytes_acquired", json!(report.bytes_acquired));
    put("expected_bytes", json!(report.expected_bytes));
    put("stop_reason", json!(report.stop_reason));
    put("aborted", json!(report.aborted));
    put("read_errors", read_error_summary(report));
    put(
        "acquisition_hashes",
        serde_json::to_value(&report.acquisition_hashes).unwrap_or_default(),
    );
    put(
        "image_hashes",
        serde_json::to_value(&report.image_hashes).unwrap_or_default(),
    );
    put(
        "verification",
        serde_json::to_value(&report.verification).unwrap_or_default(),
    );
    put("identity_end_ok", json!(report.identity_check.end_ok));
    put(
        "write_protection",
        report
            .write_protection
            .as_ref()
            .map(|wp| json!({ "summary": wp.summary(), "nodes_set": wp.nodes_set }))
            .unwrap_or(Value::Null),
    );
    put(
        "capacity",
        report
            .capacity
            .as_ref()
            .map(|c| json!(c.summary()))
            .unwrap_or(Value::Null),
    );
    for (key, snap) in [
        ("smart_before", &report.smart_before),
        ("smart_after", &report.smart_after),
    ] {
        put(
            key,
            snap.as_ref()
                .map(|s| json!(s.summary.health.label()))
                .unwrap_or(Value::Null),
        );
    }
    put("report_written", json!(files.is_some()));
    put(
        "report_file",
        json!(files.map(|f| f.text.to_string_lossy().into_owned())),
    );
    put(
        "report_json_file",
        json!(files.map(|f| f.json.to_string_lossy().into_owned())),
    );
    put("report_sha256", json!(files.map(|f| &f.text_sha256)));
    put("report_json_sha256", json!(files.map(|f| &f.json_sha256)));
    put("files", json!(report.image_files));
    put(
        "auxiliary_files",
        serde_json::to_value(&report.auxiliary_files).unwrap_or_default(),
    );
    put(
        "piecewise",
        serde_json::to_value(&report.piecewise).unwrap_or_default(),
    );
    put("audit_export", json!(report.audit.export_file));
    d
}

/// Details of the "acquisition_finished" record of a run that ended by an
/// error, without a report (pure).
pub fn error_details(engine: EngineKind, err: &AcquisitionError) -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("engine".into(), json!(engine.tag()));
    d.insert(
        "error_kind".into(),
        serde_json::to_value(err.kind).unwrap_or_default(),
    );
    d.insert("outcome".into(), json!(err.kind.label()));
    d.insert("exit_code".into(), json!(err.exit_code()));
    d.insert("report_written".into(), json!(false));
    d
}

/// Writes the "acquisition_finished" record exactly once: through
/// [`report`](Self::report) or [`error`](Self::error), or, if the run ends
/// any other way after "started" (panic unwinding, a cancelled future), when
/// dropped. A record that cannot be written is a warning on the progress sink.
#[derive(Debug)]
pub struct FinishedGuard {
    log: PathBuf,
    device: DeviceIdentity,
    engine: EngineKind,
    anchor: Option<String>,
    sink: ProgressSink,
    armed: bool,
}

impl FinishedGuard {
    pub fn new(
        log: impl Into<PathBuf>,
        device: DeviceIdentity,
        engine: EngineKind,
        anchor: Option<String>,
        sink: ProgressSink,
    ) -> Self {
        Self {
            log: log.into(),
            device,
            engine,
            anchor,
            sink,
            armed: true,
        }
    }

    fn event(
        &self,
        outcome: Outcome,
        message: Option<String>,
        details: Map<String, Value>,
    ) -> Event {
        let mut e = Event::new(TOOL, VERSION, action::ACQUISITION_FINISHED)
            .device(self.device.clone())
            .outcome(outcome, message);
        e.details = details;
        e.details
            .entry("anchor")
            .or_insert_with(|| json!(self.anchor));
        e
    }

    fn write(&mut self, event: Event) -> Result<String, String> {
        self.armed = false;
        let r = append(&self.log, event);
        if let Err(reason) = &r {
            self.sink.warn(format!(
                "the audit record \"acquisition_finished\" was not written: {reason}"
            ));
        }
        r
    }

    /// The run produced a report (any outcome, aborted included). The
    /// record's outcome is `error` for verdicts 4, 5, 6 and 8
    /// ([`outcome_for_exit_code`]).
    pub fn report(
        mut self,
        report: &ForensicInfoReport,
        files: &ReportFiles,
    ) -> Result<String, String> {
        let event = self.event(
            outcome_for_exit_code(report.exit_code),
            Some(verdict_message(report.outcome, report.exit_code)),
            finished_details(report, Some(files)),
        );
        self.write(event)
    }

    /// The run reached a verdict but its report could not be written
    /// (`err`): the record carries everything the report would have (the
    /// digests, the read errors, the files), the report digests are null,
    /// `report_written` is false, `exit_code` is the process exit code of
    /// `err` and `verdict_exit_code` that of the verdict.
    pub fn report_not_written(
        mut self,
        report: &ForensicInfoReport,
        err: &AcquisitionError,
    ) -> Result<String, String> {
        let mut details = finished_details(report, None);
        details.insert("exit_code".into(), json!(err.exit_code()));
        details.insert("verdict_exit_code".into(), json!(report.exit_code));
        details.insert(
            "error_kind".into(),
            serde_json::to_value(err.kind).unwrap_or_default(),
        );
        details.insert("error".into(), json!(err.message));
        let event = self.event(err.audit_outcome(), Some(err.message.clone()), details);
        self.write(event)
    }

    /// The run ended by an error after "started" without a report
    /// (refusal, failure, or an abort before anything was written).
    pub fn error(mut self, err: &AcquisitionError) -> Result<String, String> {
        let event = self.event(
            err.audit_outcome(),
            Some(err.message.clone()),
            error_details(self.engine, err),
        );
        self.write(event)
    }
}

impl Drop for FinishedGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let message = if std::thread::panicking() {
            "the acquisition ended by an internal error (panic) without a result"
        } else {
            "the acquisition ended without a result (cancelled)"
        };
        let mut details = Map::new();
        details.insert("engine".into(), json!(self.engine.tag()));
        details.insert("report_written".into(), json!(false));
        details.insert(
            "exit_code".into(),
            json!(crate::models::outcome::exit_code::INTERNAL_ERROR),
        );
        let event = self.event(Outcome::Error, Some(message.into()), details);
        let _ = self.write(event);
    }
}

/// Record a refusal before "acquisition_started" (§4 steps 2-4: identity,
/// source safety, destination): the attempt is in the log although nothing
/// was written to the destination and nothing was read from the source.
/// `device` is the probed identity when the probe succeeded, else the
/// selected device.
pub fn refused(
    log: &Path,
    device: DeviceIdentity,
    engine: EngineKind,
    err: &AcquisitionError,
) -> Result<String, String> {
    let mut event = Event::new(TOOL, VERSION, action::ACQUISITION_REFUSED)
        .device(device)
        .outcome(err.audit_outcome(), Some(err.message.clone()));
    event.details = error_details(engine, err);
    append(log, event)
}

/// Record an explicit unmount of the source tree (§10): the mounts found,
/// those unmounted, and the result.
pub fn unmount(
    log: &Path,
    identity: &SourceIdentity,
    mounts: &[String],
    result: Result<&[String], &AcquisitionError>,
) -> Result<String, String> {
    let mut event = Event::new(TOOL, VERSION, action::UNMOUNT)
        .device(identity.device_identity())
        .detail("mounts_before", json!(mounts));
    event = match result {
        Ok(done) => event.detail("unmounted", json!(done)),
        Err(e) => event
            .detail(
                "error_kind",
                serde_json::to_value(e.kind).unwrap_or_default(),
            )
            .outcome(e.audit_outcome(), Some(e.message.clone())),
    };
    append(log, event)
}

/// Record a re-verification of an existing image (§13 Verify).
pub fn image_verification(
    log: &Path,
    image: &Path,
    result: &VerificationResult,
    exit_code: i32,
    details: Map<String, Value>,
) -> Result<String, String> {
    let mut event = Event::new(TOOL, VERSION, action::IMAGE_VERIFICATION);
    event.details = details;
    event
        .details
        .insert("image".into(), json!(image.to_string_lossy()));
    event.details.insert(
        "result".into(),
        serde_json::to_value(result).unwrap_or_default(),
    );
    event.details.insert("exit_code".into(), json!(exit_code));
    event = event.outcome(
        outcome_for_exit_code(exit_code),
        Some(format!("{} (exit code {exit_code})", result.describe())),
    );
    append(log, event)
}

/// Record the start of a conversion (§13 Converter); the hash is the anchor
/// of its report.
pub fn conversion_started(
    log: &Path,
    source: &Path,
    target: &Path,
    details: Map<String, Value>,
) -> Result<String, String> {
    let mut event = Event::new(TOOL, VERSION, action::CONVERSION_STARTED);
    event.details = details;
    event
        .details
        .insert("source".into(), json!(source.to_string_lossy()));
    event
        .details
        .insert("target".into(), json!(target.to_string_lossy()));
    append(log, event)
}

/// Record a refused conversion (§13 Converter, before
/// "conversion_started": nothing was written), mirroring
/// "acquisition_refused": the source, the intended output, why, and
/// `details` (target format, output directory, base name when known).
pub fn conversion_refused(
    log: &Path,
    source: &Path,
    target: &Path,
    err: &AcquisitionError,
    details: Map<String, Value>,
) -> Result<String, String> {
    let mut event = Event::new(TOOL, VERSION, action::CONVERSION_REFUSED)
        .outcome(err.audit_outcome(), Some(err.message.clone()));
    event.details = details;
    event.details.insert(
        "error_kind".into(),
        serde_json::to_value(err.kind).unwrap_or_default(),
    );
    event
        .details
        .insert("exit_code".into(), json!(err.exit_code()));
    event
        .details
        .insert("source".into(), json!(source.to_string_lossy()));
    event
        .details
        .insert("target".into(), json!(target.to_string_lossy()));
    append(log, event)
}

/// Record how a conversion ended: `Ok(details)` (outcome, digests, report
/// digests, files) or the error.
pub fn conversion_finished(
    log: &Path,
    source: &Path,
    target: &Path,
    anchor: Option<&str>,
    result: Result<Map<String, Value>, &AcquisitionError>,
) -> Result<String, String> {
    let mut event = Event::new(TOOL, VERSION, action::CONVERSION_FINISHED);
    match result {
        Ok(details) => {
            // The verdict decides the record's outcome, as for acquisitions
            if let Some(code) = details
                .get("exit_code")
                .and_then(Value::as_i64)
                .and_then(|c| i32::try_from(c).ok())
            {
                let message = details
                    .get("outcome")
                    .cloned()
                    .and_then(|o| serde_json::from_value::<crate::models::outcome::Outcome>(o).ok())
                    .map(|o| verdict_message(o, code))
                    .unwrap_or_else(|| format!("exit code {code}"));
                event = event.outcome(outcome_for_exit_code(code), Some(message));
            }
            event.details = details;
        }
        Err(e) => {
            event = event
                .detail(
                    "error_kind",
                    serde_json::to_value(e.kind).unwrap_or_default(),
                )
                .detail("exit_code", e.exit_code())
                .outcome(e.audit_outcome(), Some(e.message.clone()));
        }
    }
    event
        .details
        .insert("source".into(), json!(source.to_string_lossy()));
    event
        .details
        .insert("target".into(), json!(target.to_string_lossy()));
    event.details.insert("anchor".into(), json!(anchor));
    append(log, event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::config::AcquisitionConfig;
    use crate::models::identity::SerialSource;
    use crate::models::info_report::HashResults;

    fn identity() -> SourceIdentity {
        let mut id = SourceIdentity {
            path: "/dev/sdb".into(),
            canonical_path: "/dev/sdb".into(),
            kernel_name: "sdb".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(9),
            size_bytes: 4096,
            logical_sector_size: 512,
            physical_sector_size: 512,
            ..Default::default()
        };
        id.add_serial_candidate("SER9", SerialSource::VpdPage80);
        id
    }

    fn case() -> CaseMetadata {
        CaseMetadata {
            case_number: "C1".into(),
            evidence_number: "E1".into(),
            examiner: "X".into(),
            ..Default::default()
        }
    }

    fn records(log: &Path) -> Vec<Value> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn started_record<'a>(
        id: &'a SourceIdentity,
        case: &'a CaseMetadata,
        eff: &'a EffectiveConfig,
        registry: &'a RegistryPresence,
    ) -> StartedRecord<'a> {
        StartedRecord {
            engine: EngineKind::Raw,
            identity: id,
            case,
            effective: eff,
            output_dir: Path::new("/out"),
            base_name: "c1_ea01_e1_SER9",
            tool_source_path: "/dev/disk/by-diskseq/9",
            destination: None,
            registry,
        }
    }

    #[test]
    fn started_records_identity_and_config_and_gives_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let (id, case) = (identity(), case());
        let eff = EffectiveConfig::build(&AcquisitionConfig::raw("/out"), Some(&id));
        let info = started(
            &log,
            &started_record(&id, &case, &eff, &RegistryPresence::Absent),
        )
        .unwrap();
        assert_eq!(info.status, AuditStatus::Written);
        let recs = records(&log);
        assert_eq!(recs[0]["hash"], json!(info.anchor));
        assert_eq!(recs[0]["action"], "acquisition_started");
        assert_eq!(recs[0]["device"]["maj_min"], "8:16");
        assert_eq!(recs[0]["device"]["diskseq"], 9);
        assert_eq!(
            recs[0]["details"]["source"]["serial_source"],
            "SCSI VPD page 0x80"
        );
        assert_eq!(recs[0]["details"]["effective_config"]["engine"], "raw");
        assert_eq!(
            recs[0]["details"]["tool_source_path"],
            "/dev/disk/by-diskseq/9"
        );
    }

    #[test]
    fn unwritable_log_refuses_on_dfnix_and_warns_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x").unwrap();
        let log = blocker.join("audit.jsonl");
        let (id, case) = (identity(), case());
        let eff = EffectiveConfig::build(&AcquisitionConfig::raw("/out"), Some(&id));
        let e = started(
            &log,
            &started_record(&id, &case, &eff, &RegistryPresence::Present),
        )
        .unwrap_err();
        assert!(e.is_refusal());
        assert!(e.message.contains("on dfnix"), "{e}");
        let info = started(
            &log,
            &started_record(&id, &case, &eff, &RegistryPresence::Absent),
        )
        .unwrap();
        assert!(info.anchor.is_none());
        let AuditStatus::NotWritten { reason } = info.status else {
            panic!()
        };
        assert!(reason.contains("cannot be written"), "{reason}");
    }

    #[test]
    fn finished_guard_records_errors_by_kind_and_fires_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let sink = ProgressSink::disconnected();
        let guard = FinishedGuard::new(
            &log,
            identity().device_identity(),
            EngineKind::Ewf,
            Some("a".into()),
            sink.clone(),
        );
        guard
            .error(&AcquisitionError::refused("cannot write-protect"))
            .unwrap();
        let guard = FinishedGuard::new(
            &log,
            identity().device_identity(),
            EngineKind::Ewf,
            None,
            sink.clone(),
        );
        guard
            .error(&AcquisitionError::failed("Refusing words are not refusals"))
            .unwrap();
        {
            let _guard = FinishedGuard::new(
                &log,
                identity().device_identity(),
                EngineKind::Raw,
                Some("b".into()),
                sink.clone(),
            );
        }
        let recs = records(&log);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0]["outcome"], "refused");
        assert_eq!(recs[0]["details"]["error_kind"], "refused");
        assert_eq!(recs[0]["details"]["exit_code"], 3);
        assert_eq!(recs[0]["details"]["anchor"], "a");
        assert_eq!(recs[1]["outcome"], "error");
        assert_eq!(recs[1]["details"]["exit_code"], 4);
        assert_eq!(recs[2]["outcome"], "error");
        assert!(recs[2]["message"].as_str().unwrap().contains("cancelled"));
        assert_eq!(recs[2]["details"]["anchor"], "b");
        assert!(sink.warnings().is_empty());

        // A record that cannot be written is a visible warning
        let blocker = dir.path().join("f");
        std::fs::write(&blocker, b"x").unwrap();
        let guard = FinishedGuard::new(
            blocker.join("log"),
            identity().device_identity(),
            EngineKind::Raw,
            None,
            sink.clone(),
        );
        assert!(guard.error(&AcquisitionError::failed("x")).is_err());
        assert_eq!(sink.warnings().len(), 1);
    }

    #[test]
    fn finished_details_carry_everything_the_report_knows() {
        let id = identity();
        let eff = EffectiveConfig::build(&AcquisitionConfig::raw("/out"), Some(&id));
        let mut r = ForensicInfoReport::new(EngineKind::Raw, &case(), id, eff);
        r.bytes_acquired = 4096;
        r.read_errors.push(512, 512, RangeKind::Substituted);
        r.acquisition_hashes = HashResults {
            md5: Some("aa".into()),
            ..Default::default()
        };
        r.image_files = vec!["/out/x.raw".into()];
        r.apply_classification();
        let files = ReportFiles {
            text: "/out/x.info".into(),
            json: "/out/x.info.json".into(),
            text_sha256: "t".into(),
            json_sha256: "j".into(),
        };
        let d = finished_details(&r, Some(&files));
        assert_eq!(d["outcome"], serde_json::to_value(r.outcome).unwrap());
        assert_eq!(d["exit_code"], r.exit_code);
        assert_eq!(d["read_errors"]["substituted_sectors"], 1);
        assert_eq!(d["acquisition_hashes"]["md5"], "aa");
        assert_eq!(d["report_sha256"], "t");
        assert_eq!(d["report_json_sha256"], "j");
        assert_eq!(d["report_written"], true);
        assert_eq!(d["files"][0], "/out/x.raw");
        // Without a written report: everything else, report digests null
        let d = finished_details(&r, None);
        assert_eq!(d["report_written"], false);
        assert!(d["report_sha256"].is_null() && d["report_file"].is_null());
        assert_eq!(d["acquisition_hashes"]["md5"], "aa");
        assert_eq!(d["files"][0], "/out/x.raw");
    }

    #[test]
    fn records_with_a_verdict_are_errors_unless_the_verdict_is_good() {
        use crate::models::outcome::Outcome as Verdict;
        let ok: Vec<i32> = Verdict::ALL
            .iter()
            .map(Verdict::exit_code)
            .filter(|c| outcome_for_exit_code(*c) == Outcome::Ok)
            .collect();
        assert_eq!(ok, [0, 9, 7]);
        for code in [1, 2, 3, 4, 5, 6, 8] {
            assert_eq!(outcome_for_exit_code(code), Outcome::Error, "{code}");
        }

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = identity();
        let eff = EffectiveConfig::build(&AcquisitionConfig::raw("/out"), Some(&id));
        let files = ReportFiles {
            text: "/out/x.info".into(),
            json: "/out/x.info.json".into(),
            text_sha256: "t".into(),
            json_sha256: "j".into(),
        };
        let guard = |anchor: &str| {
            FinishedGuard::new(
                &log,
                identity().device_identity(),
                EngineKind::Raw,
                Some(anchor.into()),
                ProgressSink::disconnected(),
            )
        };
        // INCOMPLETE: an error record with the verdict as its message
        let mut r = ForensicInfoReport::new(EngineKind::Raw, &case(), id.clone(), eff.clone());
        r.bytes_acquired = 512;
        r.apply_classification();
        guard("a").report(&r, &files).unwrap();
        // VERIFIED: ok
        r.bytes_acquired = r.expected_bytes;
        r.verification.result = VerificationResult::Matched { method: "m".into() };
        r.apply_classification();
        assert_eq!(r.exit_code, 0);
        guard("b").report(&r, &files).unwrap();
        // The report could not be written: an error record that still
        // carries the verdict and the digests
        r.acquisition_hashes.md5 = Some("aa".into());
        guard("c")
            .report_not_written(&r, &AcquisitionError::failed("disk full"))
            .unwrap();
        // A verification: mismatch is an error, with a message
        image_verification(
            &log,
            Path::new("/x.raw"),
            &VerificationResult::Mismatched {
                method: "m".into(),
                details: "MD5 differs".into(),
            },
            5,
            Map::new(),
        )
        .unwrap();
        image_verification(
            &log,
            Path::new("/x.raw"),
            &VerificationResult::Matched { method: "m".into() },
            0,
            Map::new(),
        )
        .unwrap();
        // A conversion with a verdict
        let mut d = Map::new();
        d.insert("outcome".into(), json!("aborted"));
        d.insert("exit_code".into(), json!(8));
        conversion_finished(&log, Path::new("/a"), Path::new("/b"), None, Ok(d)).unwrap();

        let recs = records(&log);
        let got: Vec<(&str, &str)> = recs
            .iter()
            .map(|r| {
                (
                    r["outcome"].as_str().unwrap(),
                    r["message"].as_str().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(got[0], ("error", "INCOMPLETE (exit code 6)"));
        assert_eq!(got[1], ("ok", "VERIFIED (exit code 0)"));
        assert_eq!(got[2], ("error", "disk full"));
        assert_eq!(recs[2]["details"]["report_written"], false);
        assert_eq!(recs[2]["details"]["exit_code"], 4);
        assert_eq!(recs[2]["details"]["verdict_exit_code"], 0);
        assert_eq!(recs[2]["details"]["outcome"], "verified");
        assert_eq!(recs[2]["details"]["acquisition_hashes"]["md5"], "aa");
        assert!(recs[2]["details"]["report_sha256"].is_null());
        assert_eq!(got[3].0, "error");
        assert!(
            got[3].1.starts_with("MISMATCH (m): MD5 differs"),
            "{}",
            got[3].1
        );
        assert_eq!(got[4], ("ok", "matched (m) (exit code 0)"));
        assert_eq!(got[5], ("error", "ABORTED (exit code 8)"));
        assert!(dfcore::audit::verify(&log).is_ok());
    }

    #[test]
    fn other_records() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let id = identity();
        let mounts = vec!["/mnt/a".to_string()];
        unmount(&log, &id, &mounts, Ok(&mounts)).unwrap();
        unmount(
            &log,
            &id,
            &mounts,
            Err(&AcquisitionError::refused("system mount")),
        )
        .unwrap();
        image_verification(
            &log,
            Path::new("/case/x.E01"),
            &VerificationResult::Failed {
                reason: "SHA-1 not computed".into(),
            },
            4,
            Map::new(),
        )
        .unwrap();
        let anchor =
            conversion_started(&log, Path::new("/a.raw"), Path::new("/b"), Map::new()).unwrap();
        conversion_finished(
            &log,
            Path::new("/a.raw"),
            Path::new("/b"),
            Some(&anchor),
            Err(&AcquisitionError::aborted("stop")),
        )
        .unwrap();
        let recs = records(&log);
        let actions: Vec<(&str, &str)> = recs
            .iter()
            .map(|r| {
                (
                    r["action"].as_str().unwrap(),
                    r["outcome"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            actions,
            [
                ("unmount", "ok"),
                ("unmount", "refused"),
                ("image_verification", "error"),
                ("conversion_started", "ok"),
                ("conversion_finished", "error"),
            ]
        );
        assert_eq!(recs[0]["details"]["unmounted"][0], "/mnt/a");
        assert_eq!(recs[2]["details"]["exit_code"], 4);
        assert_eq!(recs[4]["details"]["anchor"], json!(anchor));
        assert_eq!(recs[4]["details"]["exit_code"], 8);
        assert!(dfcore::audit::verify(&log).is_ok());
    }
}
