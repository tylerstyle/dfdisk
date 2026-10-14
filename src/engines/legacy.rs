//! Report scaffolding shared by the 0.1 engines until `engines::session`
//! runs them (D3). It records what those engines know: the identity comes
//! from the device scan (not re-probed, and the report says so), there is no
//! write-protection, capacity or SMART record, and the verdict is still
//! derived by `classify` from the facts the engine measured.

use crate::models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, EffectiveConfig, EngineKind},
    device::BlockDevice,
    identity::SourceIdentity,
    info_report::{AuditStatus, ForensicInfoReport, ReportFiles},
    provenance::{ClockInfo, ToolProvenance},
};
use chrono::{DateTime, Utc};
use std::path::Path;
use std::time::Instant;

/// Start of a run: wall clock, monotonic clock, host clock state.
pub(crate) struct RunClock {
    pub start: DateTime<Utc>,
    pub instant: Instant,
    pub clock: ClockInfo,
}

impl RunClock {
    pub fn start() -> Self {
        let clock = ClockInfo::capture_start();
        Self {
            start: clock.start_utc,
            instant: Instant::now(),
            clock,
        }
    }
}

/// A report with the scan identity, the applied settings, provenance and
/// audit anchor filled in.
pub(crate) fn new_report(
    engine: EngineKind,
    device: &BlockDevice,
    case: &CaseMetadata,
    config: &AcquisitionConfig,
    base_name: &str,
    run: &RunClock,
    audit_anchor: &Option<String>,
) -> ForensicInfoReport {
    let source = SourceIdentity::from_block_device(device);
    let effective = EffectiveConfig::build(config, Some(&source));
    let mut r = ForensicInfoReport::new(engine, case, source, effective);
    r.output_dir = config.output_dir.to_string_lossy().into_owned();
    r.base_name = base_name.to_string();
    r.started_at = run.start;
    r.identity_check.details.push(
        "identity taken from the device scan; this engine version does not re-probe it".into(),
    );
    r.provenance = ToolProvenance::capture();
    r.audit.anchor = audit_anchor.clone();
    r.audit.status = if audit_anchor.is_some() {
        AuditStatus::Written
    } else {
        AuditStatus::NotWritten {
            reason: "the audit log could not be written (see the warning printed at the start)"
                .into(),
        }
    };
    r
}

/// Close the report: end time, elapsed time from the monotonic clock,
/// average speed over `bytes`, clock state, and the verdict.
pub(crate) fn finish_report(r: &mut ForensicInfoReport, run: &RunClock, bytes: u64) {
    let elapsed = run.instant.elapsed();
    r.ended_at = Utc::now();
    r.elapsed_seconds = elapsed.as_secs();
    r.average_speed_bytes_sec = if elapsed.as_secs_f64() > 0.0 {
        bytes as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    r.clock = run.clock.clone();
    r.clock.finish(elapsed);
    r.apply_classification();
}

pub(crate) fn write_reports(
    r: &ForensicInfoReport,
    dir: &Path,
    base: &str,
) -> Result<ReportFiles, String> {
    r.write_reports(dir, base)
        .map_err(|e| format!("Failed to write the forensic report: {e}"))
}
