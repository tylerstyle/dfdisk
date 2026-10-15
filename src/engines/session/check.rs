//! `dfdisk check`: the dry run of steps 1-6 (§4, §15). It probes and decides
//! exactly like an acquisition but writes nothing and sets nothing: no
//! directory, no reservation, no audit record, no read-only flag (the plan is
//! described), no SMART JSON file. The exclusive open is tried and released.

use super::{
    destination_checks, identify, missing_tools, source_safety, tool_options_error, tools_error,
    validate, SessionHost,
};
use crate::discovery::writeprotect::{self, WriteProtectDecision};
use crate::engines::error::{AcquisitionError, ErrorKind};
use crate::engines::preflight::DestinationFacts;
use crate::engines::process::StopControl;
use crate::models::capacity::CapacityInfo;
use crate::models::config::{EffectiveConfig, EngineKind, SmartPolicy};
use crate::models::device::SmartSnapshot;
use crate::models::identity::SourceIdentity;
use crate::models::outcome::exit_code;
use crate::models::protection::WriteProtection;
use crate::models::provenance::ProvenanceRecorder;
use crate::models::text::sanitize_line;
use serde::Serialize;
use std::path::PathBuf;

/// One reason the acquisition would not start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckProblem {
    /// "request", "tools", "identity", "source safety", "exclusive open",
    /// "destination", "capacity"
    pub step: String,
    pub kind: ErrorKind,
    pub message: String,
}

/// What `check` found. `ready` iff there is no problem.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub ready: bool,
    pub device: String,
    pub engine: EngineKind,
    pub output_dir: PathBuf,
    pub base_name: Option<String>,
    pub identity: Option<SourceIdentity>,
    pub tool_source_path: Option<String>,
    pub effective_config: Option<EffectiveConfig>,
    /// The state as found (nothing was changed)
    pub write_protection: Option<WriteProtection>,
    /// What an acquisition would do about write protection
    pub write_protection_plan: Option<String>,
    pub destination: Option<DestinationFacts>,
    pub capacity: Option<CapacityInfo>,
    pub smart: Option<SmartSnapshot>,
    /// The external programs the engine runs that are not installed (empty:
    /// none is missing); None when the check stopped before the tools step
    pub missing_tools: Option<Vec<String>>,
    pub problems: Vec<CheckProblem>,
    pub notes: Vec<String>,
}

impl CheckReport {
    fn problem(&mut self, step: &str, e: AcquisitionError) {
        self.problems.push(CheckProblem {
            step: step.to_string(),
            kind: e.kind,
            message: e.message,
        });
        self.ready = false;
    }

    /// The first problem as an error.
    pub fn first_error(&self) -> Option<AcquisitionError> {
        self.problems
            .first()
            .map(|p| AcquisitionError::new(p.kind, p.message.clone()))
    }

    /// 0 when ready; else the exit code of the first problem (2 usage, 3
    /// refused, 4 failed).
    pub fn exit_code(&self) -> i32 {
        match self.problems.first() {
            None => exit_code::VERIFIED,
            Some(p) => p.kind.exit_code(),
        }
    }

    /// Human-readable readiness report.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let mut row = |label: &str, value: &str| {
            out.push_str(&format!("{:<22}: {}\n", label, sanitize_line(value)));
        };
        row(
            "Readiness",
            if self.ready {
                "READY: every check passed (nothing was written or changed)"
            } else {
                "NOT READY: the acquisition would not start (see below)"
            },
        );
        row("Source", &self.device);
        row("Engine", self.engine.label());
        row("Output Directory", &self.output_dir.to_string_lossy());
        if let Some(b) = &self.base_name {
            row("Base Name", b);
        }
        if let Some(id) = &self.identity {
            row(
                "Identity",
                &format!("{} ({})", id.display_name(), id.kind.label()),
            );
            row("Serial Number", &id.serial_with_provenance());
            row("Size", &format!("{} bytes", id.size_bytes));
        }
        if let Some(p) = &self.tool_source_path {
            row("Tool Source Path", p);
        }
        if let Some(wp) = &self.write_protection {
            row("Write Protection Now", &wp.summary());
        }
        if let Some(plan) = &self.write_protection_plan {
            row("Write Protection Plan", plan);
        }
        if let Some(d) = &self.destination {
            row("Destination", &d.summary());
        }
        if let Some(c) = &self.capacity {
            row("Hidden Areas", &c.summary());
        }
        if let Some(s) = &self.smart {
            row(
                "SMART",
                &format!("{} ({})", s.summary.health.label(), s.summary.assessment),
            );
        }
        for p in &self.problems {
            row(&format!("{} [{}]", p.kind.label(), p.step), &p.message);
        }
        for n in &self.notes {
            row("Note", n);
        }
        out
    }
}

fn plan_text(decision: WriteProtectDecision) -> String {
    match decision {
        WriteProtectDecision::RecordOnly { reason } => format!("record only: {reason}"),
        WriteProtectDecision::AlreadyReadOnly => {
            "nothing to set: every node is already read-only".into()
        }
        WriteProtectDecision::Set { nodes, notes } => {
            let mut s = format!(
                "would set read-only (BLKROSET): {}",
                nodes
                    .iter()
                    .map(|n| format!("/dev/{n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if !notes.is_empty() {
                s.push_str(&format!(" ({})", notes.join("; ")));
            }
            s
        }
    }
}

pub(super) async fn run_check(
    host: &dyn SessionHost,
    request: super::AcquisitionRequest,
) -> CheckReport {
    let mut report = CheckReport {
        ready: true,
        device: request.device.path.clone(),
        engine: request.engine(),
        output_dir: request.config.output_dir.clone(),
        base_name: None,
        identity: None,
        tool_source_path: None,
        effective_config: None,
        write_protection: None,
        write_protection_plan: None,
        destination: None,
        capacity: None,
        smart: None,
        missing_tools: None,
        problems: Vec::new(),
        notes: Vec::new(),
    };
    let v = match validate(&request) {
        Ok(v) => v,
        Err(e) => {
            report.problem("request", e);
            return report;
        }
    };
    report.base_name = Some(v.base_name.clone());
    let identity = match identify(host, &request) {
        Ok((id, _)) => id,
        Err(e) => {
            report.problem("identity", e);
            return report;
        }
    };
    report.identity = Some(identity.clone());
    report.effective_config = Some(EffectiveConfig::build(&request.config, Some(&identity)));
    report.tool_source_path = Some(host.tool_source_path(&identity));

    let safety = source_safety(host, &request, &identity);
    report.notes.extend(safety.notes.iter().cloned());
    let safe = safety.errors.is_empty();
    for e in safety.errors {
        report.problem("source safety", e);
    }
    if let Ok(mountinfo) = host.mountinfo() {
        let inputs = writeprotect::decision_inputs(&host.sysfs(), &identity, &mountinfo);
        report.write_protection_plan = Some(plan_text(writeprotect::decide(
            request.config.write_protect,
            &inputs,
        )));
    }
    report.write_protection = Some(safety.write_protection);
    if safe {
        // Tried and released at once: the claim is only held by a real run
        if let Err(e) = host.open_source(&identity) {
            report.problem("exclusive open", e);
        }
    }
    match destination_checks(host, &request, &identity, v.engine, &v.base_name) {
        Ok(d) => {
            report.notes.extend(d.notes);
            report.destination = Some(d.facts);
        }
        Err(e) => report.problem("destination", e),
    }
    let missing = missing_tools(host, &request.config);
    report.missing_tools = Some(missing.iter().map(|t| t.to_string()).collect());
    if let Err(e) = tools_error(&request.config, &missing)
        .and_then(|()| tool_options_error(host, &request.config))
    {
        report.problem("tools", e);
    }

    // Identify-class queries only when nothing refused the source (P4)
    if report.problems.is_empty() && identity.is_block_device() {
        let recorder = ProvenanceRecorder::new();
        let control = StopControl::none();
        let capacity = host.capacity(&identity, &control, &recorder).await;
        if capacity.hidden_area() == Some(true) {
            let statements = capacity.hidden_area_statements().join("; ");
            if request.config.refuse_hidden_areas {
                report.problem(
                    "capacity",
                    AcquisitionError::refused(format!(
                        "the disk of the source hides sectors ({statements}); refused by --refuse-hidden-areas"
                    )),
                );
            } else {
                report.notes.push(format!("HIDDEN AREA: {statements}"));
            }
        }
        report.capacity = Some(capacity);
        if request.config.smart != SmartPolicy::Off {
            report.smart = host
                .smart(&identity, request.config.smart, None, &control, &recorder)
                .await;
        }
    }
    report.ready = report.problems.is_empty();
    report
}
