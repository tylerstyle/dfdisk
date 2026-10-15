//! The TUI state machine (§16). [`App`] reacts to keys ([`App::handle_key`]),
//! to the periodic tick ([`App::tick`]: background results, progress,
//! periodic device refresh) and to signals ([`App::on_signal`]). Everything
//! that touches the host runs off the UI thread through the
//! [`TuiBackend`](crate::tui::backend::TuiBackend) and reports back over a
//! channel; the UI thread only draws and edits state.
//!
//! Flow: device explorer (selection keyed by identity) -> case setup (required
//! fields, engine-specific options) -> confirmation sheet (`check_with`,
//! typed serial suffix, R10) -> acquisition (`run_with` with the process'
//! [`AbortController`], reset between runs) -> persistent result screen.
//! The converter and the re-verification have their own forms and share the
//! confirmation sheet (converter), the progress and the result screens.

use crate::discovery::safety::UnmountResult;
use crate::engines::preflight::{self, DestinationFacts, MIN_FREE_BYTES};
use crate::engines::session::{AcquisitionRequest, CheckReport};
use crate::engines::verify::{ExpectedHashes, ImageVerification, VerifyEvent};
use crate::engines::{AcquisitionError, ErrorKind};
use crate::models::capacity::CapacityInfo;
use crate::models::case::CaseMetadata;
use crate::models::config::{EngineKind, SmartPolicy};
use crate::models::conversion::{ConversionReport, ConversionRequest, ConversionTarget};
use crate::models::device::BlockDevice;
use crate::models::info_report::{AuditStatus, ForensicInfoReport, INFO_JSON_SUFFIX, INFO_SUFFIX};
use crate::models::outcome::{Outcome, RangeKind, VerificationResult};
use crate::models::telemetry::{AcquisitionStatus, PhaseProgress, ProgressTelemetry};
use crate::models::text::{format_iec, sanitize_line};
use crate::signals::{AbortController, SignalAction, SignalKind};
use crate::tui::autocomplete::{expand_tilde, find_path_completions, longest_common_prefix};
use crate::tui::backend::{HostBackend, OfflineBackend, TuiBackend};
use crate::tui::confirm::ConfirmTarget;
use crate::tui::devices::{
    invalidation_notice, reconcile, source_rows, Badge, Reconciled, SelectionKey, SourceRow,
};
use crate::tui::form::{
    case_text, case_text_mut, report_candidate, AcqForm, ConvField, ConvForm, Field, SourceFacts,
    SourceReport, VerField, VerifyForm,
};
use crate::tui::profile::{self, CaseProfile};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use std::collections::HashMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub use crate::tui::input::edit_text;

/// Smallest terminal the layouts are made for.
pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;
/// Background device refresh (hot-plug) while a source is being chosen.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
/// Informational notices disappear after this; warnings and errors stay
/// until the examiner dismisses them.
pub const INFO_TTL: Duration = Duration::from_secs(4);
/// Delay between the last keystroke in a path and its probe.
pub const PROBE_DEBOUNCE: Duration = Duration::from_millis(400);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Explorer,
    CaseSetup,
    Confirm,
    Running,
    Result,
    Converter,
    Verify,
}

/// A dialog over the current screen; it takes every key until closed.
#[derive(Debug, Clone)]
pub enum Modal {
    Help,
    /// Explicit, audited unmount of the source tree of `device`
    Unmount {
        device: Box<BlockDevice>,
        key: SelectionKey,
        mounts: Vec<String>,
        /// Continue to the case setup afterwards
        then_setup: bool,
    },
    /// y/N before a graceful abort
    Abort,
    /// y/N before killing external tools at once
    Force,
    /// Ctrl+C while busy: abort and quit after the report is written
    Quit,
    /// A ddrescue map of this base name exists: resume?
    Resume {
        map: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Warning,
    Error,
}

/// A message in the notification area. Info expires after [`INFO_TTL`];
/// warnings and errors stay until dismissed (Ctrl+X).
#[derive(Debug, Clone)]
pub struct Notice {
    pub text: String,
    pub level: Level,
    pub at: Instant,
}

/// A text input (for path completion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    Case(Field),
    Conv(ConvField),
    Verify(VerField),
}

/// Path completion candidates shown under an input.
#[derive(Debug, Clone)]
pub struct Completion {
    pub input: Input,
    pub candidates: Vec<String>,
    /// Candidate currently applied (None: only the common prefix)
    pub index: Option<usize>,
    /// Text after the cursor, kept
    pub suffix: String,
    pub token: u64,
    /// Waiting for the directory listing
    pub pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Acquisition,
    Conversion,
    Verification,
}

impl JobKind {
    pub fn label(&self) -> &'static str {
        match self {
            JobKind::Acquisition => "acquisition",
            JobKind::Conversion => "conversion",
            JobKind::Verification => "verification",
        }
    }
}

/// A running acquisition, conversion or verification.
#[derive(Debug)]
pub struct Job {
    pub kind: JobKind,
    pub telemetry: ProgressTelemetry,
    progress_rx: Option<mpsc::Receiver<ProgressTelemetry>>,
    verify_rx: Option<mpsc::UnboundedReceiver<VerifyEvent>>,
    pub started: Instant,
    /// What runs (source identity, destination), for the progress screen
    pub summary: Vec<(String, String)>,
    /// A second source read follows the verification
    pub verify_source: bool,
    pub abort_requested: bool,
    pub force_requested: bool,
}

impl Job {
    /// A job with no background work attached (rendering previews and
    /// tests): its telemetry only changes when set directly.
    pub fn detached(
        kind: JobKind,
        telemetry: ProgressTelemetry,
        summary: Vec<(String, String)>,
        verify_source: bool,
    ) -> Self {
        Self {
            kind,
            telemetry,
            progress_rx: None,
            verify_rx: None,
            started: Instant::now(),
            summary,
            verify_source,
            abort_requested: false,
            force_requested: false,
        }
    }
}

/// What the confirmation sheet is about.
#[derive(Debug, Clone)]
pub enum ConfirmSubject {
    Acquisition {
        request: Box<AcquisitionRequest>,
        base_name: String,
        /// The dry run (`session::check_with`); None while it runs
        check: Option<Box<CheckReport>>,
        destination: Option<Result<DestinationFacts, String>>,
    },
    Conversion {
        request: Box<ConversionRequest>,
        facts: Option<Box<SourceFacts>>,
        destination: Option<Result<DestinationFacts, String>>,
    },
}

#[derive(Debug, Clone)]
pub struct ConfirmState {
    pub subject: ConfirmSubject,
    pub token: u64,
    /// Checks still running
    pub pending: bool,
    pub typed: String,
    pub cursor: usize,
    pub target: Option<ConfirmTarget>,
    /// Why Enter did not start
    pub error: Option<String>,
    pub scroll: usize,
}

impl ConfirmState {
    /// Every check passed (the run would not be refused).
    pub fn ready(&self) -> bool {
        if self.pending {
            return false;
        }
        match &self.subject {
            ConfirmSubject::Acquisition { check, .. } => check.as_ref().is_some_and(|c| c.ready),
            ConfirmSubject::Conversion { facts, .. } => facts.as_ref().is_some_and(|f| f.exists),
        }
    }
}

/// Colour class of a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Good,
    Caution,
    Warning,
    Bad,
    Aborted,
}

/// Tone of an acquisition / conversion outcome.
pub fn outcome_tone(outcome: Outcome) -> Tone {
    match outcome {
        Outcome::Verified => Tone::Good,
        Outcome::CompleteUnverified => Tone::Caution,
        Outcome::CompletedWithReadErrors => Tone::Warning,
        Outcome::Incomplete | Outcome::Mismatch | Outcome::VerificationFailed => Tone::Bad,
        Outcome::Aborted => Tone::Aborted,
    }
}

/// The result of a run, kept until the examiner acknowledges it (and then
/// still reachable from the explorer with `L`).
#[derive(Debug, Clone)]
pub enum RunResult {
    Acquisition {
        report: Box<ForensicInfoReport>,
        text: String,
    },
    Conversion {
        report: Box<ConversionReport>,
        text: String,
    },
    Verification {
        result: Box<ImageVerification>,
        text: String,
    },
    /// The run ended without a report (refused, usage error, failure, abort
    /// before anything was written)
    Error {
        kind: JobKind,
        error: AcquisitionError,
    },
}

impl RunResult {
    pub fn kind(&self) -> JobKind {
        match self {
            RunResult::Acquisition { .. } => JobKind::Acquisition,
            RunResult::Conversion { .. } => JobKind::Conversion,
            RunResult::Verification { .. } => JobKind::Verification,
            RunResult::Error { kind, .. } => *kind,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            RunResult::Acquisition { report, .. } => report.exit_code,
            RunResult::Conversion { report, .. } => report.exit_code(),
            RunResult::Verification { result, .. } => result.exit_code,
            RunResult::Error { error, .. } => error.exit_code(),
        }
    }

    /// The verdict label ("VERIFIED", "HASH MISMATCH", "REFUSED", ...).
    pub fn label(&self) -> String {
        match self {
            RunResult::Acquisition { report, .. } => report.outcome.label().to_string(),
            RunResult::Conversion { report, .. } => report.outcome.label().to_string(),
            RunResult::Verification { result, .. } => match &result.result {
                VerificationResult::Matched { .. } => "VERIFIED".into(),
                VerificationResult::NotPossible { .. } => {
                    "DIGESTS COMPUTED, NOTHING COMPARED".into()
                }
                VerificationResult::Mismatched { .. } => "HASH MISMATCH".into(),
                VerificationResult::Failed { .. } => "VERIFICATION FAILED".into(),
            },
            RunResult::Error { error, .. } => match error.kind {
                ErrorKind::Refused => "REFUSED".into(),
                ErrorKind::Usage => "NOT STARTED (USAGE ERROR)".into(),
                ErrorKind::Failed => "FAILED".into(),
                ErrorKind::Aborted => "ABORTED".into(),
            },
        }
    }

    /// "HASH MISMATCH (exit code 5)".
    pub fn title(&self) -> String {
        format!("{} (exit code {})", self.label(), self.exit_code())
    }

    pub fn tone(&self) -> Tone {
        match self {
            RunResult::Acquisition { report, .. } => outcome_tone(report.outcome),
            RunResult::Conversion { report, .. } => outcome_tone(report.outcome),
            RunResult::Verification { result, .. } => match &result.result {
                VerificationResult::Matched { .. } => Tone::Good,
                VerificationResult::NotPossible { .. } => Tone::Caution,
                _ => Tone::Bad,
            },
            RunResult::Error { error, .. } => match error.kind {
                ErrorKind::Usage => Tone::Caution,
                ErrorKind::Aborted => Tone::Aborted,
                _ => Tone::Bad,
            },
        }
    }

    /// The sentences under the verdict: explanation and key numbers.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = match self {
            RunResult::Acquisition { report, .. } => {
                report.verdict_lines().into_iter().skip(1).collect()
            }
            RunResult::Conversion { report, .. } => {
                let mut l = vec![
                    report.outcome.explanation().to_string(),
                    format!("Verification: {}.", report.verification.describe()),
                ];
                l.extend(report.notes.iter().cloned());
                l
            }
            RunResult::Verification { result, .. } => {
                let mut l = vec![result.verdict(), format!("Method: {}", result.method)];
                l.extend(result.warnings.iter().map(|w| format!("Warning: {w}")));
                l
            }
            RunResult::Error { kind, error } => {
                let mut l = vec![error.message.clone()];
                if *kind == JobKind::Acquisition {
                    l.push("No image and no report were written.".into());
                }
                l
            }
        };
        if let Some(problem) = self.audit_problem() {
            lines.push(problem);
        }
        lines.into_iter().map(|l| sanitize_line(&l)).collect()
    }

    /// "AUDIT LOG NOT WRITTEN: ..." when the run's audit records are missing.
    pub fn audit_problem(&self) -> Option<String> {
        match self {
            RunResult::Acquisition { report, .. } => match &report.audit.status {
                AuditStatus::Written => None,
                AuditStatus::NotWritten { reason } => {
                    Some(format!("AUDIT LOG NOT WRITTEN: {reason}"))
                }
            },
            RunResult::Verification { result, .. } if result.audit_record.is_none() => {
                Some("AUDIT LOG NOT WRITTEN: no image_verification record was written".into())
            }
            _ => None,
        }
    }

    /// Files the run wrote, (label, path).
    pub fn files(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        match self {
            RunResult::Acquisition { report, .. } => {
                let dir = Path::new(&report.output_dir);
                for (label, suffix) in [("Report", INFO_SUFFIX), ("Report JSON", INFO_JSON_SUFFIX)]
                {
                    out.push((
                        label.to_string(),
                        dir.join(format!("{}{}", report.base_name, suffix))
                            .display()
                            .to_string(),
                    ));
                }
                for f in &report.image_files {
                    out.push(("Image".into(), f.clone()));
                }
                for f in &report.auxiliary_files {
                    out.push(("Auxiliary".into(), f.path.clone()));
                }
                if let Some(e) = &report.audit.export_file {
                    out.push(("Audit log copy".into(), e.clone()));
                }
            }
            RunResult::Conversion { report, .. } => {
                out.push(("Report".into(), report.report_file.display().to_string()));
                out.push((
                    "Report JSON".into(),
                    report.report_json_file.display().to_string(),
                ));
                for f in &report.output_files {
                    out.push(("Output".into(), f.display().to_string()));
                }
            }
            RunResult::Verification { result, .. } => {
                out.push(("Image".into(), result.image.display().to_string()));
                if let Some(a) = &result.addendum {
                    out.push(("Addendum".into(), a.display().to_string()));
                }
            }
            RunResult::Error { .. } => {}
        }
        out.into_iter()
            .map(|(l, p)| (l, sanitize_line(&p)))
            .collect()
    }

    /// The complete report text (scrollable on the result screen).
    pub fn text(&self) -> String {
        match self {
            RunResult::Acquisition { text, .. }
            | RunResult::Conversion { text, .. }
            | RunResult::Verification { text, .. } => text.clone(),
            RunResult::Error { error, .. } => format!(
                "{} (exit code {})\n\n{}\n",
                error.kind.label(),
                error.exit_code(),
                error.message
            ),
        }
    }
}

/// Results of background work.
enum BgEvent {
    Scan {
        generation: u64,
        result: Result<Vec<BlockDevice>, String>,
    },
    Destination {
        dir: PathBuf,
        result: Result<DestinationFacts, String>,
    },
    Capacity {
        disk: String,
        key: SelectionKey,
        result: Result<CapacityInfo, String>,
    },
    Unmount {
        key: SelectionKey,
        path: String,
        then_setup: bool,
        result: Result<UnmountResult, AcquisitionError>,
    },
    Prepared {
        token: u64,
        resume_map: Option<PathBuf>,
        check: Option<Box<CheckReport>>,
        destination: Option<Result<DestinationFacts, String>>,
    },
    ConvPrepared {
        token: u64,
        facts: SourceFacts,
        destination: Result<DestinationFacts, String>,
    },
    Completion {
        token: u64,
        prefix: String,
        candidates: Vec<String>,
    },
    SourceProbe {
        path: String,
        facts: SourceFacts,
    },
    VerifyReport {
        image: String,
        report: Option<PathBuf>,
    },
    Acquired(Box<Result<ForensicInfoReport, AcquisitionError>>),
    Converted(Box<Result<(ConversionReport, String), AcquisitionError>>),
    Verified(Box<Result<ImageVerification, AcquisitionError>>),
    ProfileSaved(Result<(), String>),
}

/// A warning when dfdisk runs over SSH without tmux/screen (a dropped
/// connection loses the screen; the run continues headless).
pub fn ssh_warning(env: impl Fn(&str) -> Option<OsString>) -> Option<String> {
    let set = |k: &str| env(k).is_some_and(|v| !v.is_empty());
    let ssh = set("SSH_CONNECTION") || set("SSH_CLIENT") || set("SSH_TTY");
    let multiplexer = set("TMUX") || set("STY") || set("ZELLIJ");
    (ssh && !multiplexer).then(|| {
        "Running over SSH outside tmux/screen: if the connection drops, a running acquisition continues headless and writes its report, but this screen is lost. Start dfdisk inside tmux or screen."
            .to_string()
    })
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions
    unsafe { libc::geteuid() == 0 }
}

/// The ddrescue map of `base` in `dir`, when one exists and is not empty.
fn find_rescue_map(dir: &Path, base: &str) -> Option<PathBuf> {
    let wanted = format!("{}.map", base.to_lowercase());
    preflight::existing_outputs(dir, base)
        .into_iter()
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().to_lowercase() == wanted)
        })
        .filter(|p| std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false))
}

/// Facts about a converter source: existence, size, its dfdisk report.
pub fn probe_source(path: &Path) -> SourceFacts {
    let meta = std::fs::metadata(path).ok().filter(|m| m.is_file());
    let report = report_candidate(path)
        .filter(|p| p.is_file())
        .and_then(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            let r = ForensicInfoReport::from_json(&text).ok()?;
            Some(SourceReport {
                device: format!(
                    "{} ({})",
                    r.source.display_name(),
                    r.source.serial_with_provenance()
                ),
                serial: r.source.serial.clone(),
                case: r.case_metadata.clone(),
                outcome: r.outcome.label().to_string(),
                path: p,
            })
        });
    SourceFacts {
        path: path.to_path_buf(),
        is_ewf: meta.is_some() && crate::engines::verify::is_ewf_image_file(path),
        exists: meta.is_some(),
        size: meta.map(|m| m.len()),
        report,
    }
}

/// The TUI state.
pub struct App {
    backend: Arc<dyn TuiBackend>,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    bg_rx: mpsc::UnboundedReceiver<BgEvent>,
    /// Abort/force/headless flags shared with the running job and the signal
    /// listener; reset before every run
    pub controller: AbortController,
    pub screen: Screen,
    pub modal: Option<Modal>,
    pub should_quit: bool,
    /// SIGHUP: the terminal is gone; nothing is drawn any more
    pub headless: bool,
    /// Quit as soon as the running job has its result (signal, Ctrl+C)
    pub quit_after_job: bool,
    pub ticks: u64,

    // Devices
    pub devices: Vec<BlockDevice>,
    pub rows: Vec<SourceRow>,
    pub table_state: TableState,
    /// Identity of the row under the cursor
    pub cursor_key: Option<SelectionKey>,
    pub scanning: bool,
    scan_generation: u64,
    scan_manual: bool,
    last_scan: Option<Instant>,
    last_scan_error: Option<String>,
    /// Background refresh every [`REFRESH_INTERVAL`] (off for offline Apps)
    pub auto_refresh: bool,
    /// Capacity probes by disk kernel name, with the disk identity probed
    pub capacity: HashMap<String, (SelectionKey, CapacityInfo)>,
    pub capacity_probing: Option<String>,
    pub unmounting: Option<String>,

    // The selected source of the case setup / confirmation
    pub source: Option<SourceRow>,
    /// Why the selected source is no longer valid (it changed or vanished)
    pub source_invalid: Option<String>,
    /// Mount points dfdisk unmounted (audited) for the selected source
    pub unmounted: Vec<String>,
    unmounted_key: Option<SelectionKey>,

    // Case setup
    pub case: CaseMetadata,
    pub form: AcqForm,
    pub field: Field,
    pub cursor: usize,
    /// Highlight missing required fields (after a start attempt)
    pub show_required: bool,
    pub destination_facts: Option<(PathBuf, Result<DestinationFacts, String>)>,
    dest_due: Option<Instant>,
    pub completion: Option<Completion>,

    // Confirmation sheet
    pub confirm: Option<ConfirmState>,
    token: u64,

    // Jobs and results
    pub job: Option<Job>,
    pub result: Option<RunResult>,
    pub result_scroll: usize,
    pub result_acknowledged: bool,

    // Converter and re-verification
    pub conv: ConvForm,
    conv_due: Option<Instant>,
    pub verify: VerifyForm,
    verify_due: Option<Instant>,

    pub notices: Vec<Notice>,
    pub profile: CaseProfile,
    pub profile_path: Option<PathBuf>,
    pub ssh_warning: Option<String>,
    pub is_root: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// The App on this host: background device scan (started here, so this
    /// must run inside a tokio runtime), periodic refresh, the examiner's
    /// case profile, SSH warning.
    pub fn new() -> Self {
        Self::with_controller(AbortController::new())
    }

    /// [`new`](Self::new) with the process' abort controller (the one the
    /// signal listener applies signals to).
    pub fn with_controller(controller: AbortController) -> Self {
        let mut app = Self::with_backend(Vec::new(), Arc::new(HostBackend));
        app.controller = controller;
        app.auto_refresh = true;
        app.is_root = is_root();
        if let Some(path) = profile::default_profile_path() {
            app.load_profile_from(path);
        }
        app.ssh_warning = ssh_warning(|k| std::env::var_os(k));
        if let Some(w) = app.ssh_warning.clone() {
            app.notify(Level::Warning, w);
        }
        app.start_scan(false);
        app
    }

    /// App over a given device list that never touches the host: no scan,
    /// no profile, every host request fails (tests, screenshots).
    pub fn with_devices(devices: Vec<BlockDevice>) -> Self {
        Self::with_backend(
            devices.clone(),
            Arc::new(OfflineBackend {
                devices: devices.clone(),
            }),
        )
    }

    /// App over `devices` and any backend (tests drive it with scripted
    /// results). No periodic refresh, no profile until loaded.
    pub fn with_backend(devices: Vec<BlockDevice>, backend: Arc<dyn TuiBackend>) -> Self {
        let (bg_tx, bg_rx) = mpsc::unbounded_channel();
        let mut app = Self {
            backend,
            bg_tx,
            bg_rx,
            controller: AbortController::new(),
            screen: Screen::Explorer,
            modal: None,
            should_quit: false,
            headless: false,
            quit_after_job: false,
            ticks: 0,
            devices: Vec::new(),
            rows: Vec::new(),
            table_state: TableState::default(),
            cursor_key: None,
            scanning: false,
            scan_generation: 0,
            scan_manual: false,
            last_scan: None,
            last_scan_error: None,
            auto_refresh: false,
            capacity: HashMap::new(),
            capacity_probing: None,
            unmounting: None,
            source: None,
            source_invalid: None,
            unmounted: Vec::new(),
            unmounted_key: None,
            case: CaseMetadata::default(),
            form: AcqForm::default(),
            field: Field::CaseNumber,
            cursor: 0,
            show_required: false,
            destination_facts: None,
            dest_due: None,
            completion: None,
            confirm: None,
            token: 0,
            job: None,
            result: None,
            result_scroll: 0,
            result_acknowledged: true,
            conv: ConvForm::default(),
            conv_due: None,
            verify: VerifyForm::default(),
            verify_due: None,
            notices: Vec::new(),
            profile: CaseProfile::default(),
            profile_path: None,
            ssh_warning: None,
            is_root: false,
        };
        app.apply_scan(devices, false);
        app
    }

    /// Load the case profile from `path` and pre-fill examiner, authority and
    /// destination; the profile is saved there when an acquisition starts.
    pub fn load_profile_from(&mut self, path: PathBuf) {
        match CaseProfile::load(&path) {
            Ok(p) => {
                if self.case.examiner.is_empty() {
                    self.case.examiner = p.examiner.clone();
                }
                if self.case.authority.is_empty() {
                    self.case.authority = p.authority.clone();
                }
                if self.form.destination.is_empty() {
                    self.form.destination = p.last_destination.clone();
                }
                if self.conv.case.examiner.is_empty() {
                    self.conv.case.examiner = p.examiner.clone();
                }
                self.profile = p;
            }
            Err(e) => self.notify(
                Level::Warning,
                format!("Case profile {} not loaded: {e}", path.display()),
            ),
        }
        self.profile_path = Some(path);
    }

    // ------------------------------------------------------------------
    // Notices
    // ------------------------------------------------------------------

    pub fn notify(&mut self, level: Level, text: impl Into<String>) {
        let text = sanitize_line(&text.into());
        // The same message twice in a row is shown once
        if let Some(last) = self.notices.last_mut() {
            if last.text == text && last.level == level {
                last.at = Instant::now();
                return;
            }
        }
        self.notices.push(Notice {
            text,
            level,
            at: Instant::now(),
        });
        if self.notices.len() > 50 {
            self.notices.remove(0);
        }
    }

    /// Notices that are still shown (info ones expire).
    pub fn visible_notices(&self) -> Vec<&Notice> {
        self.notices.iter().rev().collect()
    }

    /// Acknowledge every notice (Ctrl+X).
    pub fn dismiss_notices(&mut self) {
        self.notices.clear();
    }

    pub fn has_errors(&self) -> bool {
        self.notices.iter().any(|n| n.level == Level::Error)
    }

    // ------------------------------------------------------------------
    // Background work
    // ------------------------------------------------------------------

    fn spawn<F>(&mut self, fut: F) -> bool
    where
        F: Future<Output = BgEvent> + Send + 'static,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let tx = self.bg_tx.clone();
                handle.spawn(async move {
                    let _ = tx.send(fut.await);
                });
                true
            }
            Err(_) => {
                self.notify(
                    Level::Error,
                    "Internal error: no async runtime for background work",
                );
                false
            }
        }
    }

    fn spawn_blocking<F>(&mut self, f: F) -> bool
    where
        F: FnOnce() -> BgEvent + Send + 'static,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let tx = self.bg_tx.clone();
                handle.spawn_blocking(move || {
                    let _ = tx.send(f());
                });
                true
            }
            Err(_) => {
                self.notify(
                    Level::Error,
                    "Internal error: no async runtime for background work",
                );
                false
            }
        }
    }

    /// Something runs in the background (spinner in the header).
    pub fn busy_label(&self) -> Option<String> {
        if self.scanning {
            Some("scanning devices".into())
        } else if let Some(p) = &self.unmounting {
            Some(format!("unmounting {p}"))
        } else if let Some(p) = &self.capacity_probing {
            Some(format!("probing hidden areas of /dev/{p}"))
        } else if self.confirm.as_ref().is_some_and(|c| c.pending) {
            Some("pre-flight checks".into())
        } else {
            self.job
                .as_ref()
                .map(|j| format!("{} running", j.kind.label()))
        }
    }

    // ------------------------------------------------------------------
    // Devices
    // ------------------------------------------------------------------

    /// Start a device scan (lsblk + sysfs) on a blocking thread.
    pub fn start_scan(&mut self, manual: bool) {
        if self.scanning {
            if manual {
                self.notify(Level::Info, "A device scan is already running.");
            }
            return;
        }
        self.scan_generation += 1;
        let generation = self.scan_generation;
        let backend = self.backend.clone();
        self.scan_manual = manual;
        if self.spawn_blocking(move || BgEvent::Scan {
            generation,
            result: backend.scan(),
        }) {
            self.scanning = true;
        }
    }

    fn capacity_of(&self) -> impl Fn(&str) -> Option<CapacityInfo> + '_ {
        move |disk: &str| {
            let (key, info) = self.capacity.get(disk)?;
            let current = self.devices.iter().find(|d| d.name == disk)?;
            (SelectionKey::of(current) == *key).then(|| info.clone())
        }
    }

    /// The hidden-area probe of `disk`, if it was probed and is still the
    /// same disk.
    pub fn capacity_for(&self, disk: &str) -> Option<CapacityInfo> {
        self.capacity_of()(disk)
    }

    fn rebuild_rows(&mut self) {
        let rows = source_rows(&self.devices, &self.capacity_of());
        self.rows = rows;
    }

    /// Take a new device list: rows rebuilt, the cursor and the selected
    /// source followed by identity; a changed or vanished selection is
    /// invalidated with a notice.
    fn apply_scan(&mut self, devices: Vec<BlockDevice>, notify: bool) {
        let old_index = self.table_state.selected().unwrap_or(0);
        self.devices = devices;
        self.rebuild_rows();

        // The selected source (case setup / confirmation)
        let mut source_notice = None;
        if let Some(src) = self.source.clone() {
            if self.source_invalid.is_none() {
                match reconcile(&src.key, &self.rows) {
                    Reconciled::Same(i) => self.source = Some(self.rows[i].clone()),
                    other => {
                        let text =
                            invalidation_notice(&src.device.path, &other).unwrap_or_default();
                        self.source_invalid = Some(text.clone());
                        source_notice = Some(text);
                    }
                }
            }
        }
        if let Some(text) = source_notice {
            self.notify(Level::Error, text);
            if self.screen == Screen::Confirm
                && matches!(
                    self.confirm.as_ref().map(|c| &c.subject),
                    Some(ConfirmSubject::Acquisition { .. })
                )
            {
                self.confirm = None;
                self.modal = None;
                self.screen = Screen::CaseSetup;
            }
        }

        // The cursor of the explorer
        if self.rows.is_empty() {
            self.table_state.select(None);
            self.cursor_key = None;
            return;
        }
        let pinned = self.source.as_ref().map(|s| s.key.clone());
        match self.cursor_key.clone() {
            None => self.select_row(0),
            Some(key) => match reconcile(&key, &self.rows) {
                Reconciled::Same(i) => self.select_row(i),
                other => {
                    let row = match &other {
                        Reconciled::Changed { row, .. } => *row,
                        _ => old_index.min(self.rows.len() - 1),
                    };
                    if notify && pinned.as_ref() != Some(&key) {
                        let path = self
                            .devices
                            .iter()
                            .flat_map(|d| {
                                std::iter::once(d.path.clone())
                                    .chain(d.partitions.iter().map(|p| p.path.clone()))
                            })
                            .find(|p| p.ends_with(&format!("/{}", key.kernel_name)))
                            .unwrap_or_else(|| format!("/dev/{}", key.kernel_name));
                        if let Some(text) = invalidation_notice(&path, &other) {
                            self.notify(Level::Warning, text);
                        }
                    }
                    self.select_row(row);
                }
            },
        }
    }

    fn select_row(&mut self, i: usize) {
        if self.rows.is_empty() {
            self.table_state.select(None);
            self.cursor_key = None;
        } else {
            let i = i.min(self.rows.len() - 1);
            self.table_state.select(Some(i));
            self.cursor_key = Some(self.rows[i].key.clone());
        }
    }

    pub fn current_row(&self) -> Option<&SourceRow> {
        self.table_state.selected().and_then(|i| self.rows.get(i))
    }

    fn move_cursor(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let cur = self.table_state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, self.rows.len() as isize - 1);
        self.select_row(next as usize);
    }

    // ------------------------------------------------------------------
    // Keys
    // ------------------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
            self.ctrl_c();
            return;
        }
        if self.modal.is_some() {
            self.key_modal(key);
            return;
        }
        if key.code == KeyCode::F(1) {
            self.modal = Some(Modal::Help);
            return;
        }
        if ctrl && matches!(key.code, KeyCode::Char('x') | KeyCode::Char('X')) {
            self.dismiss_notices();
            return;
        }
        // '?' opens the help wherever it is not text being typed
        if key.code == KeyCode::Char('?') && !self.typing() {
            self.modal = Some(Modal::Help);
            return;
        }
        match self.screen {
            Screen::Explorer => self.key_explorer(key),
            Screen::CaseSetup => self.key_case_setup(key),
            Screen::Confirm => self.key_confirm(key),
            Screen::Running => self.key_running(key),
            Screen::Result => self.key_result(key),
            Screen::Converter => self.key_converter(key),
            Screen::Verify => self.key_verify(key),
        }
    }

    /// The focus is in a text input (keys are text).
    pub fn typing(&self) -> bool {
        match self.screen {
            Screen::CaseSetup => self.field.is_text(),
            Screen::Converter => self.conv.field.is_text(),
            Screen::Verify => self.verify.field() != VerField::Start,
            Screen::Confirm => true,
            _ => false,
        }
    }

    /// Ctrl+C: quit; while a run is busy, ask first (abort, then quit once
    /// the report is written); after an abort, offer the immediate stop.
    fn ctrl_c(&mut self) {
        match &self.job {
            None => self.should_quit = true,
            Some(job) if job.abort_requested && !job.force_requested => {
                self.modal = Some(Modal::Force)
            }
            Some(_) => self.modal = Some(Modal::Quit),
        }
    }

    fn key_modal(&mut self, key: KeyEvent) {
        let yes = matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y'));
        let Some(modal) = self.modal.take() else {
            return;
        };
        match modal {
            Modal::Help => {}
            Modal::Unmount {
                device,
                key: sel,
                then_setup,
                ..
            } => {
                if yes {
                    self.run_unmount(*device, sel, then_setup);
                }
            }
            Modal::Abort => {
                if yes {
                    self.request_abort();
                }
            }
            Modal::Force => {
                if yes {
                    self.controller.request_force();
                    if let Some(job) = &mut self.job {
                        job.abort_requested = true;
                        job.force_requested = true;
                    }
                    self.notify(
                        Level::Warning,
                        "Killing external tools immediately; the report is still written.",
                    );
                }
            }
            Modal::Quit => {
                if yes {
                    if self.job.is_some() {
                        self.request_abort();
                        self.quit_after_job = true;
                    } else {
                        self.should_quit = true;
                    }
                }
            }
            Modal::Resume { map } => {
                if yes {
                    self.form.resume = true;
                    self.notify(
                        Level::Info,
                        format!("Resuming the rescue from {}", map.display()),
                    );
                    self.begin_acquisition();
                } else {
                    self.confirm = None;
                    self.token += 1;
                    self.screen = Screen::CaseSetup;
                    self.notify(
                        Level::Warning,
                        format!(
                            "A ddrescue map of this base name exists ({}): resume it, or use another evidence number or destination.",
                            map.display()
                        ),
                    );
                }
            }
        }
    }

    fn request_abort(&mut self) {
        let action = self.controller.request_abort();
        if let Some(job) = &mut self.job {
            job.abort_requested = true;
        }
        if action == SignalAction::Abort {
            self.notify(
                Level::Warning,
                "Aborting: the tool is stopped gracefully; the partial output and an ABORTED report are kept.",
            );
        }
    }

    // ------------------------------------------------------------------
    // Explorer
    // ------------------------------------------------------------------

    fn key_explorer(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::PageUp => self.move_cursor(-10),
            KeyCode::PageDown => self.move_cursor(10),
            KeyCode::Home => self.select_row(0),
            KeyCode::End => self.select_row(self.rows.len().saturating_sub(1)),
            KeyCode::Enter | KeyCode::Char('a') | KeyCode::F(5) => self.select_for_acquisition(),
            KeyCode::Char('u') | KeyCode::F(3) => self.ask_unmount(false),
            KeyCode::Char('h') => self.probe_capacity(),
            KeyCode::Char('r') | KeyCode::F(2) => self.start_scan(true),
            KeyCode::Char('c') | KeyCode::F(7) => self.open_converter(),
            KeyCode::Char('v') | KeyCode::F(8) => self.open_verify(),
            KeyCode::Char('l') => {
                if self.result.is_some() {
                    self.screen = Screen::Result;
                    self.result_scroll = 0;
                } else {
                    self.notify(Level::Info, "No result yet in this session.");
                }
            }
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    /// Enter on a row: refused sources are explained, mounted ones offer the
    /// audited unmount, everything else goes to the case setup.
    pub fn select_for_acquisition(&mut self) {
        let Some(row) = self.current_row().cloned() else {
            self.notify(Level::Info, "No source selected.");
            return;
        };
        if row.has(Badge::Protected) {
            self.notify(
                Level::Error,
                format!(
                    "{} is protected by the dfnix registry ({}); dfdisk refuses to acquire it.",
                    row.device.path,
                    row.protected.as_deref().unwrap_or("listed")
                ),
            );
            return;
        }
        if row.has(Badge::System) {
            self.notify(
                Level::Error,
                format!(
                    "{} holds the running system ({}); dfdisk refuses to acquire it.",
                    row.device.path,
                    if row.system_mounts.is_empty() {
                        "system mounts".to_string()
                    } else {
                        row.system_mounts.join(", ")
                    }
                ),
            );
            return;
        }
        if row.has(Badge::Mounted) {
            self.ask_unmount(true);
            return;
        }
        self.pin_source(row);
    }

    fn pin_source(&mut self, row: SourceRow) {
        if self.unmounted_key.as_ref() != Some(&row.key) {
            self.unmounted.clear();
            self.unmounted_key = None;
        }
        if self.source.as_ref().map(|s| &s.key) != Some(&row.key) {
            self.form.resume = false;
            self.form.allow_low_space = false;
        }
        self.source = Some(row);
        self.source_invalid = None;
        self.screen = Screen::CaseSetup;
        self.show_required = false;
        self.completion = None;
        // Start at the first empty required field
        self.field = [Field::CaseNumber, Field::EvidenceNumber, Field::Examiner]
            .into_iter()
            .find(|f| case_text(&self.case, *f).is_none_or(|t| t.trim().is_empty()))
            .unwrap_or(Field::CaseNumber);
        self.cursor = self.field_text_len();
        self.dest_due = Some(Instant::now());
    }

    fn ask_unmount(&mut self, then_setup: bool) {
        let Some(row) = self.current_row().cloned() else {
            return;
        };
        if !row.has(Badge::Mounted) {
            self.notify(
                Level::Info,
                format!("{} has no mounted filesystem.", row.device.path),
            );
            return;
        }
        if row.has(Badge::System) || row.has(Badge::Protected) {
            self.notify(
                Level::Error,
                format!(
                    "{} holds system or protected mounts; dfdisk never unmounts them.",
                    row.device.path
                ),
            );
            return;
        }
        self.modal = Some(Modal::Unmount {
            mounts: row.mountpoints.clone(),
            key: row.key.clone(),
            device: Box::new(row.device),
            then_setup,
        });
    }

    fn run_unmount(&mut self, device: BlockDevice, key: SelectionKey, then_setup: bool) {
        let backend = self.backend.clone();
        let path = device.path.clone();
        self.unmounting = Some(path.clone());
        if !self.spawn_blocking(move || BgEvent::Unmount {
            result: backend.unmount(&device),
            key,
            path,
            then_setup,
        }) {
            self.unmounting = None;
        }
    }

    fn probe_capacity(&mut self) {
        let Some(row) = self.current_row().cloned() else {
            return;
        };
        if self.capacity_probing.is_some() {
            self.notify(Level::Info, "A hidden-area probe is already running.");
            return;
        }
        let Some(disk) = self.devices.iter().find(|d| d.name == row.disk).cloned() else {
            return;
        };
        let key = SelectionKey::of(&disk);
        let fut = self.backend.capacity(row.device.clone());
        self.notify(
            Level::Info,
            format!(
                "Probing hidden areas (HPA/DCO) of {}: identify-class queries only, nothing is changed.",
                disk.path
            ),
        );
        let name = disk.name.clone();
        if self.spawn(async move {
            BgEvent::Capacity {
                disk: name,
                key,
                result: fut.await,
            }
        }) {
            self.capacity_probing = Some(disk.name);
        }
    }

    // ------------------------------------------------------------------
    // Case setup
    // ------------------------------------------------------------------

    fn field_text_len(&self) -> usize {
        if self.field == Field::Destination {
            self.form.destination.len()
        } else {
            case_text(&self.case, self.field).map_or(0, String::len)
        }
    }

    fn focus_step(&mut self, forward: bool) {
        let order = Field::focus_order(self.form.engine);
        let i = order.iter().position(|f| *f == self.field).unwrap_or(0);
        let n = order.len();
        self.field = order[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }];
        self.cursor = self.field_text_len();
    }

    /// Suggestion shown in an empty case field (accepted with → or End).
    pub fn suggestion(&self, field: Field) -> Option<String> {
        match field {
            Field::CaseNumber if self.case.case_number.trim().is_empty() => {
                self.profile.case_suggestion()
            }
            Field::EvidenceNumber if self.case.evidence_number.trim().is_empty() => {
                self.profile.evidence_suggestion(&self.case.case_number)
            }
            _ => None,
        }
    }

    fn key_case_setup(&mut self, key: KeyEvent) {
        if key.code != KeyCode::F(4) {
            self.completion = None;
        }
        match key.code {
            KeyCode::Esc => self.screen = Screen::Explorer,
            KeyCode::Tab | KeyCode::Down => self.focus_step(true),
            KeyCode::BackTab | KeyCode::Up => self.focus_step(false),
            KeyCode::F(5) => self.begin_acquisition(),
            KeyCode::F(4) => {
                if self.field == Field::Destination {
                    self.complete(Input::Case(Field::Destination));
                } else {
                    self.notify(Level::Info, "Path completion (F4) works in path fields.");
                }
            }
            KeyCode::Enter => {
                if self.field == Field::Start {
                    self.begin_acquisition();
                } else {
                    self.focus_step(true);
                }
            }
            _ if self.field.is_text() => {
                if matches!(key.code, KeyCode::Right | KeyCode::End) {
                    if let Some(s) = self.suggestion(self.field) {
                        if let Some(t) = case_text_mut(&mut self.case, self.field) {
                            *t = s;
                            self.cursor = t.len();
                            return;
                        }
                    }
                }
                let field = self.field;
                if field == Field::Destination {
                    let before = self.form.destination.clone();
                    edit_text(&mut self.form.destination, &mut self.cursor, key);
                    if self.form.destination != before {
                        self.form.allow_low_space = false;
                        self.form.resume = false;
                        self.dest_due = Some(Instant::now() + PROBE_DEBOUNCE);
                    }
                } else if let Some(t) = case_text_mut(&mut self.case, field) {
                    edit_text(t, &mut self.cursor, key);
                    if matches!(field, Field::CaseNumber | Field::EvidenceNumber) {
                        self.form.resume = false;
                    }
                }
            }
            KeyCode::Char(' ') if self.field == Field::Start => self.begin_acquisition(),
            KeyCode::Char(' ') | KeyCode::Right => {
                if let Some(msg) = self.form.toggle(self.field, true) {
                    self.notify(Level::Warning, msg);
                }
            }
            KeyCode::Left => {
                if let Some(msg) = self.form.toggle(self.field, false) {
                    self.notify(Level::Warning, msg);
                }
            }
            _ => {}
        }
    }

    /// The base name of the acquisition as configured (None until the
    /// required fields are filled in).
    pub fn base_name_preview(&self) -> Option<String> {
        let src = self.source.as_ref()?;
        self.case
            .base_filename_checked(&src.device.display_serial())
            .ok()
    }

    /// Start pressed: validate locally, then the confirmation sheet with the
    /// dry run of the session (`check_with`) in the background.
    pub fn begin_acquisition(&mut self) {
        self.completion = None;
        let Some(source) = self.source.clone() else {
            self.notify(Level::Error, "Select a source in the device list first.");
            return;
        };
        if let Some(reason) = self.source_invalid.clone() {
            self.notify(Level::Error, reason);
            return;
        }
        if let Err(msg) = self.case.validate_required() {
            self.show_required = true;
            if let Some(f) = [Field::CaseNumber, Field::EvidenceNumber, Field::Examiner]
                .into_iter()
                .find(|f| case_text(&self.case, *f).is_none_or(|t| t.trim().is_empty()))
            {
                self.field = f;
                self.cursor = self.field_text_len();
            }
            self.notify(Level::Error, msg);
            return;
        }
        if self.form.destination.trim().is_empty() {
            self.show_required = true;
            self.field = Field::Destination;
            self.cursor = 0;
            self.notify(
                Level::Error,
                "Choose a destination directory for the image and its report.",
            );
            return;
        }
        let config = self.form.config();
        if let Err(msg) = config.validate() {
            self.notify(Level::Error, msg);
            return;
        }
        let base_name = match self
            .case
            .base_filename_checked(&source.device.display_serial())
        {
            Ok(b) => b,
            Err(msg) => {
                self.notify(Level::Error, msg);
                return;
            }
        };
        let request = AcquisitionRequest {
            device: source.device.clone(),
            case: self.case.clone(),
            config,
            unmounted_by_dfdisk: if self.unmounted_key.as_ref() == Some(&source.key) {
                self.unmounted.clone()
            } else {
                Vec::new()
            },
        };
        self.token += 1;
        let token = self.token;
        self.confirm = Some(ConfirmState {
            subject: ConfirmSubject::Acquisition {
                request: Box::new(request.clone()),
                base_name: base_name.clone(),
                check: None,
                destination: None,
            },
            token,
            pending: true,
            typed: String::new(),
            cursor: 0,
            target: None,
            error: None,
            scroll: 0,
        });
        self.screen = Screen::Confirm;

        // The dry run sends no SMART command: SMART runs once, recorded in the
        // report, when the acquisition starts (P4)
        let mut check_request = request.clone();
        check_request.config.smart = SmartPolicy::Off;
        let offer_resume = request.engine() == EngineKind::Rescue && !request.config.resume;
        let dir = request.config.output_dir.clone();
        let backend = self.backend.clone();
        self.spawn(async move {
            if offer_resume {
                let (d, b) = (dir.clone(), base_name.clone());
                let map = tokio::task::spawn_blocking(move || find_rescue_map(&d, &b))
                    .await
                    .ok()
                    .flatten();
                if map.is_some() {
                    return BgEvent::Prepared {
                        token,
                        resume_map: map,
                        check: None,
                        destination: None,
                    };
                }
            }
            let b2 = backend.clone();
            let destination = tokio::task::spawn_blocking(move || b2.destination(&dir))
                .await
                .unwrap_or_else(|e| Err(format!("destination probe stopped: {e}")));
            let check = backend.check(check_request).await;
            BgEvent::Prepared {
                token,
                resume_map: None,
                check: Some(Box::new(check)),
                destination: Some(destination),
            }
        });
    }

    // ------------------------------------------------------------------
    // Confirmation sheet
    // ------------------------------------------------------------------

    /// Free space and source size when the sheet may offer an E01 with less
    /// free space than the source (R4: explicit confirmation in the TUI).
    pub fn low_space_offer(&self) -> Option<(u64, u64)> {
        let c = self.confirm.as_ref()?;
        let ConfirmSubject::Acquisition {
            request,
            check,
            destination,
            ..
        } = &c.subject
        else {
            return None;
        };
        if c.pending
            || request.engine() != EngineKind::Ewf
            || request.config.allow_low_space
            || check.as_ref().is_none_or(|r| r.ready)
        {
            return None;
        }
        let free = destination.as_ref()?.as_ref().ok()?.free_bytes?;
        let size = check
            .as_ref()
            .and_then(|r| r.identity.as_ref().map(|i| i.size_bytes))
            .unwrap_or(request.device.size_bytes);
        (free >= MIN_FREE_BYTES && free < size).then_some((free, size))
    }

    fn key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let back = match self.confirm.as_ref().map(|c| &c.subject) {
                    Some(ConfirmSubject::Conversion { .. }) => Screen::Converter,
                    _ => Screen::CaseSetup,
                };
                self.confirm = None;
                self.token += 1;
                self.screen = back;
            }
            KeyCode::Up => self.scroll_confirm(-1),
            KeyCode::Down => self.scroll_confirm(1),
            KeyCode::PageUp => self.scroll_confirm(-10),
            KeyCode::PageDown => self.scroll_confirm(10),
            KeyCode::Home => self.scroll_confirm(isize::MIN / 2),
            KeyCode::F(6) => {
                if let Some((free, size)) = self.low_space_offer() {
                    self.form.allow_low_space = true;
                    self.notify(
                        Level::Warning,
                        format!(
                            "E01 with less free space ({}) than the source ({}) confirmed; the decision is recorded in the report.",
                            format_iec(free),
                            format_iec(size)
                        ),
                    );
                    self.begin_acquisition();
                }
            }
            KeyCode::Enter => self.confirm_start(),
            KeyCode::Tab | KeyCode::BackTab => {}
            _ => {
                if let Some(c) = &mut self.confirm {
                    edit_text(&mut c.typed, &mut c.cursor, key);
                    c.error = None;
                }
            }
        }
    }

    fn scroll_confirm(&mut self, delta: isize) {
        if let Some(c) = &mut self.confirm {
            c.scroll = (c.scroll as isize + delta).max(0) as usize;
        }
    }

    /// Enter on the sheet: start only when every check passed and the typed
    /// confirmation matches (R10).
    fn confirm_start(&mut self) {
        let Some(c) = self.confirm.clone() else {
            return;
        };
        if c.pending {
            self.notify(Level::Info, "The pre-flight checks are still running.");
            return;
        }
        if matches!(c.subject, ConfirmSubject::Acquisition { .. }) {
            if let Some(reason) = self.source_invalid.clone() {
                self.notify(Level::Error, reason);
                return;
            }
        }
        let error = if !c.ready() {
            Some(match c.subject {
                ConfirmSubject::Acquisition { .. } => {
                    "The acquisition would be refused (see the problems on this sheet); nothing was started."
                }
                ConfirmSubject::Conversion { .. } => {
                    "The source image cannot be read (see this sheet); nothing was started."
                }
            })
        } else if !c.target.as_ref().is_some_and(|t| t.matches(&c.typed)) {
            Some("That does not match: compare the serial number on this sheet with the drive label and type the requested characters.")
        } else {
            None
        };
        if let Some(e) = error {
            if let Some(cs) = &mut self.confirm {
                cs.error = Some(e.to_string());
            }
            return;
        }
        match c.subject {
            ConfirmSubject::Acquisition { request, check, .. } => {
                self.start_acquisition_job(*request, check.as_deref())
            }
            ConfirmSubject::Conversion { request, facts, .. } => {
                self.start_conversion_job(*request, facts.map(|f| *f))
            }
        }
    }

    // ------------------------------------------------------------------
    // Jobs
    // ------------------------------------------------------------------

    fn start_acquisition_job(&mut self, request: AcquisitionRequest, check: Option<&CheckReport>) {
        self.controller.reset();
        let (tx, rx) = mpsc::channel(256);
        let mut summary = Vec::new();
        match check.and_then(|c| c.identity.as_ref()) {
            Some(id) => {
                summary.push((
                    "Source".to_string(),
                    format!("{} ({})", id.path, id.kind.label()),
                ));
                summary.push(("Model".to_string(), id.display_name()));
                summary.push(("Serial".to_string(), id.serial_with_provenance()));
                summary.push((
                    "Size".to_string(),
                    format!("{} bytes ({})", id.size_bytes, format_iec(id.size_bytes)),
                ));
            }
            None => {
                summary.push(("Source".to_string(), request.device.path.clone()));
                summary.push(("Serial".to_string(), request.device.display_serial()));
            }
        }
        let base = check.and_then(|c| c.base_name.clone()).unwrap_or_default();
        summary.push((
            "Destination".to_string(),
            format!("{}/{}.*", request.config.output_dir.display(), base),
        ));
        summary.push(("Engine".to_string(), request.engine().label().to_string()));
        let verify_source = request.config.verify_source;
        let size = request.device.size_bytes;
        let fut = self
            .backend
            .acquire(request, tx, self.controller.stop_flags());
        self.job = Some(Job {
            kind: JobKind::Acquisition,
            telemetry: ProgressTelemetry {
                status: AcquisitionStatus::Preparing,
                total_bytes: size,
                status_message: "Pre-flight checks, audit record, write protection".into(),
                ..Default::default()
            },
            progress_rx: Some(rx),
            verify_rx: None,
            started: Instant::now(),
            summary,
            verify_source,
            abort_requested: false,
            force_requested: false,
        });
        self.confirm = None;
        self.screen = Screen::Running;
        self.save_profile();
        self.spawn(async move { BgEvent::Acquired(Box::new(fut.await)) });
    }

    fn save_profile(&mut self) {
        self.profile.examiner = sanitize_line(&self.case.examiner);
        self.profile.authority = sanitize_line(&self.case.authority);
        self.profile.last_destination = sanitize_line(&self.form.destination);
        self.profile.last_case = sanitize_line(&self.case.case_number);
        self.profile.last_evidence = sanitize_line(&self.case.evidence_number);
        let Some(path) = self.profile_path.clone() else {
            return;
        };
        let profile = self.profile.clone();
        self.spawn_blocking(move || {
            BgEvent::ProfileSaved(
                profile
                    .save(&path)
                    .map_err(|e| format!("case profile {} not saved: {e}", path.display())),
            )
        });
    }

    fn key_running(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('a') | KeyCode::Char('A') => {
                let Some(job) = &self.job else {
                    return;
                };
                self.modal = Some(if job.abort_requested && !job.force_requested {
                    Modal::Force
                } else if job.abort_requested {
                    return;
                } else {
                    Modal::Abort
                });
            }
            KeyCode::Esc => self.notify(
                Level::Info,
                "Esc does not abort a running job; press A to abort (asks for confirmation).",
            ),
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Results
    // ------------------------------------------------------------------

    fn show_result(&mut self, result: RunResult) {
        self.result = Some(result);
        self.result_scroll = 0;
        self.result_acknowledged = false;
        self.modal = None;
        self.screen = Screen::Result;
        if self.quit_after_job {
            self.should_quit = true;
        }
    }

    fn key_result(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.result_acknowledged = true;
                let back_to_setup = matches!(
                    self.result,
                    Some(RunResult::Error {
                        kind: JobKind::Acquisition,
                        ..
                    })
                ) && self.source.is_some();
                let back_to_converter = matches!(
                    self.result,
                    Some(RunResult::Error {
                        kind: JobKind::Conversion,
                        ..
                    })
                );
                self.screen = if back_to_setup {
                    Screen::CaseSetup
                } else if back_to_converter {
                    Screen::Converter
                } else {
                    Screen::Explorer
                };
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.result_scroll = self.result_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => self.result_scroll += 1,
            KeyCode::PageUp => self.result_scroll = self.result_scroll.saturating_sub(10),
            KeyCode::PageDown => self.result_scroll += 10,
            KeyCode::Home => self.result_scroll = 0,
            KeyCode::End => self.result_scroll = usize::MAX / 2,
            KeyCode::Char('v') => self.reverify_result(),
            KeyCode::Char('c') => self.convert_result(),
            _ => {}
        }
    }

    /// Re-verify the image of the shown acquisition.
    fn reverify_result(&mut self) {
        let Some(RunResult::Acquisition { report, .. }) = &self.result else {
            return;
        };
        let Some(image) = report.image_files.first().cloned() else {
            return;
        };
        let json = Path::new(&report.output_dir)
            .join(format!("{}{}", report.base_name, INFO_JSON_SUFFIX))
            .display()
            .to_string();
        self.result_acknowledged = true;
        self.verify = VerifyForm {
            image,
            report: json,
            field: Some(VerField::Start),
            cursor: 0,
            report_auto: false,
        };
        self.screen = Screen::Verify;
    }

    /// Convert the image of the shown rescue to E01, with the read-error
    /// summary in the notes.
    fn convert_result(&mut self) {
        let Some(RunResult::Acquisition { report, .. }) = &self.result else {
            return;
        };
        if report.engine != EngineKind::Rescue {
            return;
        }
        let Some(image) = report.image_files.first().cloned() else {
            return;
        };
        let mut notes = vec![format!(
            "Converted from the rescue image {} (outcome {}).",
            image,
            report.outcome.label()
        )];
        for kind in [RangeKind::Substituted, RangeKind::Unread] {
            if let Some(s) = report.read_errors.summary(kind) {
                notes.push(format!("Rescue read errors ({}): {s}", kind.label()));
            }
        }
        let case = report.case_metadata.clone();
        let dir = report.output_dir.clone();
        self.result_acknowledged = true;
        self.conv = ConvForm {
            source: image,
            target: ConversionTarget::E01,
            destination: dir,
            case,
            field: ConvField::Destination,
            notes,
            ..ConvForm::default()
        };
        self.conv.cursor = self.conv.destination.len();
        self.conv_due = Some(Instant::now());
        self.screen = Screen::Converter;
    }

    // ------------------------------------------------------------------
    // Converter
    // ------------------------------------------------------------------

    pub fn open_converter(&mut self) {
        self.screen = Screen::Converter;
        self.completion = None;
        if self.conv.destination.is_empty() {
            self.conv.destination = self.form.destination.clone();
        }
        self.conv.cursor = self.conv.text(self.conv.field).map_or(0, String::len);
    }

    fn conv_focus_step(&mut self, forward: bool) {
        let order = ConvField::focus_order(self.conv.target);
        let i = order
            .iter()
            .position(|f| *f == self.conv.field)
            .unwrap_or(0);
        let n = order.len();
        self.conv.field = order[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }];
        self.conv.cursor = self.conv.text(self.conv.field).map_or(0, String::len);
    }

    fn key_converter(&mut self, key: KeyEvent) {
        if key.code != KeyCode::F(4) {
            self.completion = None;
        }
        let field = self.conv.field;
        match key.code {
            KeyCode::Esc => self.screen = Screen::Explorer,
            KeyCode::Tab | KeyCode::Down => self.conv_focus_step(true),
            KeyCode::BackTab | KeyCode::Up => self.conv_focus_step(false),
            KeyCode::F(5) => self.begin_conversion(),
            KeyCode::F(4) => {
                if field.is_path() {
                    self.complete(Input::Conv(field));
                } else {
                    self.notify(Level::Info, "Path completion (F4) works in path fields.");
                }
            }
            KeyCode::Enter => {
                if field == ConvField::Start {
                    self.begin_conversion();
                } else {
                    self.conv_focus_step(true);
                }
            }
            _ if field.is_text() => {
                let mut cursor = self.conv.cursor;
                if let Some(t) = self.conv.text_mut(field) {
                    let before = t.clone();
                    edit_text(t, &mut cursor, key);
                    let changed = *t != before;
                    self.conv.cursor = cursor;
                    if changed && field == ConvField::Source {
                        self.conv.detect_target();
                        self.conv.facts = None;
                        self.conv_due = Some(Instant::now() + PROBE_DEBOUNCE);
                    }
                }
            }
            KeyCode::Char(' ') if field == ConvField::Start => self.begin_conversion(),
            KeyCode::Char(' ') | KeyCode::Right => self.conv.toggle(field, true),
            KeyCode::Left => self.conv.toggle(field, false),
            _ => {}
        }
    }

    /// Start pressed in the converter: validate, then the confirmation sheet.
    pub fn begin_conversion(&mut self) {
        self.completion = None;
        let source = self.conv.source.trim().to_string();
        if source.is_empty() {
            self.conv.field = ConvField::Source;
            self.notify(Level::Error, "Enter the image to convert.");
            return;
        }
        if self.conv.destination.trim().is_empty() {
            self.conv.field = ConvField::Destination;
            self.notify(
                Level::Error,
                "Choose a destination directory for the converted image.",
            );
            return;
        }
        if let Err(msg) = self.conv.case.validate_required() {
            self.conv.field = [
                ConvField::CaseNumber,
                ConvField::EvidenceNumber,
                ConvField::Examiner,
            ]
            .into_iter()
            .find(|f| self.conv.text(*f).is_none_or(|t| t.trim().is_empty()))
            .unwrap_or(ConvField::CaseNumber);
            self.notify(Level::Error, msg);
            return;
        }
        let source_path = expand_tilde(Path::new(&source));
        let dir = expand_tilde(Path::new(self.conv.destination.trim()));
        let source_report = self
            .conv
            .facts
            .as_ref()
            .filter(|f| f.path == source_path)
            .and_then(|f| f.report.as_ref().map(|r| r.path.clone()));
        let request = ConversionRequest {
            source: source_path.clone(),
            target: self.conv.target,
            output_dir: dir.clone(),
            case: Some(self.conv.case.clone()),
            compression: self.conv.compression,
            split_size: self.conv.split,
            notes: self.conv.notes.clone(),
            source_report,
            ..Default::default()
        };
        self.token += 1;
        let token = self.token;
        self.confirm = Some(ConfirmState {
            subject: ConfirmSubject::Conversion {
                request: Box::new(request),
                facts: None,
                destination: None,
            },
            token,
            pending: true,
            typed: String::new(),
            cursor: 0,
            target: None,
            error: None,
            scroll: 0,
        });
        self.screen = Screen::Confirm;
        let backend = self.backend.clone();
        self.spawn_blocking(move || BgEvent::ConvPrepared {
            token,
            facts: probe_source(&source_path),
            destination: backend.destination(&dir),
        });
    }

    fn start_conversion_job(&mut self, request: ConversionRequest, facts: Option<SourceFacts>) {
        self.controller.reset();
        let (tx, rx) = mpsc::channel(256);
        let summary = vec![
            ("Source".to_string(), request.source.display().to_string()),
            (
                "Target".to_string(),
                match request.target {
                    ConversionTarget::E01 => "E01".to_string(),
                    ConversionTarget::Raw => "RAW".to_string(),
                },
            ),
            (
                "Destination".to_string(),
                request.output_dir.display().to_string(),
            ),
        ];
        let total = facts.and_then(|f| f.size).unwrap_or(0);
        let fut = self
            .backend
            .convert(request, tx, self.controller.stop_flags());
        self.job = Some(Job {
            kind: JobKind::Conversion,
            telemetry: ProgressTelemetry {
                status: AcquisitionStatus::Preparing,
                total_bytes: total,
                status_message: "Starting the conversion".into(),
                ..Default::default()
            },
            progress_rx: Some(rx),
            verify_rx: None,
            started: Instant::now(),
            summary,
            verify_source: false,
            abort_requested: false,
            force_requested: false,
        });
        self.confirm = None;
        self.screen = Screen::Running;
        self.spawn(async move {
            let result = match fut.await {
                Ok(report) => {
                    let text = tokio::fs::read_to_string(&report.report_file)
                        .await
                        .unwrap_or_else(|e| {
                            format!(
                                "(the report {} could not be read: {e})",
                                report.report_file.display()
                            )
                        });
                    Ok((report, text))
                }
                Err(e) => Err(e),
            };
            BgEvent::Converted(Box::new(result))
        });
    }

    // ------------------------------------------------------------------
    // Re-verification
    // ------------------------------------------------------------------

    pub fn open_verify(&mut self) {
        self.screen = Screen::Verify;
        self.completion = None;
        self.verify.cursor = self.verify.text(self.verify.field()).map_or(0, String::len);
    }

    fn verify_focus_step(&mut self, forward: bool) {
        let all = VerField::ALL;
        let i = all
            .iter()
            .position(|f| *f == self.verify.field())
            .unwrap_or(0);
        let n = all.len();
        let f = all[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }];
        self.verify.field = Some(f);
        self.verify.cursor = self.verify.text(f).map_or(0, String::len);
    }

    fn key_verify(&mut self, key: KeyEvent) {
        if key.code != KeyCode::F(4) {
            self.completion = None;
        }
        let field = self.verify.field();
        match key.code {
            KeyCode::Esc => self.screen = Screen::Explorer,
            KeyCode::Tab | KeyCode::Down => self.verify_focus_step(true),
            KeyCode::BackTab | KeyCode::Up => self.verify_focus_step(false),
            KeyCode::F(5) => self.begin_verification(),
            KeyCode::F(4) if field != VerField::Start => self.complete(Input::Verify(field)),
            KeyCode::Enter => {
                if field == VerField::Start {
                    self.begin_verification();
                } else {
                    self.verify_focus_step(true);
                }
            }
            KeyCode::Char(' ') if field == VerField::Start => self.begin_verification(),
            _ => {
                let mut cursor = self.verify.cursor;
                if let Some(t) = self.verify.text_mut(field) {
                    let before = t.clone();
                    edit_text(t, &mut cursor, key);
                    let changed = *t != before;
                    self.verify.cursor = cursor;
                    if changed {
                        match field {
                            VerField::Image => {
                                self.verify_due = Some(Instant::now() + PROBE_DEBOUNCE)
                            }
                            VerField::Report => self.verify.report_auto = false,
                            VerField::Start => {}
                        }
                    }
                }
            }
        }
    }

    /// Start the re-verification (reads the image, writes an addendum and an
    /// audit record; no confirmation sheet: nothing is acquired).
    pub fn begin_verification(&mut self) {
        self.completion = None;
        let image = self.verify.image.trim().to_string();
        if image.is_empty() {
            self.verify.field = Some(VerField::Image);
            self.notify(Level::Error, "Enter the image to verify.");
            return;
        }
        let image = expand_tilde(Path::new(&image));
        let report = Some(self.verify.report.trim().to_string())
            .filter(|r| !r.is_empty())
            .map(|r| expand_tilde(Path::new(&r)));
        self.controller.reset();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let backend = self.backend.clone();
        let stop = self.controller.stop_flags();
        let summary = vec![
            ("Image".to_string(), image.display().to_string()),
            (
                "Expected".to_string(),
                report
                    .as_ref()
                    .map(|r| format!("digests from {}", r.display()))
                    .unwrap_or_else(|| "none given: the digests are only computed".into()),
            ),
        ];
        self.job = Some(Job {
            kind: JobKind::Verification,
            telemetry: ProgressTelemetry {
                status: AcquisitionStatus::Verifying,
                status_message: "Re-reading the image".into(),
                ..Default::default()
            },
            progress_rx: None,
            verify_rx: Some(events_rx),
            started: Instant::now(),
            summary,
            verify_source: false,
            abort_requested: false,
            force_requested: false,
        });
        self.screen = Screen::Running;
        self.spawn(async move {
            let expected = match report {
                None => Ok(ExpectedHashes::default()),
                Some(p) => {
                    tokio::task::spawn_blocking(move || ExpectedHashes::from_report_json(&p))
                        .await
                        .unwrap_or_else(|e| {
                            Err(AcquisitionError::failed(format!(
                                "reading the report stopped: {e}"
                            )))
                        })
                }
            };
            let result = match expected {
                Ok(expected) => backend.verify(image, expected, stop, events_tx).await,
                Err(e) => Err(e),
            };
            BgEvent::Verified(Box::new(result))
        });
    }

    // ------------------------------------------------------------------
    // Path completion (F4), off the UI thread
    // ------------------------------------------------------------------

    fn input_state(&mut self, input: Input) -> Option<(&mut String, &mut usize)> {
        match input {
            Input::Case(Field::Destination) => Some((&mut self.form.destination, &mut self.cursor)),
            Input::Case(_) => None,
            Input::Conv(f) => {
                let ConvForm {
                    source,
                    destination,
                    cursor,
                    ..
                } = &mut self.conv;
                match f {
                    ConvField::Source => Some((source, cursor)),
                    ConvField::Destination => Some((destination, cursor)),
                    _ => None,
                }
            }
            Input::Verify(f) => {
                let VerifyForm {
                    image,
                    report,
                    cursor,
                    ..
                } = &mut self.verify;
                match f {
                    VerField::Image => Some((image, cursor)),
                    VerField::Report => Some((report, cursor)),
                    VerField::Start => None,
                }
            }
        }
    }

    /// F4 in a path input: the first press lists the candidates (and
    /// completes their common prefix), further presses cycle through them.
    pub fn complete(&mut self, input: Input) {
        if let Some(c) = &mut self.completion {
            if c.input == input && !c.pending && !c.candidates.is_empty() {
                let next = c.index.map_or(0, |i| (i + 1) % c.candidates.len());
                c.index = Some(next);
                let candidate = c.candidates[next].clone();
                let suffix = c.suffix.clone();
                if let Some((text, cursor)) = self.input_state(input) {
                    *text = format!("{candidate}{suffix}");
                    *cursor = candidate.len();
                }
                self.after_path_change(input);
                return;
            }
        }
        let dirs_only = matches!(
            input,
            Input::Case(Field::Destination) | Input::Conv(ConvField::Destination)
        );
        let Some((text, cursor)) = self.input_state(input) else {
            return;
        };
        let mut at = (*cursor).min(text.len());
        while at > 0 && !text.is_char_boundary(at) {
            at -= 1;
        }
        let prefix = text[..at].to_string();
        let suffix = text[at..].to_string();
        self.token += 1;
        let token = self.token;
        self.completion = Some(Completion {
            input,
            candidates: Vec::new(),
            index: None,
            suffix,
            token,
            pending: true,
        });
        let p = prefix.clone();
        self.spawn_blocking(move || BgEvent::Completion {
            token,
            candidates: find_path_completions(&p, dirs_only),
            prefix,
        });
    }

    fn apply_completion(&mut self, token: u64, prefix: String, candidates: Vec<String>) {
        let Some(c) = self.completion.clone() else {
            return;
        };
        if c.token != token {
            return;
        }
        let input = c.input;
        let unchanged = match self.input_state(input) {
            Some((text, cursor)) => text.get(..*cursor) == Some(prefix.as_str()),
            None => false,
        };
        if !unchanged {
            self.completion = None;
            return;
        }
        match candidates.len() {
            0 => {
                self.completion = None;
                self.notify(Level::Info, "No matching path.");
            }
            1 => {
                let only = candidates[0].clone();
                if let Some((text, cursor)) = self.input_state(input) {
                    *text = format!("{only}{}", c.suffix);
                    *cursor = only.len();
                }
                self.completion = None;
                self.after_path_change(input);
            }
            _ => {
                let lcp = longest_common_prefix(&candidates);
                if lcp.len() > prefix.len() {
                    if let Some((text, cursor)) = self.input_state(input) {
                        *text = format!("{lcp}{}", c.suffix);
                        *cursor = lcp.len();
                    }
                    self.after_path_change(input);
                }
                self.completion = Some(Completion {
                    candidates,
                    pending: false,
                    ..c
                });
            }
        }
    }

    fn after_path_change(&mut self, input: Input) {
        let due = Some(Instant::now() + PROBE_DEBOUNCE);
        match input {
            Input::Case(Field::Destination) => {
                self.form.allow_low_space = false;
                self.form.resume = false;
                self.dest_due = due;
            }
            Input::Conv(ConvField::Source) => {
                self.conv.detect_target();
                self.conv.facts = None;
                self.conv_due = due;
            }
            Input::Verify(VerField::Image) => self.verify_due = due,
            Input::Verify(VerField::Report) => self.verify.report_auto = false,
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Signals
    // ------------------------------------------------------------------

    /// A signal arrived (the [`AbortController`] already applied it to the
    /// flags). SIGHUP: continue headless and quit after the report; SIGTERM /
    /// SIGINT: graceful abort of a running job, then quit; idle: quit.
    pub fn on_signal(&mut self, kind: SignalKind, action: SignalAction) {
        match kind {
            SignalKind::Hangup => {
                self.headless = true;
                if self.job.is_some() {
                    self.quit_after_job = true;
                } else {
                    self.should_quit = true;
                }
            }
            SignalKind::Interrupt | SignalKind::Terminate => {
                if let Some(job) = &mut self.job {
                    job.abort_requested = true;
                    if action == SignalAction::Force {
                        job.force_requested = true;
                    }
                    self.quit_after_job = true;
                    self.notify(Level::Warning, action.message(kind));
                } else {
                    self.should_quit = true;
                }
            }
        }
    }

    /// One line for the terminal after the TUI closed, when a result was not
    /// acknowledged on screen.
    pub fn exit_summary(&self) -> Option<String> {
        if self.result_acknowledged {
            return None;
        }
        let r = self.result.as_ref()?;
        let report = r
            .files()
            .into_iter()
            .next()
            .map(|(_, p)| format!("; report: {p}"))
            .unwrap_or_default();
        Some(format!(
            "dfdisk: {} {}{}",
            r.kind().label(),
            r.title(),
            report
        ))
    }

    // ------------------------------------------------------------------
    // Tick
    // ------------------------------------------------------------------

    /// Periodic work on the UI thread (cheap): background results, progress,
    /// expiring notices, the periodic refresh and debounced probes.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        while let Ok(ev) = self.bg_rx.try_recv() {
            self.on_bg(ev);
        }
        if let Some(job) = &mut self.job {
            if let Some(rx) = &mut job.progress_rx {
                while let Ok(update) = rx.try_recv() {
                    job.telemetry.apply_update(update);
                }
            }
            if let Some(rx) = &mut job.verify_rx {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        VerifyEvent::Progress(p) => {
                            job.telemetry.status = AcquisitionStatus::Verifying;
                            job.telemetry.verify_progress = Some(PhaseProgress {
                                bytes_done: p.bytes_hashed,
                                total_bytes: p.total_bytes,
                                percentage: p.percentage,
                                speed_bps: p.speed_bps,
                            });
                        }
                        VerifyEvent::ToolOutput(line) => {
                            job.telemetry.push_log(sanitize_line(&line))
                        }
                    }
                }
            }
        }
        let now = Instant::now();
        self.notices
            .retain(|n| n.level != Level::Info || now.duration_since(n.at) < INFO_TTL);

        if self.auto_refresh
            && !self.scanning
            && self.job.is_none()
            && self.unmounting.is_none()
            && matches!(
                self.screen,
                Screen::Explorer | Screen::CaseSetup | Screen::Confirm
            )
            && self
                .last_scan
                .is_none_or(|t| now.duration_since(t) >= REFRESH_INTERVAL)
        {
            self.start_scan(false);
        }
        if self.dest_due.is_some_and(|t| now >= t) {
            self.dest_due = None;
            self.probe_destination();
        }
        if self.conv_due.is_some_and(|t| now >= t) {
            self.conv_due = None;
            let path = self.conv.source.trim().to_string();
            if !path.is_empty() {
                self.spawn_blocking(move || BgEvent::SourceProbe {
                    facts: probe_source(&expand_tilde(Path::new(&path))),
                    path,
                });
            }
        }
        if self.verify_due.is_some_and(|t| now >= t) {
            self.verify_due = None;
            let image = self.verify.image.trim().to_string();
            if !image.is_empty() && (self.verify.report.is_empty() || self.verify.report_auto) {
                self.spawn_blocking(move || BgEvent::VerifyReport {
                    report: report_candidate(&expand_tilde(Path::new(&image)))
                        .filter(|p| p.is_file()),
                    image,
                });
            }
        }
    }

    fn probe_destination(&mut self) {
        if self.form.destination.trim().is_empty() {
            self.destination_facts = None;
            return;
        }
        let dir = self.form.output_dir();
        let backend = self.backend.clone();
        self.spawn_blocking(move || BgEvent::Destination {
            result: backend.destination(&dir),
            dir,
        });
    }

    fn on_bg(&mut self, ev: BgEvent) {
        match ev {
            BgEvent::Scan { generation, result } => {
                if generation != self.scan_generation {
                    return;
                }
                self.scanning = false;
                self.last_scan = Some(Instant::now());
                match result {
                    Ok(devices) => {
                        self.last_scan_error = None;
                        let n = devices.len();
                        self.apply_scan(devices, true);
                        if self.scan_manual {
                            self.notify(Level::Info, format!("Device list refreshed ({n} disks)."));
                        }
                    }
                    Err(e) => {
                        if self.scan_manual || self.last_scan_error.as_deref() != Some(&e) {
                            self.notify(Level::Error, format!("Device scan failed: {e}"));
                        }
                        self.last_scan_error = Some(e);
                    }
                }
            }
            BgEvent::Destination { dir, result } => {
                if dir == self.form.output_dir() {
                    self.destination_facts = Some((dir, result));
                }
            }
            BgEvent::Capacity { disk, key, result } => {
                self.capacity_probing = None;
                match result {
                    Ok(info) => {
                        let hidden = info.hidden_area() == Some(true);
                        let summary = info.summary();
                        self.capacity.insert(disk.clone(), (key, info));
                        self.rebuild_rows();
                        if hidden {
                            self.notify(Level::Warning, format!("/dev/{disk}: {summary}"));
                        } else {
                            self.notify(Level::Info, format!("/dev/{disk}: {summary}"));
                        }
                    }
                    Err(e) => self.notify(
                        Level::Error,
                        format!("Hidden-area probe of /dev/{disk} failed: {e}"),
                    ),
                }
            }
            BgEvent::Unmount {
                key,
                path,
                then_setup,
                result,
            } => {
                self.unmounting = None;
                match result {
                    Ok(res) => {
                        self.notify(
                            Level::Info,
                            if res.unmounted.is_empty() {
                                format!("Nothing was mounted on {path}.")
                            } else {
                                format!("Unmounted (audited): {}", res.unmounted.join(", "))
                            },
                        );
                        if !res.holders.is_empty() {
                            self.notify(
                                Level::Warning,
                                format!(
                                    "Still open on {path} (reported, not closed): {}",
                                    res.holders.join(", ")
                                ),
                            );
                        }
                        self.unmounted = res.unmounted;
                        self.unmounted_key = Some(key.clone());
                        if then_setup {
                            if let Some(row) = self.rows.iter().find(|r| r.key == key).cloned() {
                                self.pin_source(row);
                            }
                        }
                        self.start_scan(false);
                    }
                    Err(e) => self.notify(
                        Level::Error,
                        format!("Unmount of {path} {}: {}", e.kind.label().to_lowercase(), e),
                    ),
                }
            }
            BgEvent::Prepared {
                token,
                resume_map,
                check,
                destination,
            } => {
                let Some(c) = &mut self.confirm else {
                    return;
                };
                if c.token != token {
                    return;
                }
                if let Some(map) = resume_map {
                    self.modal = Some(Modal::Resume { map });
                    return;
                }
                c.pending = false;
                if let ConfirmSubject::Acquisition {
                    request,
                    check: slot,
                    destination: dslot,
                    ..
                } = &mut c.subject
                {
                    let serial = check
                        .as_ref()
                        .and_then(|r| r.identity.as_ref())
                        .and_then(|i| i.serial.clone())
                        .or_else(|| request.device.serial.clone());
                    c.target = Some(ConfirmTarget::new(
                        serial.as_deref(),
                        &request.case.evidence_number,
                    ));
                    *slot = check;
                    *dslot = destination;
                }
            }
            BgEvent::ConvPrepared {
                token,
                facts,
                destination,
            } => {
                let Some(c) = &mut self.confirm else {
                    return;
                };
                if c.token != token {
                    return;
                }
                c.pending = false;
                if let ConfirmSubject::Conversion {
                    request,
                    facts: slot,
                    destination: dslot,
                } = &mut c.subject
                {
                    let serial = facts.report.as_ref().and_then(|r| r.serial.clone());
                    let evidence = request
                        .case
                        .as_ref()
                        .map(|cm| cm.evidence_number.clone())
                        .unwrap_or_default();
                    c.target = Some(ConfirmTarget::new(serial.as_deref(), &evidence));
                    *slot = Some(Box::new(facts));
                    *dslot = Some(destination);
                }
            }
            BgEvent::Completion {
                token,
                prefix,
                candidates,
            } => self.apply_completion(token, prefix, candidates),
            BgEvent::SourceProbe { path, facts } => {
                if path != self.conv.source.trim() {
                    return;
                }
                if facts.is_ewf {
                    self.conv.target = ConversionTarget::Raw;
                }
                if let Some(report) = &facts.report {
                    // Pre-fill what the report recorded; the examiner sees and
                    // may edit every value before it is recorded again
                    let case = &mut self.conv.case;
                    let from = &report.case;
                    for (dst, src) in [
                        (&mut case.case_number, &from.case_number),
                        (&mut case.evidence_number, &from.evidence_number),
                        (&mut case.location_ea, &from.location_ea),
                        (&mut case.authority, &from.authority),
                        (&mut case.description, &from.description),
                        (&mut case.seal_number, &from.seal_number),
                        (&mut case.seizure_time, &from.seizure_time),
                        (&mut case.seizure_location, &from.seizure_location),
                    ] {
                        if dst.trim().is_empty() {
                            *dst = src.clone();
                        }
                    }
                    if case.examiner.trim().is_empty() {
                        case.examiner = from.examiner.clone();
                    }
                    self.notify(
                        Level::Info,
                        format!("Case fields pre-filled from {}", report.path.display()),
                    );
                }
                self.conv.facts = Some(facts);
            }
            BgEvent::VerifyReport { image, report } => {
                if image != self.verify.image.trim() {
                    return;
                }
                if self.verify.report.is_empty() || self.verify.report_auto {
                    match report {
                        Some(p) => {
                            self.verify.report = p.display().to_string();
                            self.verify.report_auto = true;
                        }
                        None if self.verify.report_auto => {
                            self.verify.report.clear();
                            self.verify.report_auto = false;
                        }
                        None => {}
                    }
                }
            }
            BgEvent::Acquired(result) => {
                self.job = None;
                match *result {
                    Ok(report) => {
                        let text = report.render_text();
                        // Drive-specific fields start empty for the next drive
                        self.case.evidence_number.clear();
                        self.case.seal_number.clear();
                        self.case.description.clear();
                        self.case.notes.clear();
                        self.form.resume = false;
                        self.form.allow_low_space = false;
                        self.source = None;
                        self.source_invalid = None;
                        self.unmounted.clear();
                        self.unmounted_key = None;
                        self.show_result(RunResult::Acquisition {
                            report: Box::new(report),
                            text,
                        });
                    }
                    Err(error) => self.show_result(RunResult::Error {
                        kind: JobKind::Acquisition,
                        error,
                    }),
                }
                if self.auto_refresh {
                    self.start_scan(false);
                }
            }
            BgEvent::Converted(result) => {
                self.job = None;
                match *result {
                    Ok((report, text)) => self.show_result(RunResult::Conversion {
                        report: Box::new(report),
                        text,
                    }),
                    Err(error) => self.show_result(RunResult::Error {
                        kind: JobKind::Conversion,
                        error,
                    }),
                }
            }
            BgEvent::Verified(result) => {
                self.job = None;
                match *result {
                    Ok(v) => {
                        let text = v.render_text();
                        self.show_result(RunResult::Verification {
                            result: Box::new(v),
                            text,
                        })
                    }
                    Err(error) => self.show_result(RunResult::Error {
                        kind: JobKind::Verification,
                        error,
                    }),
                }
            }
            BgEvent::ProfileSaved(Err(e)) => self.notify(Level::Warning, e),
            BgEvent::ProfileSaved(Ok(())) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn ssh_warning_only_outside_a_multiplexer() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(*v))
            }
        };
        assert!(ssh_warning(env(&[("SSH_CONNECTION", "1 2 3 4")])).is_some());
        assert!(ssh_warning(env(&[("SSH_TTY", "/dev/pts/1"), ("TMUX", "/tmp/t,1,0")])).is_none());
        assert!(ssh_warning(env(&[("SSH_CLIENT", "x"), ("STY", "1.pts")])).is_none());
        assert!(ssh_warning(env(&[])).is_none());
        assert!(ssh_warning(env(&[("SSH_TTY", "")])).is_none());
    }

    #[test]
    fn ctrl_c_in_the_explorer_quits_and_never_opens_the_converter() {
        let mut app = App::with_devices(Vec::new());
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
        assert_eq!(app.screen, Screen::Explorer);
    }

    #[test]
    fn info_notices_expire_errors_stay() {
        let mut app = App::with_devices(Vec::new());
        app.notify(Level::Info, "info");
        app.notify(Level::Error, "error");
        for n in &mut app.notices {
            n.at -= INFO_TTL * 10;
        }
        app.tick();
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].text, "error");
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL));
        assert!(app.notices.is_empty());
    }

    #[test]
    fn help_opens_with_f1_and_question_mark_outside_text() {
        let mut app = App::with_devices(Vec::new());
        app.handle_key(key(KeyCode::Char('?')));
        assert!(matches!(app.modal, Some(Modal::Help)));
        app.handle_key(key(KeyCode::Esc));
        assert!(app.modal.is_none());
        app.handle_key(key(KeyCode::F(1)));
        assert!(matches!(app.modal, Some(Modal::Help)));
    }
}
