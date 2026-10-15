//! The TUI state machine driven with key events and a scripted backend
//! (§16, R10): nothing here touches a host disk or runs a tool.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dfdisk::discovery::safety::UnmountResult;
use dfdisk::engines::preflight::DestinationFacts;
use dfdisk::engines::session::{AcquisitionRequest, CheckProblem, CheckReport};
use dfdisk::engines::verify::{ExpectedHashes, ImageVerification, VerifyEvent, VerifyOptions};
use dfdisk::engines::{AcquisitionError, ErrorKind};
use dfdisk::models::capacity::CapacityInfo;
use dfdisk::models::config::{EffectiveConfig, EngineKind, SmartPolicy};
use dfdisk::models::conversion::{ConversionReport, ConversionRequest};
use dfdisk::models::device::{BlockDevice, DeviceSafety, Partition};
use dfdisk::models::identity::{SourceIdentity, SourceKind};
use dfdisk::models::info_report::{ForensicInfoReport, HashResults};
use dfdisk::models::outcome::{Outcome, VerificationResult};
use dfdisk::models::telemetry::ProgressTelemetry;
use dfdisk::signals::{SignalAction, SignalKind, StopFlags};
use dfdisk::tui::app::{App, Level, Modal, RunResult, Screen};
use dfdisk::tui::backend::{ProgressTx, TuiBackend};
use dfdisk::tui::form::{ConvField, Field};
use futures::future::BoxFuture;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn disk(name: &str, serial: Option<&str>, seq: u64, minor: u32) -> BlockDevice {
    BlockDevice {
        name: name.into(),
        path: format!("/dev/{name}"),
        size_bytes: 64 << 30,
        model: Some("Test Disk".into()),
        serial: serial.map(String::from),
        bus_type: "USB".into(),
        transport: Some("usb".into()),
        logical_sector_size: 512,
        physical_sector_size: 512,
        maj_min: Some(format!("8:{minor}")),
        diskseq: Some(seq),
        partitions: vec![Partition {
            name: format!("{name}1"),
            path: format!("/dev/{name}1"),
            size_bytes: 1 << 30,
            kind: Some("part".into()),
            maj_min: Some(format!("8:{}", minor + 1)),
            start_sector: Some(2048),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn evidence() -> BlockDevice {
    disk("sdx", Some("WX41A8F2KD7Y"), 17, 16)
}

fn mounted() -> BlockDevice {
    let mut d = disk("sdy", Some("MNT0001"), 18, 32);
    d.partitions[0].mountpoint = Some("/media/stick".into());
    d.mountpoints = vec!["/media/stick".into()];
    d.safety = DeviceSafety::Mounted(vec!["/media/stick".into()]);
    d
}

fn system() -> BlockDevice {
    let mut d = disk("sdw", Some("SYS0001"), 1, 0);
    d.mountpoints = vec!["/".into()];
    d.safety = DeviceSafety::SystemDisk(vec!["/".into()]);
    d
}

fn identity_of(dev: &BlockDevice) -> SourceIdentity {
    let mut id = SourceIdentity {
        path: dev.path.clone(),
        canonical_path: dev.path.clone(),
        kernel_name: dev.name.clone(),
        maj_min: dev.maj_min.clone(),
        diskseq: dev.diskseq,
        kind: SourceKind::Disk,
        size_bytes: dev.size_bytes,
        logical_sector_size: 512,
        physical_sector_size: 512,
        model: dev.model.clone(),
        ..Default::default()
    };
    if let Some(s) = &dev.serial {
        id.add_serial_candidate(s, dfdisk::models::identity::SerialSource::Lsblk);
    }
    id
}

fn check_for(req: &AcquisitionRequest, problems: Vec<CheckProblem>) -> CheckReport {
    let id = identity_of(&req.device);
    CheckReport {
        ready: problems.is_empty(),
        device: req.device.path.clone(),
        engine: req.engine(),
        output_dir: req.config.output_dir.clone(),
        base_name: req
            .case
            .base_filename_checked(&req.device.display_serial())
            .ok(),
        effective_config: Some(EffectiveConfig::build(&req.config, Some(&id))),
        identity: Some(id),
        tool_source_path: None,
        write_protection: None,
        write_protection_plan: None,
        destination: None,
        capacity: None,
        smart: None,
        problems,
        notes: Vec::new(),
    }
}

fn report_for(req: &AcquisitionRequest, aborted: bool, mismatch: bool) -> ForensicInfoReport {
    let id = identity_of(&req.device);
    let mut r = ForensicInfoReport::new(
        req.engine(),
        &req.case,
        id.clone(),
        EffectiveConfig::build(&req.config, Some(&id)),
    );
    r.output_dir = req.config.output_dir.display().to_string();
    r.base_name = req
        .case
        .base_filename_checked(&req.device.display_serial())
        .unwrap();
    r.image_files = vec![format!("{}/{}.E01", r.output_dir, r.base_name)];
    let mut facts = r.facts();
    facts.aborted = aborted;
    facts.bytes_acquired = if aborted { 4096 } else { facts.expected_bytes };
    facts.verification = if mismatch {
        VerificationResult::Mismatched {
            method: "ewfverify".into(),
            details: "MD5 differs".into(),
        }
    } else {
        VerificationResult::Matched {
            method: "ewfverify".into(),
        }
    };
    r.acquisition_hashes = HashResults {
        md5: Some("00".repeat(16)),
        ..Default::default()
    };
    r.apply_facts(&facts);
    r
}

// ---------------------------------------------------------------------------
// Scripted backend
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Acquire {
    Verified,
    Mismatch,
    Refused,
    /// Runs until the abort flag is set, then reports Aborted
    UntilAborted,
}

struct Script {
    scans: VecDeque<Vec<BlockDevice>>,
    last_scan: Vec<BlockDevice>,
    problems: VecDeque<Vec<CheckProblem>>,
    check_requests: Vec<AcquisitionRequest>,
    acquire_requests: Vec<AcquisitionRequest>,
    acquire: Acquire,
    destination: Result<DestinationFacts, String>,
    unmounts: Vec<String>,
    conversions: Vec<ConversionRequest>,
    audit_log: Option<PathBuf>,
}

#[derive(Clone)]
struct Fake(Arc<Mutex<Script>>);

impl Fake {
    fn new(devices: Vec<BlockDevice>) -> Self {
        Fake(Arc::new(Mutex::new(Script {
            scans: VecDeque::new(),
            last_scan: devices,
            problems: VecDeque::new(),
            check_requests: Vec::new(),
            acquire_requests: Vec::new(),
            acquire: Acquire::Verified,
            destination: Ok(DestinationFacts {
                fs_type: Some("ext4".into()),
                free_bytes: Some(1 << 40),
                ..Default::default()
            }),
            unmounts: Vec::new(),
            conversions: Vec::new(),
            audit_log: None,
        })))
    }

    fn s(&self) -> std::sync::MutexGuard<'_, Script> {
        self.0.lock().unwrap()
    }
}

impl TuiBackend for Fake {
    fn scan(&self) -> Result<Vec<BlockDevice>, String> {
        let mut s = self.s();
        if let Some(next) = s.scans.pop_front() {
            s.last_scan = next;
        }
        Ok(s.last_scan.clone())
    }

    fn destination(&self, _dir: &Path) -> Result<DestinationFacts, String> {
        self.s().destination.clone()
    }

    fn unmount(&self, device: &BlockDevice) -> Result<UnmountResult, AcquisitionError> {
        self.s().unmounts.push(device.path.clone());
        Ok(UnmountResult {
            unmounted: device.mountpoints.clone(),
            holders: Vec::new(),
            audit_hash: Some("h".into()),
            mounts_before: device.mountpoints.clone(),
            ..Default::default()
        })
    }

    fn capacity(&self, device: BlockDevice) -> BoxFuture<'static, Result<CapacityInfo, String>> {
        Box::pin(async move { Ok(CapacityInfo::not_probed(device.size_bytes, "test")) })
    }

    fn check(&self, request: AcquisitionRequest) -> BoxFuture<'static, CheckReport> {
        let me = self.clone();
        Box::pin(async move {
            let problems = me.s().problems.pop_front().unwrap_or_default();
            me.s().check_requests.push(request.clone());
            check_for(&request, problems)
        })
    }

    fn acquire(
        &self,
        request: AcquisitionRequest,
        _progress: ProgressTx,
        stop: StopFlags,
    ) -> BoxFuture<'static, Result<ForensicInfoReport, AcquisitionError>> {
        let me = self.clone();
        Box::pin(async move {
            me.s().acquire_requests.push(request.clone());
            let mode = me.s().acquire;
            match mode {
                Acquire::Verified => Ok(report_for(&request, false, false)),
                Acquire::Mismatch => Ok(report_for(&request, false, true)),
                Acquire::Refused => Err(AcquisitionError::refused("in use: mounted elsewhere")),
                Acquire::UntilAborted => {
                    for _ in 0..1000 {
                        if stop.is_aborted() {
                            return Ok(report_for(&request, true, false));
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(AcquisitionError::failed("test: never aborted"))
                }
            }
        })
    }

    fn convert(
        &self,
        request: ConversionRequest,
        _progress: ProgressTx,
        _stop: StopFlags,
    ) -> BoxFuture<'static, Result<ConversionReport, AcquisitionError>> {
        let me = self.clone();
        Box::pin(async move {
            me.s().conversions.push(request);
            Err(AcquisitionError::refused(
                "Refusing to overwrite: the output already exists",
            ))
        })
    }

    fn verify(
        &self,
        image: PathBuf,
        expected: ExpectedHashes,
        stop: StopFlags,
        events: mpsc::UnboundedSender<VerifyEvent>,
    ) -> BoxFuture<'static, Result<ImageVerification, AcquisitionError>> {
        // The real verification of a RAW file (hashed by dfdisk, no tool),
        // with the audit record in a temporary log
        let log = self.s().audit_log.clone();
        Box::pin(async move {
            let options = VerifyOptions {
                write_addendum: true,
                audit_log: log,
                ..Default::default()
            };
            dfdisk::engines::verify::verify_image(&image, &expected, &options, &stop, |e| {
                let _ = events.send(e);
            })
            .await
        })
    }
}

// ---------------------------------------------------------------------------
// Driving
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn typ(app: &mut App, text: &str) {
    for c in text.chars() {
        app.handle_key(key(KeyCode::Char(c)));
    }
}

async fn pump(app: &mut App, what: &str, done: impl Fn(&App) -> bool) {
    for _ in 0..1000 {
        app.tick();
        if done(app) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn app_with(fake: &Fake) -> App {
    let devices = fake.s().last_scan.clone();
    App::with_backend(devices, Arc::new(fake.clone()))
}

fn select(app: &mut App, kernel_name: &str) {
    app.handle_key(key(KeyCode::Home));
    for _ in 0..app.rows.len() {
        if app.current_row().unwrap().key.kernel_name == kernel_name {
            return;
        }
        app.handle_key(key(KeyCode::Down));
    }
    panic!("{kernel_name} not in the table");
}

/// Explorer -> case setup on sdx with every required field typed.
fn to_case_setup(app: &mut App, dest: &str) {
    select(app, "sdx");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::CaseSetup);
    for (field, text) in [
        (Field::CaseNumber, "2026-0042"),
        (Field::EvidenceNumber, "HDD01"),
        (Field::Examiner, "J. Doe"),
        (Field::Destination, dest),
    ] {
        app.field = field;
        app.cursor = 0;
        app.handle_key(ctrl('u'));
        typ(app, text);
    }
}

async fn to_confirm(app: &mut App) {
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.screen, Screen::Confirm);
    pump(app, "pre-flight checks", |a| {
        a.confirm.as_ref().is_some_and(|c| !c.pending)
    })
    .await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn selection_follows_identity_across_refresh_and_hotplug() {
    let fake = Fake::new(vec![system(), evidence()]);
    let mut app = app_with(&fake);
    select(&mut app, "sdx");
    let before = app.table_state.selected().unwrap();
    // Hot-plug: a new disk sorts in front of the selected one
    fake.s()
        .scans
        .push_back(vec![system(), disk("sda", Some("NEW1"), 30, 0), evidence()]);
    app.handle_key(key(KeyCode::Char('r')));
    pump(&mut app, "rescan", |a| !a.scanning).await;
    let now = app.table_state.selected().unwrap();
    assert_ne!(before, now, "the row index moved");
    assert_eq!(app.current_row().unwrap().key.kernel_name, "sdx");
    assert_eq!(
        app.current_row().unwrap().device.serial.as_deref(),
        Some("WX41A8F2KD7Y")
    );
    assert!(!app.notices.iter().any(|n| n.level != Level::Info));
}

#[tokio::test]
async fn a_changed_or_vanished_source_is_invalidated() {
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    // Another drive on the same kernel name (swapped in the dock)
    fake.s()
        .scans
        .push_back(vec![disk("sdx", Some("OTHERDRIVE01"), 21, 16)]);
    app.start_scan(true);
    pump(&mut app, "rescan", |a| !a.scanning).await;
    let reason = app.source_invalid.clone().expect("invalidated");
    assert!(
        reason.contains("changed") && reason.contains("serial OTHERDRIVE01"),
        "{reason}"
    );
    assert!(app
        .notices
        .iter()
        .any(|n| n.level == Level::Error && n.text.contains("changed")));
    // Start is refused, no check runs
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.screen, Screen::CaseSetup);
    assert!(fake.s().check_requests.is_empty());

    // Selecting the device again clears it
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Enter));
    assert!(app.source_invalid.is_none());
    assert_eq!(
        app.source.as_ref().unwrap().device.serial.as_deref(),
        Some("OTHERDRIVE01")
    );

    // Vanished while the confirmation sheet is open: back to the case setup
    to_confirm(&mut app).await;
    fake.s().scans.push_back(Vec::new());
    app.start_scan(false);
    pump(&mut app, "rescan", |a| !a.scanning).await;
    assert_eq!(app.screen, Screen::CaseSetup);
    assert!(app.confirm.is_none());
    assert!(app.source_invalid.as_ref().unwrap().contains("disappeared"));
}

#[tokio::test]
async fn required_fields_are_enforced_and_placeholders_never_used() {
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    select(&mut app, "sdx");
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.screen, Screen::CaseSetup, "nothing starts");
    assert!(app.show_required);
    assert_eq!(app.field, Field::CaseNumber);
    assert!(app
        .notices
        .iter()
        .any(|n| n.level == Level::Error && n.text.contains("Required case information")));
    assert!(app.case.case_number.is_empty() && app.case.examiner.is_empty());
    typ(&mut app, "C1");
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.field, Field::EvidenceNumber);
    typ(&mut app, "E1");
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.field, Field::Examiner);
    typ(&mut app, "Ex");
    // Destination is required too
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.field, Field::Destination);
    typ(&mut app, "/mnt/c");
    to_confirm(&mut app).await;
    let req = fake.s().check_requests[0].clone();
    assert_eq!(req.case.case_number, "C1");
    assert_eq!(req.case.evidence_number, "E1");
    assert_eq!(req.case.examiner, "Ex");
    assert_eq!(req.case.description, "", "placeholders are not values");
    assert_eq!(req.config.output_dir, PathBuf::from("/mnt/c"));
}

#[tokio::test]
async fn tab_and_shift_tab_always_move_between_fields() {
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt");
    assert_eq!(app.field, Field::Destination);
    // Tab in a path field moves on (completion is F4)
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.field, Field::Engine);
    assert!(app.completion.is_none());
    app.handle_key(key(KeyCode::BackTab));
    assert_eq!(app.field, Field::Destination);
    // E01: MD5 is forced and skipped
    app.field = Field::Segments;
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.field, Field::Sha1);
    // RAW: compression and segments are skipped
    app.field = Field::Engine;
    app.handle_key(key(KeyCode::Right));
    assert_eq!(app.form.engine, EngineKind::Raw);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.field, Field::Md5);
    // Full cycle comes back
    let start = app.field;
    for _ in 0..Field::focus_order(EngineKind::Raw).len() {
        app.handle_key(key(KeyCode::Tab));
    }
    assert_eq!(app.field, start);

    // Converter and verification forms too
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Char('c')));
    assert_eq!(app.screen, Screen::Converter);
    assert_eq!(app.conv.field, ConvField::Source);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.conv.field, ConvField::Target);
    app.handle_key(key(KeyCode::BackTab));
    assert_eq!(app.conv.field, ConvField::Source);
}

#[tokio::test]
async fn confirmation_requires_the_serial_suffix() {
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    let c = app.confirm.as_ref().unwrap();
    assert!(c.ready());
    assert!(c.target.as_ref().unwrap().prompt().contains("LAST 4"));
    // The dry run sends no SMART command
    assert_eq!(fake.s().check_requests[0].config.smart, SmartPolicy::Off);

    // Enter without typing, a wrong suffix, the evidence number: nothing starts
    for attempt in ["", "KD7", "HDD01", "2KD7Y"] {
        app.confirm.as_mut().unwrap().typed.clear();
        app.confirm.as_mut().unwrap().cursor = 0;
        typ(&mut app, attempt);
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Confirm, "{attempt:?} must not start");
        assert!(app.confirm.as_ref().unwrap().error.is_some());
    }
    assert!(fake.s().acquire_requests.is_empty());

    // Last four characters, any case, surrounding spaces
    app.confirm.as_mut().unwrap().typed.clear();
    app.confirm.as_mut().unwrap().cursor = 0;
    typ(&mut app, " kd7y ");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Running);
    pump(&mut app, "result", |a| a.screen == Screen::Result).await;
    let req = fake.s().acquire_requests[0].clone();
    assert_eq!(
        req.config.smart,
        SmartPolicy::Basic,
        "SMART runs once, in the run"
    );
    assert_eq!(req.device.name, "sdx");
    match &app.result {
        Some(RunResult::Acquisition { report, .. }) => {
            assert_eq!(report.outcome, Outcome::Verified)
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_source_without_serial_is_confirmed_with_the_evidence_number() {
    let fake = Fake::new(vec![disk("sdx", None, 17, 16)]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    assert!(app
        .confirm
        .as_ref()
        .unwrap()
        .target
        .as_ref()
        .unwrap()
        .prompt()
        .contains("EVIDENCE NUMBER"));
    typ(&mut app, "hdd0");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Confirm);
    typ(&mut app, "1");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Running);
}

#[tokio::test]
async fn a_refused_check_cannot_be_started() {
    let fake = Fake::new(vec![evidence()]);
    fake.s().problems.push_back(vec![CheckProblem {
        step: "destination".into(),
        kind: ErrorKind::Refused,
        message: "tmpfs destination".into(),
    }]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    assert!(!app.confirm.as_ref().unwrap().ready());
    typ(&mut app, "KD7Y");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Confirm);
    assert!(fake.s().acquire_requests.is_empty());
    // Esc goes back without starting
    app.handle_key(key(KeyCode::Esc));
    assert_eq!(app.screen, Screen::CaseSetup);
}

#[tokio::test]
async fn e01_with_less_free_space_needs_an_explicit_confirmation() {
    let fake = Fake::new(vec![evidence()]);
    fake.s().destination = Ok(DestinationFacts {
        fs_type: Some("ext4".into()),
        free_bytes: Some(1 << 30),
        ..Default::default()
    });
    fake.s().problems.push_back(vec![CheckProblem {
        step: "destination".into(),
        kind: ErrorKind::Refused,
        message: "free space".into(),
    }]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    assert_eq!(app.low_space_offer(), Some((1 << 30, 64 << 30)));
    app.handle_key(key(KeyCode::F(6)));
    pump(&mut app, "second check", |a| {
        a.confirm.as_ref().is_some_and(|c| !c.pending)
    })
    .await;
    let reqs = fake.s().check_requests.clone();
    assert_eq!(reqs.len(), 2);
    assert!(!reqs[0].config.allow_low_space);
    assert!(reqs[1].config.allow_low_space);
    assert!(app.confirm.as_ref().unwrap().ready());
    assert_eq!(app.low_space_offer(), None);
}

#[tokio::test]
async fn abort_needs_confirmation_and_esc_never_aborts() {
    let fake = Fake::new(vec![evidence()]);
    fake.s().acquire = Acquire::UntilAborted;
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    typ(&mut app, "kd7y");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Running);

    app.handle_key(key(KeyCode::Esc));
    assert!(!app.controller.is_aborted(), "Esc never aborts");
    assert!(app.modal.is_none());

    app.handle_key(key(KeyCode::Char('a')));
    assert!(matches!(app.modal, Some(Modal::Abort)));
    app.handle_key(key(KeyCode::Enter)); // default is No
    assert!(app.modal.is_none());
    assert!(!app.controller.is_aborted());

    app.handle_key(key(KeyCode::Char('a')));
    app.handle_key(key(KeyCode::Char('n')));
    assert!(!app.controller.is_aborted());

    app.handle_key(key(KeyCode::Char('a')));
    app.handle_key(key(KeyCode::Char('y')));
    assert!(app.controller.is_aborted());
    assert!(!app.controller.is_forced());
    // A second abort offers the immediate stop
    app.handle_key(key(KeyCode::Char('a')));
    assert!(matches!(app.modal, Some(Modal::Force)));
    app.handle_key(key(KeyCode::Esc));

    pump(&mut app, "aborted result", |a| a.screen == Screen::Result).await;
    let r = app.result.as_ref().unwrap();
    assert_eq!(r.label(), "ABORTED");
    assert_eq!(r.exit_code(), 8);
    // The controller is reset for the next run
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Explorer);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    typ(&mut app, "kd7y");
    app.handle_key(key(KeyCode::Enter));
    assert!(!app.controller.is_aborted(), "reset between runs");
    app.handle_key(key(KeyCode::Char('a')));
    app.handle_key(key(KeyCode::Char('y')));
    pump(&mut app, "aborted result", |a| a.screen == Screen::Result).await;
}

#[tokio::test]
async fn ctrl_c_while_busy_asks_then_quits_after_the_report() {
    let fake = Fake::new(vec![evidence()]);
    fake.s().acquire = Acquire::UntilAborted;
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    typ(&mut app, "KD7Y");
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(ctrl('c'));
    assert!(matches!(app.modal, Some(Modal::Quit)));
    assert!(!app.should_quit);
    app.handle_key(key(KeyCode::Char('n')));
    assert!(!app.controller.is_aborted() && !app.should_quit);
    app.handle_key(ctrl('c'));
    app.handle_key(key(KeyCode::Char('y')));
    assert!(app.controller.is_aborted());
    assert!(!app.should_quit, "waits for the report");
    pump(&mut app, "quit after report", |a| a.should_quit).await;
    assert!(app.exit_summary().unwrap().contains("ABORTED"));
}

#[tokio::test]
async fn sighup_continues_headless_and_quits_after_the_report() {
    let fake = Fake::new(vec![evidence()]);
    fake.s().acquire = Acquire::UntilAborted;
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    typ(&mut app, "KD7Y");
    app.handle_key(key(KeyCode::Enter));
    let action = app.controller.handle(SignalKind::Hangup);
    app.on_signal(SignalKind::Hangup, action);
    assert!(app.headless && !app.should_quit && !app.controller.is_aborted());
    // SIGTERM later: graceful abort, the report is still awaited
    let action = app.controller.handle(SignalKind::Terminate);
    assert_eq!(action, SignalAction::Abort);
    app.on_signal(SignalKind::Terminate, action);
    assert!(app.controller.is_aborted() && !app.should_quit);
    pump(&mut app, "quit after report", |a| a.should_quit).await;
    assert!(matches!(app.result, Some(RunResult::Acquisition { .. })));

    // Idle: a signal quits at once
    let mut idle = app_with(&Fake::new(vec![evidence()]));
    idle.on_signal(SignalKind::Hangup, SignalAction::Headless);
    assert!(idle.should_quit);
}

#[tokio::test]
async fn results_and_errors_stay_until_acknowledged() {
    let fake = Fake::new(vec![evidence()]);
    fake.s().acquire = Acquire::Refused;
    let mut app = app_with(&fake);
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    typ(&mut app, "KD7Y");
    app.handle_key(key(KeyCode::Enter));
    pump(&mut app, "result", |a| a.screen == Screen::Result).await;
    let r = app.result.as_ref().unwrap();
    assert_eq!(r.label(), "REFUSED");
    assert_eq!(r.exit_code(), 3);
    assert!(r.lines().iter().any(|l| l.contains("in use")));
    // Quitting now (e.g. by signal) exits with the unseen result's code
    assert_eq!(app.exit_code(), 3);
    assert!(app
        .exit_summary()
        .unwrap()
        .contains("REFUSED (exit code 3)"));
    // It does not go away by itself
    for _ in 0..50 {
        app.tick();
    }
    assert_eq!(app.screen, Screen::Result);
    // Scrolling keeps it
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Char('q')));
    assert_eq!(app.screen, Screen::Result);
    app.handle_key(key(KeyCode::Enter));
    // Acknowledged on screen: the TUI exits 0
    assert_eq!(app.exit_code(), 0);
    assert!(app.exit_summary().is_none());
    // A refused acquisition goes back to the case setup with the values kept
    assert_eq!(app.screen, Screen::CaseSetup);
    assert_eq!(app.case.evidence_number, "HDD01");
    // ... and the last result is still reachable
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Char('l')));
    assert_eq!(app.screen, Screen::Result);

    // A mismatch report: drive-specific fields are cleared afterwards
    fake.s().acquire = Acquire::Mismatch;
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Esc));
    to_case_setup(&mut app, "/mnt/case");
    to_confirm(&mut app).await;
    typ(&mut app, "KD7Y");
    app.handle_key(key(KeyCode::Enter));
    pump(&mut app, "result", |a| {
        matches!(a.result, Some(RunResult::Acquisition { .. }))
    })
    .await;
    assert_eq!(app.result.as_ref().unwrap().exit_code(), 5);
    assert!(app.case.evidence_number.is_empty());
    assert_eq!(app.case.examiner, "J. Doe");
}

#[tokio::test]
async fn refused_sources_and_audited_unmount() {
    let fake = Fake::new(vec![system(), mounted(), evidence()]);
    let mut app = app_with(&fake);
    select(&mut app, "sdw");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Explorer);
    assert!(app
        .notices
        .iter()
        .any(|n| n.level == Level::Error && n.text.contains("running system")));
    // The system disk is never offered for unmounting
    app.handle_key(key(KeyCode::Char('u')));
    assert!(app.modal.is_none());

    select(&mut app, "sdy");
    app.handle_key(key(KeyCode::Enter));
    assert!(matches!(app.modal, Some(Modal::Unmount { .. })));
    app.handle_key(key(KeyCode::Char('n')));
    assert!(fake.s().unmounts.is_empty());
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char('y')));
    pump(&mut app, "unmount", |a| a.screen == Screen::CaseSetup).await;
    assert_eq!(fake.s().unmounts, vec!["/dev/sdy".to_string()]);
    assert_eq!(app.source.as_ref().unwrap().key.kernel_name, "sdy");
    // The unmounted mount points are passed to the session (report + audit)
    app.case.case_number = "C".into();
    app.case.evidence_number = "E".into();
    app.case.examiner = "X".into();
    app.form.destination = "/mnt/case".into();
    to_confirm(&mut app).await;
    let req = fake.s().check_requests[0].clone();
    assert_eq!(req.unmounted_by_dfdisk, vec!["/media/stick".to_string()]);
}

#[tokio::test]
async fn partitions_are_selectable_sources() {
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    select(&mut app, "sdx1");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::CaseSetup);
    let src = &app.source.as_ref().unwrap().device;
    assert_eq!(src.kind, SourceKind::Partition);
    assert_eq!(src.path, "/dev/sdx1");
    assert_eq!(src.serial.as_deref(), Some("WX41A8F2KD7Y"));
    assert_eq!(src.parent.as_deref(), Some("/dev/sdx"));
}

#[tokio::test]
async fn a_partition_whose_mapping_is_mounted_offers_the_unmount() {
    // sdx -> sdx1 (LUKS) -> luks-x (mounted at /media/x), as the scan lists it
    let mut d = evidence();
    d.partitions[0].fstype = Some("crypto_LUKS".into());
    d.partitions[0].tree_mounts = vec!["/media/x".into()];
    d.partitions[0].holders = vec!["dm-0".into()];
    d.partitions[0].parent_disks = vec!["/dev/sdx".into()];
    d.partitions.push(Partition {
        name: "luks-x".into(),
        path: "/dev/mapper/luks-x".into(),
        size_bytes: (1 << 30) - (16 << 20),
        kind: Some("crypt".into()),
        maj_min: Some("254:0".into()),
        mountpoint: Some("/media/x".into()),
        tree_mounts: vec!["/media/x".into()],
        parent_disks: vec!["/dev/sdx".into()],
        ..Default::default()
    });
    d.mountpoints = vec!["/media/x".into()];
    d.holders = vec!["dm-0".into()];
    d.safety = DeviceSafety::Mounted(vec!["/media/x".into()]);
    let fake = Fake::new(vec![d]);
    let mut app = app_with(&fake);
    select(&mut app, "sdx1");
    let row = app.current_row().unwrap();
    assert_eq!(row.badge_text(), "MOUNTED IN-USE");
    // U offers the audited unmount of the partition's tree (it said "has no
    // mounted filesystem")
    app.handle_key(key(KeyCode::Char('u')));
    match &app.modal {
        Some(Modal::Unmount { device, mounts, .. }) => {
            assert_eq!(device.path, "/dev/sdx1");
            assert_eq!(mounts, &["/media/x".to_string()]);
        }
        other => panic!("{other:?}; notices {:?}", app.notices),
    }
    app.handle_key(key(KeyCode::Char('n')));
    // Enter does not start a case setup on a mounted source either
    app.handle_key(key(KeyCode::Enter));
    assert!(matches!(app.modal, Some(Modal::Unmount { .. })));
    assert_eq!(app.screen, Screen::Explorer);
}

#[tokio::test]
async fn rescue_resume_prompt_when_a_map_exists() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, &dir.path().display().to_string());
    app.form.engine = EngineKind::Rescue;
    let base = app.base_name_preview().unwrap();
    std::fs::write(dir.path().join(format!("{base}.map")), "# map\n0x0 +\n").unwrap();
    app.handle_key(key(KeyCode::F(5)));
    pump(&mut app, "resume prompt", |a| {
        matches!(a.modal, Some(Modal::Resume { .. }))
    })
    .await;
    assert!(fake.s().check_requests.is_empty());
    app.handle_key(key(KeyCode::Char('y')));
    pump(&mut app, "check", |a| {
        a.confirm.as_ref().is_some_and(|c| !c.pending)
    })
    .await;
    assert!(fake.s().check_requests[0].config.resume);

    // Declining goes back without a check
    app.handle_key(key(KeyCode::Esc));
    app.form.resume = false;
    app.handle_key(key(KeyCode::F(5)));
    pump(&mut app, "resume prompt", |a| {
        matches!(a.modal, Some(Modal::Resume { .. }))
    })
    .await;
    app.handle_key(key(KeyCode::Char('n')));
    assert_eq!(app.screen, Screen::CaseSetup);
    assert_eq!(fake.s().check_requests.len(), 1);
}

#[tokio::test]
async fn case_profile_prefills_suggests_and_is_saved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dfdisk").join("profile.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "examiner = \"A. Examiner\"\nauthority = \"Unit 7\"\nlast_destination = \"/mnt/ev\"\nlast_case = \"2026-0042\"\nlast_evidence = \"HDD07\"\n",
    )
    .unwrap();
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    app.load_profile_from(path.clone());
    assert_eq!(app.case.examiner, "A. Examiner");
    assert_eq!(app.case.authority, "Unit 7");
    assert_eq!(app.form.destination, "/mnt/ev");
    // Suggestions are not values until accepted
    select(&mut app, "sdx");
    app.handle_key(key(KeyCode::Enter));
    assert!(app.case.case_number.is_empty());
    assert_eq!(
        app.suggestion(Field::CaseNumber).as_deref(),
        Some("2026-0042")
    );
    app.handle_key(key(KeyCode::Right));
    assert_eq!(app.case.case_number, "2026-0042");
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(
        app.suggestion(Field::EvidenceNumber).as_deref(),
        Some("HDD08")
    );
    app.handle_key(key(KeyCode::End));
    assert_eq!(app.case.evidence_number, "HDD08");

    to_confirm(&mut app).await;
    typ(&mut app, "KD7Y");
    app.handle_key(key(KeyCode::Enter));
    pump(&mut app, "result", |a| a.screen == Screen::Result).await;
    // The profile is saved on a blocking thread, independently of the run:
    // wait for its content, not for the result screen
    let saved = wait_for_file(&path, "last_evidence = \"HDD08\"").await;
    assert!(saved.contains("examiner = \"A. Examiner\""), "{saved}");
}

/// The content of `path` once it contains `needle` (5 s at most).
async fn wait_for_file(path: &Path, needle: &str) -> String {
    let mut last = String::new();
    for _ in 0..1000 {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains(needle) {
                return text;
            }
            last = text;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "{} never contained {needle:?}; last content:\n{last}",
        path.display()
    );
}

#[tokio::test]
async fn path_completion_is_a_separate_key_with_a_candidate_list() {
    let dir = tempfile::tempdir().unwrap();
    for d in ["case_alpha", "case_beta"] {
        std::fs::create_dir(dir.path().join(d)).unwrap();
    }
    let fake = Fake::new(vec![evidence()]);
    let mut app = app_with(&fake);
    to_case_setup(&mut app, &format!("{}/c", dir.path().display()));
    app.handle_key(key(KeyCode::F(4)));
    pump(&mut app, "completion", |a| {
        a.completion.as_ref().is_some_and(|c| !c.pending)
    })
    .await;
    let base = dir.path().display().to_string();
    assert_eq!(app.form.destination, format!("{base}/case_"));
    assert_eq!(app.completion.as_ref().unwrap().candidates.len(), 2);
    app.handle_key(key(KeyCode::F(4)));
    assert_eq!(app.form.destination, format!("{base}/case_alpha/"));
    app.handle_key(key(KeyCode::F(4)));
    assert_eq!(app.form.destination, format!("{base}/case_beta/"));
    // Tab moves to the next field and closes the list
    app.handle_key(key(KeyCode::Tab));
    assert!(app.completion.is_none());
    assert_eq!(app.field, Field::Engine);
}

#[tokio::test]
async fn reverification_writes_an_addendum() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.raw");
    std::fs::write(&image, b"dfdisk test image").unwrap();
    let fake = Fake::new(vec![]);
    fake.s().audit_log = Some(dir.path().join("audit.jsonl"));
    let mut app = app_with(&fake);
    app.handle_key(key(KeyCode::Char('v')));
    assert_eq!(app.screen, Screen::Verify);
    typ(&mut app, &image.display().to_string());
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.screen, Screen::Running);
    pump(&mut app, "verification", |a| a.screen == Screen::Result).await;
    match app.result.as_ref().unwrap() {
        RunResult::Verification { result, .. } => {
            assert!(result.addendum.as_ref().is_some_and(|a| a.exists()));
            assert!(matches!(
                result.result,
                VerificationResult::NotPossible { .. }
            ));
        }
        other => panic!("{other:?}"),
    }
    let label = app.result.as_ref().unwrap().label();
    assert!(label.contains("NOTHING COMPARED"), "{label}");
}

#[tokio::test]
async fn conversion_goes_through_the_confirmation_sheet() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("img.raw");
    std::fs::write(&image, vec![0u8; 4096]).unwrap();
    let fake = Fake::new(vec![]);
    let mut app = app_with(&fake);
    app.handle_key(key(KeyCode::Char('c')));
    typ(&mut app, &image.display().to_string());
    app.conv.field = ConvField::Destination;
    app.conv.cursor = app.conv.destination.len();
    typ(&mut app, &dir.path().join("out").display().to_string());
    // Required case fields
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.screen, Screen::Converter);
    assert_eq!(app.conv.field, ConvField::CaseNumber);
    typ(&mut app, "C9");
    app.handle_key(key(KeyCode::Tab));
    typ(&mut app, "EV9");
    app.handle_key(key(KeyCode::Tab));
    typ(&mut app, "Ex");
    app.handle_key(key(KeyCode::F(5)));
    assert_eq!(app.screen, Screen::Confirm);
    pump(&mut app, "conversion facts", |a| {
        a.confirm.as_ref().is_some_and(|c| !c.pending)
    })
    .await;
    assert!(app.confirm.as_ref().unwrap().ready());
    // No serial known: the evidence number confirms
    typ(&mut app, "ev");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::Confirm);
    typ(&mut app, "9");
    app.handle_key(key(KeyCode::Enter));
    pump(&mut app, "conversion result", |a| {
        a.screen == Screen::Result
    })
    .await;
    assert_eq!(app.result.as_ref().unwrap().label(), "REFUSED");
    let req = fake.s().conversions[0].clone();
    assert_eq!(req.source, image);
    assert_eq!(req.case.as_ref().unwrap().evidence_number, "EV9");
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(
        app.screen,
        Screen::Converter,
        "back to the form after an error"
    );
}

#[test]
fn offline_app_never_touches_the_host() {
    let mut app = App::with_devices(vec![evidence()]);
    assert!(!app.auto_refresh);
    app.tick();
    assert!(!app.scanning);
    assert_eq!(app.rows.len(), 2);
    let _ = ProgressTelemetry::default();
}
