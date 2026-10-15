//! Rendering of the TUI with ratatui's TestBackend (§16, review H1): the
//! verdict banner comes first at 80x24 and 120x40, the "terminal too small"
//! screen, column priority of the serial number, truthful gauges, and no
//! panic at any terminal size.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dfdisk::engines::session::{AcquisitionRequest, CheckProblem, CheckReport};
use dfdisk::engines::{AcquisitionError, ErrorKind};
use dfdisk::models::config::{EffectiveConfig, EngineKind};
use dfdisk::models::device::{BlockDevice, DeviceSafety, Partition};
use dfdisk::models::identity::{SourceIdentity, SourceKind};
use dfdisk::models::info_report::{AuditStatus, ForensicInfoReport};
use dfdisk::models::outcome::{Outcome, RangeKind, ReadErrorTable, VerificationResult};
use dfdisk::models::telemetry::{AcquisitionStatus, PhaseProgress, ProgressTelemetry};
use dfdisk::tui::app::{
    App, ConfirmState, ConfirmSubject, Job, JobKind, Level, Modal, RunResult, Screen,
};
use dfdisk::tui::confirm::ConfirmTarget;
use dfdisk::tui::ui::{self, outcome_color};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Modifier;
use ratatui::Terminal;

const SERIAL: &str = "S4EVNX0R812345B_LONG";

fn devices() -> Vec<BlockDevice> {
    vec![
        BlockDevice {
            name: "sdx".into(),
            path: "/dev/sdx".into(),
            size_bytes: 2_000_398_934_016,
            model: Some("Very Long Vendor Model Name Of A Disk".into()),
            vendor: Some("ACME".into()),
            serial: Some(SERIAL.into()),
            bus_type: "USB".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(17),
            logical_sector_size: 512,
            physical_sector_size: 4096,
            is_read_only: true,
            partitions: (1..=3)
                .map(|i| Partition {
                    name: format!("sdx{i}"),
                    path: format!("/dev/sdx{i}"),
                    size_bytes: 1 << 30,
                    kind: Some("part".into()),
                    maj_min: Some(format!("8:{}", 16 + i)),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        },
        BlockDevice {
            name: "sdw".into(),
            path: "/dev/sdw".into(),
            size_bytes: 1 << 40,
            serial: Some("SYS".into()),
            mountpoints: vec!["/".into()],
            safety: DeviceSafety::SystemDisk(vec!["/".into()]),
            protected: Some("dfnix boot medium".into()),
            holders: vec!["dm-0".into()],
            maj_min: Some("8:0".into()),
            ..Default::default()
        },
    ]
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn draw(app: &mut App, w: u16, h: u16) -> Buffer {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| ui::render(f, app)).unwrap();
    t.backend().buffer().clone()
}

fn text(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in 0..area.height {
        for x in 0..area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn identity(dev: &BlockDevice) -> SourceIdentity {
    let mut id = SourceIdentity {
        path: dev.path.clone(),
        kernel_name: dev.name.clone(),
        kind: SourceKind::Disk,
        size_bytes: dev.size_bytes,
        logical_sector_size: 512,
        physical_sector_size: 4096,
        model: dev.model.clone(),
        ..Default::default()
    };
    id.add_serial_candidate(SERIAL, dfdisk::models::identity::SerialSource::Lsblk);
    id
}

fn case_app() -> App {
    let mut app = App::with_devices(devices());
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen, Screen::CaseSetup);
    app.case.case_number = "2026-0042".into();
    app.case.evidence_number = "HDD01".into();
    app.case.examiner = "J. Doe".into();
    app.form.destination = "/mnt/evidence/a/very/long/destination/path/that/scrolls".into();
    app
}

fn report(outcome: Outcome) -> ForensicInfoReport {
    let dev = &devices()[0];
    let id = identity(dev);
    let app = case_app();
    let config = app.form.config();
    let mut r = ForensicInfoReport::new(
        EngineKind::Ewf,
        &app.case,
        id.clone(),
        EffectiveConfig::build(&config, Some(&id)),
    );
    r.output_dir = "/mnt/evidence/case".into();
    r.base_name = "2026-0042_01_HDD01_S4EVNX0R812345B_LONG".into();
    r.image_files = vec![format!("/mnt/evidence/case/{}.E01", r.base_name)];
    let mut facts = r.facts();
    facts.bytes_acquired = facts.expected_bytes;
    facts.verification = VerificationResult::Matched {
        method: "ewfverify".into(),
    };
    match outcome {
        Outcome::Verified => {}
        Outcome::CompleteUnverified => {
            facts.verification = VerificationResult::NotPossible {
                reason: "no second read".into(),
            }
        }
        Outcome::CompletedWithReadErrors => {
            let mut t = ReadErrorTable::new(512, "ewfinfo -e");
            t.push_sectors(2048, 64, RangeKind::Substituted);
            facts.read_errors = t;
        }
        Outcome::Incomplete => {
            facts.bytes_acquired /= 2;
            facts.stop_reason = Some("source lost at offset 1000".into());
        }
        Outcome::Mismatch => {
            facts.verification = VerificationResult::Mismatched {
                method: "ewfverify".into(),
                details: "MD5 acquisition 00.. image 11..".into(),
            }
        }
        Outcome::VerificationFailed => {
            facts.verification = VerificationResult::Failed {
                reason: "ewfverify could not run".into(),
            }
        }
        Outcome::Aborted => facts.aborted = true,
    }
    r.apply_facts(&facts);
    assert_eq!(r.outcome, outcome);
    r
}

fn result_app(outcome: Outcome) -> App {
    let mut app = App::with_devices(devices());
    let r = report(outcome);
    let text = r.render_text();
    app.result = Some(RunResult::Acquisition {
        report: Box::new(r),
        text,
    });
    app.screen = Screen::Result;
    app
}

#[test]
fn verdict_banner_comes_first_at_80x24_and_120x40() {
    for outcome in Outcome::ALL {
        for (w, h) in [(80u16, 24u16), (120, 40)] {
            let mut app = result_app(outcome);
            let buf = draw(&mut app, w, h);
            let screen = text(&buf);
            let title = format!("{} (exit code {})", outcome.label(), outcome.exit_code());
            // The banner is the first content row under the header
            let banner_row: String = screen.lines().nth(2).unwrap().to_string();
            assert!(
                banner_row.contains(&title),
                "{outcome:?} at {w}x{h}: banner row {banner_row:?}\n{screen}"
            );
            // Coloured by outcome
            let x = banner_row.find('■').map(|_| 3).unwrap();
            assert_eq!(buf[(x, 2)].bg, outcome_color(outcome), "{outcome:?}");
            // The explanation follows right under it
            let explanation: String = outcome
                .explanation_for(EngineKind::Ewf)
                .chars()
                .take(20)
                .collect();
            assert!(
                screen.lines().nth(3).unwrap().contains(&explanation),
                "{outcome:?} at {w}x{h}\n{screen}"
            );
            if outcome != Outcome::Verified {
                assert!(!screen.contains("ALL HASHES MATCH"), "{outcome:?}");
            }
        }
    }
    // The key numbers of a read-error result are visible at 80x24
    let mut app = result_app(Outcome::CompletedWithReadErrors);
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("64 sectors"), "{screen}");
    assert!(screen.contains("Report"), "file list shown");
}

#[test]
fn error_results_and_audit_problems_are_shown() {
    let mut app = App::with_devices(devices());
    app.result = Some(RunResult::Error {
        kind: JobKind::Acquisition,
        error: AcquisitionError::new(ErrorKind::Refused, "the destination is a tmpfs"),
    });
    app.screen = Screen::Result;
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("REFUSED (exit code 3)"), "{screen}");
    assert!(screen.contains("the destination is a tmpfs"));
    assert!(screen.contains("No image and no report were written"));

    let mut app = result_app(Outcome::Verified);
    if let Some(RunResult::Acquisition { report, .. }) = &mut app.result {
        report.audit.status = AuditStatus::NotWritten {
            reason: "log not writable".into(),
        };
    }
    let screen = text(&draw(&mut app, 120, 40));
    assert!(screen.contains("AUDIT LOG NOT WRITTEN"), "{screen}");
}

#[test]
fn the_full_report_scrolls() {
    let mut app = result_app(Outcome::Mismatch);
    let first = text(&draw(&mut app, 80, 24));
    for _ in 0..30 {
        app.handle_key(key(KeyCode::Down));
    }
    let later = text(&draw(&mut app, 80, 24));
    assert_ne!(first, later);
    // The banner stays on top while the report scrolls
    assert!(later.lines().nth(2).unwrap().contains("HASH MISMATCH"));
    app.handle_key(key(KeyCode::End));
    let end = text(&draw(&mut app, 80, 24));
    assert!(end.contains("Full report"));
}

#[test]
fn too_small_terminal_screen() {
    for (w, h) in [(79u16, 24u16), (80, 23), (40, 10), (20, 3)] {
        let mut app = App::with_devices(devices());
        let screen = text(&draw(&mut app, w, h));
        assert!(
            screen.contains("small") || screen.contains("Terminal"),
            "{w}x{h}:\n{screen}"
        );
    }
    let mut app = App::with_devices(devices());
    let screen = text(&draw(&mut app, 80, 24));
    assert!(!screen.contains("too small"));
}

fn all_states() -> Vec<(&'static str, App)> {
    let mut states = Vec::new();
    let mut explorer = App::with_devices(devices());
    explorer.notify(Level::Error, "x".repeat(300));
    explorer.notify(Level::Warning, "warning");
    explorer.notify(Level::Info, "info ケース");
    explorer.notify(Level::Error, "second error");
    states.push(("explorer", explorer));
    let mut empty = App::with_devices(Vec::new());
    empty.scanning = true;
    states.push(("empty", empty));

    let mut case = case_app();
    case.field = dfdisk::tui::form::Field::Destination;
    case.cursor = 10;
    case.source_invalid = Some("The selected source /dev/sdx changed: serial X (was Y)".into());
    states.push(("case", case));

    let mut confirm = case_app();
    let dev = confirm.source.clone().unwrap().device;
    let config = confirm.form.config();
    let request = AcquisitionRequest::new(dev.clone(), confirm.case.clone(), config.clone());
    let id = identity(&dev);
    let check = CheckReport {
        ready: false,
        device: dev.path.clone(),
        engine: EngineKind::Ewf,
        output_dir: config.output_dir.clone(),
        base_name: confirm.base_name_preview(),
        identity: Some(id.clone()),
        tool_source_path: Some("/dev/disk/by-diskseq/17".into()),
        effective_config: Some(EffectiveConfig::build(&config, Some(&id))),
        write_protection: None,
        write_protection_plan: Some("would set read-only (BLKROSET): /dev/sdx".into()),
        destination: None,
        capacity: None,
        smart: None,
        problems: vec![CheckProblem {
            step: "destination".into(),
            kind: ErrorKind::Refused,
            message: "free space ".repeat(20),
        }],
        notes: vec!["a note".into()],
    };
    confirm.confirm = Some(ConfirmState {
        subject: ConfirmSubject::Acquisition {
            request: Box::new(request),
            base_name: "BASE".into(),
            check: Some(Box::new(check)),
            destination: Some(Err("cannot read".into())),
        },
        token: 1,
        pending: false,
        typed: "世界abc".into(),
        cursor: 3,
        target: Some(ConfirmTarget::new(Some(SERIAL), "HDD01")),
        error: Some("does not match".into()),
        scroll: 5,
    });
    confirm.screen = Screen::Confirm;
    states.push(("confirm", confirm));

    let mut running = case_app();
    running.job = Some(Job::detached(
        JobKind::Acquisition,
        ProgressTelemetry {
            status: AcquisitionStatus::Verifying,
            total_bytes: 100,
            bytes_processed: 100,
            percentage: 100.0,
            log_messages: (0..50).map(|i| format!("line {i}")).collect(),
            verify_progress: Some(PhaseProgress {
                bytes_done: 50,
                total_bytes: 100,
                percentage: 50.0,
                speed_bps: 1.0,
            }),
            ..Default::default()
        },
        vec![("Source".into(), "/dev/sdx".into()); 8],
        true,
    ));
    running.screen = Screen::Running;
    running.modal = Some(Modal::Abort);
    states.push(("running", running));

    for outcome in [Outcome::Mismatch, Outcome::Aborted] {
        states.push(("result", result_app(outcome)));
    }
    let mut conv = App::with_devices(Vec::new());
    conv.handle_key(key(KeyCode::Char('c')));
    conv.conv.source = "/x/".repeat(40);
    conv.conv.notes = vec!["rescue read errors: 8 sectors".into()];
    states.push(("converter", conv));
    let mut verify = App::with_devices(Vec::new());
    verify.handle_key(key(KeyCode::Char('v')));
    states.push(("verify", verify));
    let mut help = App::with_devices(devices());
    help.modal = Some(Modal::Help);
    states.push(("help", help));
    states
}

#[test]
fn no_panic_at_any_size() {
    // Every width at the boundary heights, every height at the boundary
    // widths, and a coarse grid in between
    let mut sizes = Vec::new();
    for w in 0..=200u16 {
        for h in [0u16, 1, 23, 24, 25, 60] {
            sizes.push((w, h));
        }
    }
    for h in 0..=60u16 {
        for w in [0u16, 1, 79, 80, 81, 200] {
            sizes.push((w, h));
        }
    }
    for w in (0..=200u16).step_by(10) {
        for h in (0..=60u16).step_by(5) {
            sizes.push((w, h));
        }
    }
    std::thread::scope(|scope| {
        for (name, mut app) in all_states() {
            let sizes = &sizes;
            scope.spawn(move || {
                for &(w, h) in sizes {
                    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
                    t.draw(|f| ui::render(f, &mut app))
                        .unwrap_or_else(|e| panic!("{name} at {w}x{h}: {e}"));
                }
            });
        }
    });
}

#[test]
fn serial_has_priority_over_the_model_at_80_columns() {
    let mut app = App::with_devices(devices());
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains(SERIAL), "{screen}");
    // Partitions are listed as sources; every badge is shown, in short form
    // when the full labels do not fit
    assert!(screen.contains("└ sdx1"));
    assert!(screen.contains("SYS PROT MNT HOLD"), "{screen}");
    let wide = text(&draw(&mut app, 160, 30));
    assert!(wide.contains("SYSTEM PROTECTED MOUNTED IN-USE"), "{wide}");
}

#[test]
fn the_table_scrolls_to_the_selection() {
    let many: Vec<BlockDevice> = (0..30)
        .map(|i| BlockDevice {
            name: format!("sd{i}"),
            path: format!("/dev/sd{i}"),
            serial: Some(format!("SERIAL{i:03}")),
            maj_min: Some(format!("8:{}", i * 16)),
            ..Default::default()
        })
        .collect();
    let mut app = App::with_devices(many);
    app.handle_key(key(KeyCode::End));
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("SERIAL029"), "{screen}");
}

#[test]
fn case_setup_shows_the_source_and_marks_placeholders() {
    let mut app = App::with_devices(devices());
    app.handle_key(key(KeyCode::Enter));
    let buf = draw(&mut app, 80, 24);
    let screen = text(&buf);
    assert!(
        screen.contains("/dev/sdx") && screen.contains(SERIAL),
        "{screen}"
    );
    assert!(screen.contains("Case number*"));
    assert!(screen.contains("Review and confirm"));
    // The example in an empty field is drawn in italics, never as a value
    let (x, y) = find(&buf, "e.g. HDD01").expect("placeholder shown");
    assert!(buf[(x, y)].modifier.contains(Modifier::ITALIC));
    assert!(screen.contains("fill in case number"));
    // Fields that do not apply are greyed: RAW shows no compression value
    app.form.engine = EngineKind::Raw;
    app.case.case_number = "C".into();
    app.case.evidence_number = "E".into();
    app.case.examiner = "X".into();
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("n/a (E01 only)"));
    let base = app.base_name_preview().unwrap();
    assert!(screen.contains(&format!("{base}.raw")), "{screen}");
}

fn find(buf: &Buffer, needle: &str) -> Option<(u16, u16)> {
    let area = buf.area;
    for y in 0..area.height {
        let mut row = String::new();
        let mut xs = Vec::new();
        for x in 0..area.width {
            let s = buf[(x, y)].symbol();
            for _ in 0..s.len() {
                xs.push(x);
            }
            row.push_str(s);
        }
        if let Some(i) = row.find(needle) {
            return Some((xs[i], y));
        }
    }
    None
}

#[test]
fn input_scrolls_horizontally_to_the_cursor() {
    let mut app = case_app();
    app.field = dfdisk::tui::form::Field::Destination;
    app.cursor = app.form.destination.len();
    let screen = text(&draw(&mut app, 80, 24));
    assert!(
        screen.contains("that/scrolls"),
        "end of the path visible:\n{screen}"
    );
    app.cursor = 0;
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("/mnt/evidence"), "{screen}");
}

#[test]
fn verify_gauge_is_truthful() {
    let mut app = case_app();
    app.job = Some(Job::detached(
        JobKind::Acquisition,
        ProgressTelemetry {
            status: AcquisitionStatus::Verifying,
            total_bytes: 100,
            bytes_processed: 100,
            percentage: 100.0,
            ..Default::default()
        },
        vec![("Source".into(), "/dev/sdx".into())],
        false,
    ));
    app.screen = Screen::Running;
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("the tool reports no progress"), "{screen}");
    assert!(screen.contains("verify image"));
    assert!(
        !screen.contains("re-read source"),
        "no second read configured"
    );
    // Esc is documented as not aborting
    assert!(screen.contains("Esc does NOT abort"));
}

#[test]
fn long_errors_are_wrapped_and_the_hidden_ones_counted() {
    let mut app = App::with_devices(devices());
    for i in 0..4 {
        app.notify(
            Level::Error,
            format!("error number {i}: Unmount of /dev/sdx1 refused: /media/evidence/some/long/path is held by process 1234 (bash) and cannot be unmounted without force"),
        );
    }
    let screen = text(&draw(&mut app, 80, 24));
    // The newest error in full (it was cut at the terminal width)
    assert!(
        screen.contains("✖ error number 3: Unmount of /dev/sdx1 refused"),
        "{screen}"
    );
    assert!(
        screen.contains("cannot be unmounted without force"),
        "{screen}"
    );
    assert!(
        screen.contains("2 more message(s), 2 of them errors; Ctrl+X dismisses the ones shown"),
        "{screen}"
    );
}

#[test]
fn modals_are_sized_to_content_and_fit_80x24() {
    let mut app = App::with_devices(devices());
    app.modal = Some(Modal::Help);
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("Any key closes this help"), "{screen}");
    let mut app = case_app();
    app.screen = Screen::Running;
    app.job = Some(Job::detached(
        JobKind::Acquisition,
        ProgressTelemetry::default(),
        Vec::new(),
        false,
    ));
    app.modal = Some(Modal::Abort);
    let buf = draw(&mut app, 120, 40);
    let screen = text(&buf);
    assert!(screen.contains("Abort now? [y/N]"), "{screen}");
    let (x, _) = find(&buf, "Abort now?").unwrap();
    assert!(x > 10, "centred, not full width");

    // Quit while an unmount runs: it is not interrupted, dfdisk waits
    let mut app = App::with_devices(devices());
    app.unmounting = Some("/dev/sdx".into());
    app.modal = Some(Modal::Quit);
    let screen = text(&draw(&mut app, 80, 24));
    assert!(
        screen.contains("An audited unmount of /dev/sdx is running"),
        "{screen}"
    );
    assert!(screen.contains("Quit then? [y/N]"), "{screen}");
    assert!(!screen.contains("Abort and quit"), "{screen}");
}

#[test]
fn confirmation_sheet_at_80x24() {
    let mut states = all_states();
    let (_, mut app) = states.remove(3);
    app.confirm.as_mut().unwrap().scroll = 0;
    let screen = text(&draw(&mut app, 80, 24));
    assert!(screen.contains("NOT READY"), "{screen}");
    assert!(screen.contains("CONFIRM ACQUISITION"));
    assert!(screen.contains("does not match"));
}
