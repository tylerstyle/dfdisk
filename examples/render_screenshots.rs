//! Renders TUI screens with example data into SVG files (and PNG files when
//! ImageMagick's `magick` is available and `--png` is given), for the README.
//!
//! Usage: `cargo run --example render_screenshots -- [OUTPUT_DIR] [--png]`
//! (default OUTPUT_DIR: `target/screenshots` in the crate). Every value shown
//! is invented example data; nothing is read from the host.

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use std::path::{Path, PathBuf};

use dfdisk::engines::preflight::DestinationFacts;
use dfdisk::engines::session::{AcquisitionRequest, CheckReport};
use dfdisk::models::capacity::{AtaCapacity, CapacityInfo};
use dfdisk::models::case::CaseMetadata;
use dfdisk::models::config::{EffectiveConfig, EngineKind};
use dfdisk::models::device::{BlockDevice, DeviceSafety, Partition};
use dfdisk::models::identity::{SourceIdentity, SourceKind};
use dfdisk::models::info_report::{AuditInfo, AuditStatus, ForensicInfoReport, HashResults};
use dfdisk::models::outcome::{RangeKind, ReadErrorTable, VerificationResult};
use dfdisk::models::protection::{RegistryPresence, WriteProtection};
use dfdisk::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use dfdisk::tui::app::{App, ConfirmState, ConfirmSubject, Job, JobKind, RunResult, Screen};
use dfdisk::tui::confirm::ConfirmTarget;
use dfdisk::tui::form::Field;
use dfdisk::tui::ui;

fn color_to_hex(color: Color) -> &'static str {
    match color {
        Color::Reset => "#1E1E2E",
        Color::Black => "#11111B",
        Color::Red | Color::LightRed => "#F38BA8",
        Color::Green | Color::LightGreen => "#A6E3A1",
        Color::Yellow | Color::LightYellow => "#F9E2AF",
        Color::Blue | Color::LightBlue => "#89B4FA",
        Color::Magenta | Color::LightMagenta => "#F5C2E7",
        Color::Cyan | Color::LightCyan => "#94E2D5",
        Color::Gray => "#A6ADC8",
        Color::DarkGray => "#585B70",
        Color::White => "#CDD6F4",
        _ => "#CDD6F4",
    }
}

fn color_to_string(color: Color) -> String {
    match color {
        Color::Rgb(r, g, b) => format!("#{:02X}{:02X}{:02X}", r, g, b),
        _ => color_to_hex(color).to_string(),
    }
}

/// Text colour: the terminal's default foreground for `Reset` (as a
/// terminal draws it), not the background colour.
fn fg_to_string(color: Color) -> String {
    match color {
        Color::Reset => "#CDD6F4".to_string(),
        other => color_to_string(other),
    }
}

fn is_box_drawing(sym: &str) -> bool {
    matches!(
        sym,
        "─" | "│"
            | "╭"
            | "╮"
            | "╯"
            | "╰"
            | "┌"
            | "┐"
            | "└"
            | "┘"
            | "├"
            | "┤"
            | "┬"
            | "┴"
            | "┼"
            | "═"
            | "║"
            | "╔"
            | "╗"
            | "╚"
            | "╝"
            | "█"
    )
}

fn buffer_to_svg(buffer: &Buffer, width_cells: u16, height_cells: u16) -> String {
    let cell_w = 8.0f64;
    let cell_h = 16.0f64;
    let pad_x = 6.0f64;
    let pad_y = 0.0f64;

    let total_w = (pad_x * 2.0 + width_cells as f64 * cell_w).ceil() as u32;
    let total_h = (pad_y * 2.0 + height_cells as f64 * cell_h).ceil() as u32;

    let mut svg = String::new();
    let bg_base = "#1E1E2E";
    svg.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{total_h}" viewBox="0 0 {total_w} {total_h}">
  <rect width="{total_w}" height="{total_h}" fill="{bg_base}"/>
"#,
        total_w = total_w,
        total_h = total_h,
        bg_base = bg_base
    ));

    // Pass 1: Render all background rects
    for y in 0..height_cells {
        for x in 0..width_cells {
            let cell = buffer.cell((x, y)).unwrap();
            let bg = cell.bg;
            if bg != Color::Reset && bg != Color::Black {
                let bg_hex = color_to_string(bg);
                if bg_hex != "#1E1E2E" && bg_hex != "#11111B" {
                    let cx = pad_x + x as f64 * cell_w;
                    let cy = pad_y + y as f64 * cell_h;
                    svg.push_str(&format!(
                        r#"  <rect x="{}" y="{}" width="{}" height="{}" fill="{}"/>
"#,
                        cx, cy, cell_w, cell_h, bg_hex
                    ));
                }
            }
        }
    }

    // Pass 2: Render box drawing characters and text runs
    for y in 0..height_cells {
        let cy = pad_y + y as f64 * cell_h;
        let mut x = 0;

        while x < width_cells {
            let cell = buffer.cell((x, y)).unwrap();
            let sym = cell.symbol();

            if sym.is_empty() || sym == " " {
                x += 1;
                continue;
            }

            let fg_hex = fg_to_string(cell.fg);
            let cx = pad_x + x as f64 * cell_w;

            if is_box_drawing(sym) {
                match sym {
                    "─" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx, cy + 8.0, cx + 8.0, cy + 8.0, fg_hex
                        ));
                    }
                    "│" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx + 4.0, cy, cx + 4.0, cy + 16.0, fg_hex
                        ));
                    }
                    "╭" => {
                        svg.push_str(&format!(
                            r#"  <path d="M {} {} L {} {} A 4 4 0 0 1 {} {} L {} {}" fill="none" stroke="{}" stroke-width="1"/>
"#,
                            cx + 4.0, cy + 16.0, cx + 4.0, cy + 12.0, cx + 8.0, cy + 8.0, cx + 8.0, cy + 8.0, fg_hex
                        ));
                    }
                    "╮" => {
                        svg.push_str(&format!(
                            r#"  <path d="M {} {} L {} {} A 4 4 0 0 1 {} {} L {} {}" fill="none" stroke="{}" stroke-width="1"/>
"#,
                            cx, cy + 8.0, cx + 4.0, cy + 8.0, cx + 4.0, cy + 12.0, cx + 4.0, cy + 16.0, fg_hex
                        ));
                    }
                    "╯" => {
                        svg.push_str(&format!(
                            r#"  <path d="M {} {} L {} {} A 4 4 0 0 0 {} {} L {} {}" fill="none" stroke="{}" stroke-width="1"/>
"#,
                            cx, cy + 8.0, cx + 4.0, cy + 8.0, cx + 4.0, cy + 4.0, cx + 4.0, cy, fg_hex
                        ));
                    }
                    "╰" => {
                        svg.push_str(&format!(
                            r#"  <path d="M {} {} L {} {} A 4 4 0 0 0 {} {} L {} {}" fill="none" stroke="{}" stroke-width="1"/>
"#,
                            cx + 4.0, cy, cx + 4.0, cy + 4.0, cx + 8.0, cy + 8.0, cx + 8.0, cy + 8.0, fg_hex
                        ));
                    }
                    "═" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx, cy + 6.0, cx + 8.0, cy + 6.0, fg_hex,
                            cx, cy + 10.0, cx + 8.0, cy + 10.0, fg_hex
                        ));
                    }
                    "║" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx + 2.0, cy, cx + 2.0, cy + 16.0, fg_hex,
                            cx + 6.0, cy, cx + 6.0, cy + 16.0, fg_hex
                        ));
                    }
                    "╔" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx + 2.0, cy + 10.0, cx + 2.0, cy + 16.0, fg_hex,
                            cx + 6.0, cy + 6.0, cx + 6.0, cy + 16.0, fg_hex,
                            cx + 6.0, cy + 6.0, cx + 8.0, cy + 6.0, fg_hex,
                            cx + 2.0, cy + 10.0, cx + 8.0, cy + 10.0, fg_hex
                        ));
                    }
                    "╗" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx + 6.0, cy + 10.0, cx + 6.0, cy + 16.0, fg_hex,
                            cx + 2.0, cy + 6.0, cx + 2.0, cy + 16.0, fg_hex,
                            cx, cy + 6.0, cx + 2.0, cy + 6.0, fg_hex,
                            cx, cy + 10.0, cx + 6.0, cy + 10.0, fg_hex
                        ));
                    }
                    "╚" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx + 2.0, cy, cx + 2.0, cy + 6.0, fg_hex,
                            cx + 6.0, cy, cx + 6.0, cy + 10.0, fg_hex,
                            cx + 6.0, cy + 10.0, cx + 8.0, cy + 10.0, fg_hex,
                            cx + 2.0, cy + 6.0, cx + 8.0, cy + 6.0, fg_hex
                        ));
                    }
                    "╝" => {
                        svg.push_str(&format!(
                            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="1"/>
"#,
                            cx + 6.0, cy, cx + 6.0, cy + 6.0, fg_hex,
                            cx + 2.0, cy, cx + 2.0, cy + 10.0, fg_hex,
                            cx, cy + 10.0, cx + 2.0, cy + 10.0, fg_hex,
                            cx, cy + 6.0, cx + 6.0, cy + 6.0, fg_hex
                        ));
                    }
                    "█" => {
                        svg.push_str(&format!(
                            r#"  <rect x="{}" y="{}" width="{}" height="{}" fill="{}"/>
"#,
                            cx, cy, cell_w, cell_h, fg_hex
                        ));
                    }
                    _ => {}
                }
                x += 1;
            } else {
                // Collect contiguous text run with same style
                let start_x = x;
                let cur_fg = cell.fg;
                let cur_bg = cell.bg;
                let cur_mod = cell.modifier;

                let mut text = String::new();
                while x < width_cells {
                    let next_cell = buffer.cell((x, y)).unwrap();
                    let next_sym = next_cell.symbol();
                    if is_box_drawing(next_sym)
                        || next_cell.fg != cur_fg
                        || next_cell.bg != cur_bg
                        || next_cell.modifier != cur_mod
                    {
                        break;
                    }
                    text.push_str(next_sym);
                    x += 1;
                }

                let span_len = x - start_x;
                let span_w = span_len as f64 * cell_w;
                let span_cx = pad_x + start_x as f64 * cell_w;

                let is_bold = cur_mod.contains(Modifier::BOLD);
                let bold_attr = if is_bold {
                    r#" font-weight="bold""#
                } else {
                    ""
                };

                let escaped = text
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;");

                svg.push_str(&format!(
                    r#"  <text xml:space="preserve" x="{}" y="{}" font-family="MesloLGS Nerd Font" font-size="13px"{} fill="{}" textLength="{}" lengthAdjust="spacing">{}</text>
"#,
                    span_cx,
                    cy + 12.0,
                    bold_attr,
                    fg_to_string(cur_fg),
                    span_w,
                    escaped
                ));
            }
        }
    }

    svg.push_str("</svg>\n");
    svg
}

fn sample_devices() -> Vec<BlockDevice> {
    vec![
        BlockDevice {
            name: "nvme0n1".into(),
            path: "/dev/nvme0n1".into(),
            size_bytes: 512_110_190_592,
            model: Some("Example NVMe SSD 512GB".into()),
            serial: Some("EXN512A0001234".into()),
            bus_type: "NVME".into(),
            transport: Some("nvme".into()),
            is_rotational: Some(false),
            logical_sector_size: 512,
            physical_sector_size: 512,
            mountpoints: vec!["/".into(), "/boot".into()],
            safety: DeviceSafety::SystemDisk(vec!["/".into(), "/boot".into()]),
            maj_min: Some("259:0".into()),
            diskseq: Some(1),
            ..Default::default()
        },
        BlockDevice {
            name: "sdb".into(),
            path: "/dev/sdb".into(),
            size_bytes: 1_000_204_886_016,
            model: Some("Example SATA HDD 1TB".into()),
            vendor: Some("ACME".into()),
            serial: Some("WX41A8F2KD7Y".into()),
            wwn: Some("0x50014ee2b5a1c3d4".into()),
            bus_type: "USB".into(),
            transport: Some("usb".into()),
            hotplug: true,
            is_rotational: Some(true),
            is_read_only: true,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            maj_min: Some("8:16".into()),
            diskseq: Some(17),
            partitions: vec![
                Partition {
                    name: "sdb1".into(),
                    path: "/dev/sdb1".into(),
                    size_bytes: 104_857_600,
                    kind: Some("part".into()),
                    maj_min: Some("8:17".into()),
                    start_sector: Some(2048),
                    is_read_only: true,
                    ..Default::default()
                },
                Partition {
                    name: "sdb2".into(),
                    path: "/dev/sdb2".into(),
                    size_bytes: 1_000_098_000_896,
                    kind: Some("part".into()),
                    maj_min: Some("8:18".into()),
                    start_sector: Some(206_848),
                    is_read_only: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        BlockDevice {
            name: "sdc".into(),
            path: "/dev/sdc".into(),
            size_bytes: 32_010_928_128,
            model: Some("Example USB Stick".into()),
            serial: Some("0401A55F8C21".into()),
            bus_type: "USB".into(),
            transport: Some("usb".into()),
            hotplug: true,
            is_removable: true,
            logical_sector_size: 512,
            physical_sector_size: 512,
            maj_min: Some("8:32".into()),
            diskseq: Some(18),
            mountpoints: vec!["/media/stick".into()],
            safety: DeviceSafety::Mounted(vec!["/media/stick".into()]),
            ..Default::default()
        },
    ]
}

fn sample_case() -> CaseMetadata {
    CaseMetadata {
        case_number: "2026-0042".into(),
        evidence_number: "HDD01".into(),
        examiner: "J. Doe".into(),
        authority: "Example Forensic Unit".into(),
        description: "External USB hard disk".into(),
        seal_number: "S-1187".into(),
        ..Default::default()
    }
}

fn explorer_app() -> App {
    let mut app = App::with_devices(sample_devices());
    app.is_root = true;
    app.handle_key(key(crossterm::event::KeyCode::Down));
    app
}

fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}

fn case_setup_app() -> App {
    let mut app = explorer_app();
    app.handle_key(key(crossterm::event::KeyCode::Enter));
    app.case = sample_case();
    app.form.destination = "/mnt/evidence/2026-0042".into();
    app.field = Field::Notes;
    app.cursor = 0;
    app
}

fn identity(dev: &BlockDevice) -> SourceIdentity {
    let mut id = SourceIdentity::from_block_device(dev);
    id.kind = SourceKind::Disk;
    id.probe_notes.clear();
    id
}

/// The case drive of the examples.
fn sample_destination() -> DestinationFacts {
    DestinationFacts {
        output_dir: "/mnt/evidence/2026-0042".into(),
        existing_ancestor: "/mnt/evidence".into(),
        ancestor_is_dir: true,
        mount_point: Some("/mnt/evidence".into()),
        fs_type: Some("ext4".into()),
        mount_source: Some("/dev/sdc1".into()),
        read_only_mount: false,
        free_bytes: Some(1_712_000_000_000),
        backing_device: Some("8:33".into()),
    }
}

fn confirm_app() -> App {
    let mut app = case_setup_app();
    let dev = app.source.clone().unwrap().device;
    let config = app.form.config();
    let request = AcquisitionRequest::new(dev.clone(), app.case.clone(), config.clone());
    let id = identity(&dev);
    let check = CheckReport {
        ready: true,
        device: dev.path.clone(),
        engine: EngineKind::Ewf,
        output_dir: config.output_dir.clone(),
        base_name: app.base_name_preview(),
        identity: Some(id.clone()),
        tool_source_path: Some("/dev/disk/by-diskseq/17".into()),
        effective_config: Some(EffectiveConfig::build(&config, Some(&id))),
        write_protection: Some(WriteProtection {
            sysfs_ro_before: Some(true),
            exclusive_open: true,
            dfnix_registry: RegistryPresence::Absent,
            ..Default::default()
        }),
        write_protection_plan: Some("nothing to set: every node is already read-only".into()),
        destination: Some(sample_destination()),
        capacity: Some(CapacityInfo {
            reported_bytes: dev.size_bytes,
            probed_device: Some(dev.path.clone()),
            ata: Some(AtaCapacity {
                native_max_sectors: Some(dev.size_bytes / 512),
                current_max_sectors: Some(dev.size_bytes / 512),
                hpa_present: Some(false),
                dco_real_max_sectors: Some(dev.size_bytes / 512),
                dco_present: Some(false),
                sector_bytes: Some(512),
            }),
            nvme: None,
            method: "hdparm -N /dev/sdb; hdparm --dco-identify /dev/sdb".into(),
            errors: Vec::new(),
        }),
        smart: None,
        problems: Vec::new(),
        notes: Vec::new(),
    };
    app.confirm = Some(ConfirmState {
        subject: ConfirmSubject::Acquisition {
            request: Box::new(request),
            base_name: app.base_name_preview().unwrap_or_default(),
            check: Some(Box::new(check)),
            destination: Some(Ok(sample_destination())),
        },
        token: 1,
        pending: false,
        typed: "kd7".into(),
        cursor: 3,
        target: Some(ConfirmTarget::new(dev.serial.as_deref(), "HDD01")),
        error: None,
        scroll: 0,
    });
    app.screen = Screen::Confirm;
    app
}

fn running_app() -> App {
    let mut app = case_setup_app();
    let base = app.base_name_preview().unwrap_or_default();
    let t = ProgressTelemetry {
        status: AcquisitionStatus::Acquiring,
        total_bytes: 1_000_204_886_016,
        bytes_processed: 412_316_860_416,
        percentage: 41.2,
        speed_bps: 148.0 * 1024.0 * 1024.0,
        avg_speed_bps: 151.0 * 1024.0 * 1024.0,
        eta_secs: Some(6510),
        elapsed_secs: 2710,
        compression_ratio: Some(1.31),
        log_messages: vec![
            "ewfacquire: acquiry started".into(),
            "Status: at 41%.".into(),
        ],
        ..Default::default()
    };
    app.job = Some(Job::detached(
        JobKind::Acquisition,
        t,
        vec![
            ("Source".into(), "/dev/sdb (whole disk)".into()),
            ("Serial".into(), "WX41A8F2KD7Y (lsblk)".into()),
            (
                "Destination".into(),
                format!("/mnt/evidence/2026-0042/{base}.*"),
            ),
            ("Engine".into(), "E01 (ewfacquire)".into()),
        ],
        true,
    ));
    app.screen = Screen::Running;
    app
}

fn result_app() -> App {
    let mut app = case_setup_app();
    let dev = app.source.clone().unwrap().device;
    let config = app.form.config();
    let id = identity(&dev);
    let mut report = ForensicInfoReport::new(
        EngineKind::Ewf,
        &app.case,
        id.clone(),
        EffectiveConfig::build(&config, Some(&id)),
    );
    report.output_dir = "/mnt/evidence/2026-0042".into();
    report.base_name = app.base_name_preview().unwrap_or_default();
    report.image_files = vec![format!("/mnt/evidence/2026-0042/{}.E01", report.base_name)];
    report.acquisition_hashes = HashResults {
        md5: Some("0123456789abcdef0123456789abcdef".into()),
        ..Default::default()
    };
    report.image_hashes = report.acquisition_hashes.clone();
    let mut errors = ReadErrorTable::new(512, "ewfinfo -e");
    errors.push_sectors(2048, 64, RangeKind::Substituted);
    let mut facts = report.facts();
    facts.bytes_acquired = facts.expected_bytes;
    facts.read_errors = errors;
    facts.verification = VerificationResult::Matched {
        method: "ewfverify".into(),
    };
    report.audit = AuditInfo {
        anchor: Some("5d1f0c6e2b7a94e3c08f6a1d2e3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d".into()),
        status: AuditStatus::Written,
        export_file: Some("/mnt/evidence/2026-0042/audit-4f2a9c1e.jsonl".into()),
    };
    report.apply_facts(&facts);
    let text = report.render_text();
    app.result = Some(RunResult::Acquisition {
        report: Box::new(report),
        text,
    });
    app.result_acknowledged = false;
    app.screen = Screen::Result;
    app
}

fn render(app: &mut App, w: u16, h: u16) -> Result<String, Box<dyn std::error::Error>> {
    let mut terminal = Terminal::new(TestBackend::new(w, h))?;
    terminal.draw(|f| ui::render(f, app))?;
    Ok(buffer_to_svg(terminal.backend().buffer(), w, h))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let png = args.iter().any(|a| a == "--png");
    let out: PathBuf = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target/screenshots"));
    std::fs::create_dir_all(&out)?;

    let screens: Vec<(&str, App)> = vec![
        ("device_explorer", explorer_app()),
        ("case_setup", case_setup_app()),
        ("confirmation", confirm_app()),
        ("acquisition", running_app()),
        ("result", result_app()),
    ];
    for (name, mut app) in screens {
        let svg = render(&mut app, 120, 36)?;
        let svg_path = out.join(format!("{name}.svg"));
        std::fs::write(&svg_path, svg)?;
        println!("wrote {}", svg_path.display());
        if png {
            let png_path = out.join(format!("{name}.png"));
            // No metadata (dates, file names): the same screens give the same
            // files
            let status = std::process::Command::new("magick")
                .arg(&svg_path)
                .args(["-strip", "-define", "png:exclude-chunk=date,time"])
                .arg(&png_path)
                .status()?;
            if !status.success() {
                return Err(format!("magick failed for {}", svg_path.display()).into());
            }
            println!("wrote {}", png_path.display());
        }
    }
    Ok(())
}
