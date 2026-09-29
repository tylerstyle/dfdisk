use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use std::fs::File;
use std::io::Write;

use dfdisk::models::case::CaseMetadata;
use dfdisk::models::config::{AcquisitionConfig, CompressionLevel, ImageFormat, SplitSize};
use dfdisk::models::device::{BlockDevice, DeviceSafety};
use dfdisk::tui::app::{App, Screen};
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

    let total_w = 1143;
    let total_h = 672;

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

            let fg_hex = color_to_string(cell.fg);
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
                    r#"  <text x="{}" y="{}" font-family="MesloLGS Nerd Font" font-size="13px"{} fill="{}" textLength="{}" lengthAdjust="spacing">{}</text>
"#,
                    span_cx,
                    cy + 12.0,
                    bold_attr,
                    color_to_string(cur_fg),
                    span_w,
                    escaped
                ));
            }
        }
    }

    svg.push_str("</svg>\n");
    svg
}

fn build_case_setup_app() -> App {
    let mut app = App::new();
    app.current_screen = Screen::CaseSetup;
    app.case_metadata = CaseMetadata {
        case_number: "VG-2026/4192".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "SSD01".to_string(),
        authority: "Cybercrime & Digital Forensics Unit".to_string(),
        examiner: "Det. J. Doe (#4192)".to_string(),
        description: "Samsung 970 EVO NVMe M.2 1TB".to_string(),
        notes: "/mnt/evidence/cases".to_string(),
    };
    app.active_field = 6; // FormField::Notes
    app.cursor_pos = app.case_metadata.notes.len();

    app.target_dir_str = "/home/tylerstyle/git/dfdisk".to_string();
    app.config = AcquisitionConfig {
        output_dir: std::path::PathBuf::from("/home/tylerstyle/git/dfdisk"),
        format: ImageFormat::E01,
        split_size: SplitSize::TwoGb,
        compression: CompressionLevel::Fast,
        calc_md5: true,
        calc_sha1: true,
        calc_sha256: true,
        error_retries: 3,
        wipe_bad_sectors: false,
        rescue_mode: false,
        resume: false,
    };

    let dev = BlockDevice {
        name: "nvme0n1".to_string(),
        path: "/dev/nvme0n1".to_string(),
        devlinks: vec![],
        size_bytes: 1_000_204_886_016,
        model: Some("Samsung 970 EVO NVMe M.2 1TB".to_string()),
        vendor: None,
        serial: Some("CJ99N6560143Y902F".to_string()),
        wwn: None,
        revision: None,
        bus_type: "NVMe".to_string(),
        is_rotational: Some(false),
        is_removable: false,
        is_read_only: true,
        logical_sector_size: 512,
        physical_sector_size: 512,
        partition_table_type: None,
        partitions: vec![],
        mountpoints: vec![],
        safety: DeviceSafety::Safe,
        smart: None,
    };
    app.devices = vec![dev];
    app.selected_device_idx = 0;

    app
}

fn build_image_converter_app() -> App {
    let mut app = App::new();
    app.current_screen = Screen::Converter;
    app.conv_source_path = "/mnt/evidence/cases/suspect_disk.raw".to_string();
    app.conv_cursor_pos = app.conv_source_path.len();
    app.conv_active_field = 0; // ConverterField::SourcePath
    app.conv_to_e01 = true;
    app.conv_target_dir = "/home/tylerstyle/git/dfdisk".to_string();
    app.conv_status_msg = "Ready to convert images.".to_string();

    app
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Rendering Case Setup screen...");
    let mut case_app = build_case_setup_app();
    let backend = TestBackend::new(142, 42);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|f| {
        ui::render(f, &mut case_app);
    })?;
    let case_svg = buffer_to_svg(terminal.backend().buffer(), 142, 42);
    let mut f = File::create("/tmp/case_setup.svg")?;
    f.write_all(case_svg.as_bytes())?;

    println!("Rendering Image Converter screen...");
    let mut conv_app = build_image_converter_app();
    let backend = TestBackend::new(142, 42);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|f| {
        ui::render(f, &mut conv_app);
    })?;
    let conv_svg = buffer_to_svg(terminal.backend().buffer(), 142, 42);
    let mut f = File::create("/tmp/image_converter.svg")?;
    f.write_all(conv_svg.as_bytes())?;

    println!("Rasterizing to PNG via ImageMagick...");
    let status = std::process::Command::new("magick")
        .args(["/tmp/case_setup.svg", "assets/screenshots/case_setup.png"])
        .status()?;
    assert!(status.success());

    let status = std::process::Command::new("magick")
        .args([
            "/tmp/image_converter.svg",
            "assets/screenshots/image_converter.png",
        ])
        .status()?;
    assert!(status.success());

    println!("Screenshots successfully generated!");
    Ok(())
}
