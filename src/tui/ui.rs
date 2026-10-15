//! Drawing (§16). Every screen fits 80x24; anything smaller gets a
//! "terminal too small" screen (no panic at any size). The verdict of a run
//! is the first thing on the result screen, coloured by outcome; modals are
//! sized to their content; inputs scroll horizontally by display width.

use crate::engines::preflight::is_memory_fs;
use crate::models::config::{EffectiveConfig, EngineKind};
use crate::models::conversion::ConversionTarget;
use crate::models::outcome::Outcome;
use crate::models::telemetry::AcquisitionStatus;
use crate::models::text::{format_iec, sanitize_line};
use crate::tui::app::{
    App, ConfirmSubject, Input, JobKind, Level, Modal, Screen, Tone, MIN_HEIGHT, MIN_WIDTH,
};
use crate::tui::devices::{Badge, SourceRow};
use crate::tui::form::{case_text, engine_choice, image_extension, ConvField, Field, VerField};
use crate::tui::input::{str_width, truncate_to_width, visible_window, wrap_text};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Gauge, Paragraph, Row, Table},
    Frame,
};

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const LABEL_WIDTH: usize = 13;

fn spinner(app: &App) -> &'static str {
    SPINNER[(app.ticks / 2) as usize % SPINNER.len()]
}

pub fn tone_color(tone: Tone) -> Color {
    match tone {
        Tone::Good => Color::Green,
        Tone::Caution => Color::Yellow,
        Tone::Warning => Color::LightRed,
        Tone::Bad => Color::Red,
        Tone::Aborted => Color::Magenta,
    }
}

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn placeholder_style() -> Style {
    Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::ITALIC)
}

fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn block(title: impl Into<String>, color: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(title.into(), bold(color)))
}

/// Draw the whole screen.
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    app.notices_drawn.clear();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }
    let (notice_lines, drawn) = notice_lines(app, area.width as usize, area.height);
    app.notices_drawn = drawn;
    let [header, notices, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(notice_lines.len() as u16),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(frame, app, header);
    frame.render_widget(Paragraph::new(notice_lines), notices);
    match app.screen {
        Screen::Explorer => render_explorer(frame, app, body),
        Screen::CaseSetup => render_case_setup(frame, app, body),
        Screen::Confirm => render_confirm(frame, app, body),
        Screen::Running => render_running(frame, app, body),
        Screen::Result => render_result(frame, app, body),
        Screen::Converter => render_converter(frame, app, body),
        Screen::Verify => render_verify(frame, app, body),
    }
    render_completion(frame, app, body);
    render_footer(frame, app, footer);
    if app.modal.is_some() {
        render_modal(frame, app, area);
    }
}

/// The "terminal too small" screen; safe for every size including 0x0.
pub fn render_too_small(frame: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let text = format!(
        "Terminal too small ({}x{}). dfdisk needs at least {}x{}: enlarge the window. A running acquisition continues.",
        area.width, area.height, MIN_WIDTH, MIN_HEIGHT
    );
    let lines: Vec<Line> = wrap_text(&text, area.width as usize)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, bold(Color::Yellow))))
        .collect();
    let h = (lines.len() as u16).min(area.height);
    let y = area.y + (area.height - h) / 2;
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        Rect::new(area.x, y, area.width, h),
    );
}

fn screen_title(app: &App) -> &'static str {
    match app.screen {
        Screen::Explorer => "Sources",
        Screen::CaseSetup => "Case setup",
        Screen::Confirm => "Confirmation",
        Screen::Running => match app.job.as_ref().map(|j| j.kind) {
            Some(JobKind::Conversion) => "Conversion running",
            Some(JobKind::Verification) => "Verification running",
            _ => "Acquisition running",
        },
        Screen::Result => "Result",
        Screen::Converter => "Converter",
        Screen::Verify => "Re-verify an image",
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut badges: Vec<Span> = Vec::new();
    if let Some(label) = app.busy_label() {
        badges.push(Span::styled(
            format!(" {} {} ", spinner(app), label),
            Style::default().fg(Color::Cyan),
        ));
    }
    if app
        .result
        .as_ref()
        .is_some_and(|r| r.audit_problem().is_some())
    {
        badges.push(Span::styled(
            " AUDIT LOG NOT WRITTEN ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ));
        badges.push(Span::raw(" "));
    }
    if app.ssh_warning.is_some() {
        badges.push(Span::styled(
            " SSH: USE TMUX ",
            Style::default().fg(Color::Black).bg(Color::Yellow),
        ));
        badges.push(Span::raw(" "));
    }
    badges.push(if app.is_root {
        Span::styled(" ROOT ", Style::default().fg(Color::Black).bg(Color::Cyan))
    } else {
        Span::styled(
            " NOT ROOT ",
            Style::default().fg(Color::Black).bg(Color::Yellow),
        )
    });
    let right_w: usize = badges.iter().map(|s| s.width()).sum();
    let right_w = (right_w as u16).min(area.width);
    let [left, right] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(right_w)]).areas(area);
    let title = format!(
        " dfdisk {} │ {}",
        env!("CARGO_PKG_VERSION"),
        screen_title(app)
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            truncate_to_width(&title, left.width as usize),
            bold(Color::Cyan),
        )),
        left,
    );
    frame.render_widget(
        Paragraph::new(Line::from(badges)).alignment(Alignment::Right),
        right,
    );
}

/// Notification lines: errors first, then warnings, then information,
/// newest first, each wrapped in full ([`App::notice_page`]); a last line
/// counts the notices that did not fit, errors among them.
/// The notification area's lines and the ids of the notices in them.
fn notice_lines(app: &App, width: usize, height: u16) -> (Vec<Line<'static>>, Vec<u64>) {
    let page = app.notice_page(width, App::notice_lines_max(height));
    let drawn = page.shown.iter().map(|(n, _)| n.id).collect();
    let mut lines = Vec::new();
    for (n, text) in &page.shown {
        let color = match n.level {
            Level::Error => Color::Red,
            Level::Warning => Color::Yellow,
            Level::Info => Color::Cyan,
        };
        for l in text {
            lines.push(Line::from(Span::styled(
                truncate_to_width(l, width),
                bold(color),
            )));
        }
    }
    if page.hidden > 0 {
        let errors = match page.hidden_errors {
            0 => String::new(),
            1 => ", 1 of them an error".into(),
            e => format!(", {e} of them errors"),
        };
        lines.push(Line::from(Span::styled(
            truncate_to_width(
                &format!(
                    "  … {} more message(s){errors}; Ctrl+X dismisses the ones shown",
                    page.hidden
                ),
                width,
            ),
            if page.hidden_errors > 0 {
                bold(Color::Red)
            } else {
                Style::default().fg(Color::Yellow)
            },
        )));
    }
    (lines, drawn)
}

pub(crate) fn footer_hints(app: &App) -> String {
    let base = match app.screen {
        Screen::Explorer => {
            "↑↓ select · Enter acquire · U unmount · H hidden areas · R refresh · C convert · V verify · L last result · ? help · Q quit"
        }
        Screen::CaseSetup => {
            "Tab/Shift+Tab fields · ←→/Space change · F4 complete path · F5 review & start · Esc back · F1 help"
        }
        Screen::Confirm => {
            "Type the confirmation · Enter start · ↑↓ PgUp PgDn scroll · Esc back · F1 help"
        }
        Screen::Running => {
            "A abort (asks y/N) · Ctrl+C abort & quit (asks) · Esc does NOT abort · F1 help"
        }
        Screen::Result => match &app.result {
            Some(crate::tui::app::RunResult::Acquisition { report, .. })
                if report.engine == EngineKind::Rescue =>
            {
                "Enter/Esc acknowledge · ↑↓ PgUp PgDn scroll · V re-verify · C convert rescue to E01"
            }
            _ => "Enter/Esc acknowledge · ↑↓ PgUp PgDn scroll · V re-verify",
        },
        Screen::Converter => {
            "Tab/Shift+Tab fields · ←→/Space change · F4 complete path · F5 review & start · Esc back"
        }
        Screen::Verify => "Tab/Shift+Tab fields · F4 complete path · F5 start · Esc back · F1 help",
    };
    if app.notices.iter().any(|n| n.level != Level::Info) {
        format!("Ctrl+X dismiss shown messages · {base}")
    } else {
        base.to_string()
    }
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let hints = footer_hints(app);
    frame.render_widget(
        Paragraph::new(Span::styled(
            truncate_to_width(&format!(" {hints}"), area.width as usize),
            Style::default().fg(Color::Gray),
        )),
        area,
    );
}

// ---------------------------------------------------------------------------
// Explorer
// ---------------------------------------------------------------------------

fn badge_style(b: Badge) -> Style {
    let color = match b {
        Badge::System | Badge::Protected | Badge::HiddenArea | Badge::Dco => Color::Red,
        Badge::Mounted => Color::Yellow,
        Badge::ReadOnly => Color::Green,
        Badge::InUse => Color::Magenta,
    };
    bold(color)
}

fn badge_spans(row: &SourceRow) -> Line<'static> {
    badge_line(row, usize::MAX)
}

/// Badges in at most `width` cells: the short forms when the full labels do
/// not fit, so no badge is ever cut off.
fn badge_line(row: &SourceRow, width: usize) -> Line<'static> {
    let short = str_width(&row.badge_text()) > width;
    let mut spans = Vec::new();
    for (i, b) in row.badges.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(
            if short { b.short() } else { b.label() },
            badge_style(*b),
        ));
    }
    Line::from(spans)
}

/// Column widths of the device table: the serial number has priority over
/// the model, which takes what is left.
pub fn table_widths(rows: &[SourceRow], width: u16) -> [u16; 6] {
    let maxw =
        |f: &dyn Fn(&SourceRow) -> String| rows.iter().map(|r| str_width(&f(r))).max().unwrap_or(0);
    let avail = width.saturating_sub(2 + 2 + 5) as usize; // borders, highlight, spacing
    let dev = maxw(&|r| device_cell(r)).clamp(8, 18);
    let kind = 5;
    let size = 9;
    let serial = maxw(&|r| r.serial()).clamp(8, 24);
    let rest = avail.saturating_sub(dev + kind + size + serial);
    // Full badge labels when the model keeps 8 cells, else the short forms
    let full = maxw(&|r| r.badge_text()).max(6);
    let short = maxw(&|r| r.badge_short_text()).max(6);
    let badges = if rest >= full + 8 {
        full
    } else {
        short.min(rest)
    };
    let model = rest - badges;
    [
        dev as u16,
        kind as u16,
        size as u16,
        serial as u16,
        model as u16,
        badges as u16,
    ]
}

fn device_cell(row: &SourceRow) -> String {
    if row.is_partition() {
        format!("└ {}", row.device.path.trim_start_matches("/dev/"))
    } else {
        row.device.path.clone()
    }
}

fn render_explorer(frame: &mut Frame, app: &mut App, area: Rect) {
    let details_h = if area.height >= 20 {
        9
    } else {
        area.height / 2
    };
    let [table_area, details_area] =
        Layout::vertical([Constraint::Min(4), Constraint::Length(details_h)]).areas(area);

    let widths = table_widths(&app.rows, table_area.width);
    let header = Row::new(
        ["Device", "Kind", "Size", "Serial", "Model", "Badges"]
            .map(|h| Cell::from(Span::styled(h, bold(Color::Cyan)))),
    );
    let rows: Vec<Row> = app
        .rows
        .iter()
        .map(|r| {
            let size = format_iec(r.device.size_bytes);
            Row::new(vec![
                Cell::from(truncate_to_width(&device_cell(r), widths[0] as usize)),
                Cell::from(Span::styled(r.kind_label(), dim())),
                Cell::from(truncate_to_width(&size, widths[2] as usize)),
                Cell::from(Span::styled(
                    truncate_to_width(&r.serial(), widths[3] as usize),
                    Style::default().fg(Color::Yellow),
                )),
                Cell::from(truncate_to_width(&r.model(), widths[4] as usize)),
                Cell::from(badge_line(r, widths[5] as usize)),
            ])
        })
        .collect();
    let empty = app.rows.is_empty();
    let title = if app.scanning && empty {
        format!(" Sources {} scanning… ", spinner(app))
    } else {
        format!(" Sources ({}) ", app.rows.len())
    };
    let table = Table::new(rows, widths.map(Constraint::Length))
        .header(header)
        .column_spacing(1)
        .block(block(title, Color::Cyan))
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 50, 80))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, table_area, &mut app.table_state);
    if empty && !app.scanning {
        let inner = table_area.inner(ratatui::layout::Margin::new(2, 2));
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No block devices found. R rescans.",
                Style::default().fg(Color::Yellow),
            )),
            inner,
        );
    }
    render_details(frame, app, details_area);
}

fn kv(label: &str, value: impl Into<String>, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:<13}", label), dim()),
        Span::styled(sanitize_line(&value.into()), Style::default().fg(color)),
    ])
}

fn render_details(frame: &mut Frame, app: &App, area: Rect) {
    let Some(row) = app.current_row() else {
        frame.render_widget(block(" Details ", Color::DarkGray), area);
        return;
    };
    let d = &row.device;
    let mut lines = vec![
        kv(
            "Source",
            format!(
                "{} ({}){}",
                d.path,
                d.kind.label(),
                d.parent
                    .as_deref()
                    .map(|p| format!(", on {p}"))
                    .unwrap_or_default()
            ),
            Color::White,
        ),
        kv(
            "Model",
            format!("{}  ·  {}", row.model(), d.attachment_str()),
            Color::White,
        ),
        kv(
            "Serial / WWN",
            format!(
                "{}  ·  WWN {}",
                row.serial(),
                d.wwn.as_deref().unwrap_or("(none)")
            ),
            Color::Yellow,
        ),
        kv(
            "Size",
            format!(
                "{} bytes ({}) · sectors {}/{} B · {} · diskseq {}",
                d.size_bytes,
                format_iec(d.size_bytes),
                d.logical_sector_size,
                d.physical_sector_size,
                d.maj_min.as_deref().unwrap_or("maj:min ?"),
                d.diskseq
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into())
            ),
            Color::White,
        ),
    ];
    if !row.mountpoints.is_empty() {
        lines.push(kv("Mounted", row.mountpoints.join(", "), Color::Yellow));
    }
    if !d.holders.is_empty() {
        lines.push(kv("Holders", d.holders.join(", "), Color::Magenta));
    }
    if let Some(p) = &row.protected {
        lines.push(kv("PROTECTED", p.clone(), Color::Red));
    }
    let hidden = app
        .capacity_for(&row.disk)
        .map(|c| c.summary())
        .unwrap_or_else(|| {
            "not probed (H probes the disk: identify-class queries, nothing is changed)".into()
        });
    lines.push(kv("Hidden areas", hidden, Color::White));
    let inner_w = area.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = lines
        .into_iter()
        .map(|l| {
            let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
            if str_width(&text) > inner_w {
                let mut l = l;
                if let Some(last) = l.spans.last_mut() {
                    let keep = inner_w.saturating_sub(LABEL_WIDTH);
                    *last = Span::styled(truncate_to_width(&last.content, keep), last.style);
                }
                l
            } else {
                l
            }
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(block(" Details ", Color::DarkGray)),
        area,
    );
}

// ---------------------------------------------------------------------------
// Inputs and form rows
// ---------------------------------------------------------------------------

/// Spans of a text input `width` cells wide.
fn input_spans(
    text: &str,
    cursor: usize,
    width: usize,
    focused: bool,
    placeholder: &str,
    suggestion: Option<&str>,
) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    if width == 0 {
        return spans;
    }
    let hint = suggestion
        .map(|s| format!("suggested: {s} (→ accepts)"))
        .unwrap_or_else(|| placeholder.to_string());
    if focused {
        let (before, under, after) = visible_window(text, cursor, width);
        let cursor_style = Style::default().fg(Color::Black).bg(Color::Cyan);
        spans.push(Span::styled(before, bold(Color::White)));
        match under {
            Some(c) => spans.push(Span::styled(c.to_string(), cursor_style)),
            None => spans.push(Span::styled(" ", cursor_style)),
        }
        spans.push(Span::styled(after, bold(Color::White)));
        if text.is_empty() && !hint.is_empty() {
            spans.push(Span::styled(
                truncate_to_width(&hint, width.saturating_sub(1)),
                placeholder_style(),
            ));
        }
    } else if text.is_empty() {
        spans.push(Span::styled(
            truncate_to_width(&hint, width),
            placeholder_style(),
        ));
    } else {
        spans.push(Span::styled(
            truncate_to_width(text, width),
            Style::default().fg(Color::White),
        ));
    }
    spans
}

struct RowSpec<'a> {
    label: &'a str,
    focused: bool,
    required: bool,
    missing: bool,
    applies: bool,
}

fn row_prefix(spec: &RowSpec) -> Vec<Span<'static>> {
    let marker = if spec.focused { "▶ " } else { "  " };
    let label = format!(
        "{:<w$}",
        format!("{}{}", spec.label, if spec.required { "*" } else { "" }),
        w = LABEL_WIDTH
    );
    let style = if !spec.applies {
        dim()
    } else if spec.missing {
        bold(Color::Red)
    } else if spec.focused {
        bold(Color::Cyan)
    } else {
        Style::default().fg(Color::Gray)
    };
    vec![
        Span::styled(marker, bold(Color::Cyan)),
        Span::styled(label, style),
        Span::raw(" "),
    ]
}

fn text_row(
    spec: RowSpec,
    text: &str,
    cursor: usize,
    width: usize,
    placeholder: &str,
    suggestion: Option<&str>,
) -> Line<'static> {
    let input_w = width.saturating_sub(2 + LABEL_WIDTH + 1);
    let mut spans = row_prefix(&spec);
    spans.extend(input_spans(
        text,
        cursor,
        input_w,
        spec.focused,
        placeholder,
        suggestion,
    ));
    Line::from(spans)
}

fn choice_row(spec: RowSpec, value: &str, width: usize) -> Line<'static> {
    let input_w = width.saturating_sub(2 + LABEL_WIDTH + 1);
    let applies = spec.applies;
    let focused = spec.focused;
    let mut spans = row_prefix(&spec);
    let shown = if focused && applies {
        format!("‹ {value} ›")
    } else {
        value.to_string()
    };
    let style = if !applies {
        dim()
    } else if focused {
        Style::default().fg(Color::Black).bg(Color::Cyan)
    } else {
        Style::default().fg(Color::Yellow)
    };
    spans.push(Span::styled(truncate_to_width(&shown, input_w), style));
    Line::from(spans)
}

fn button(frame: &mut Frame, area: Rect, label: &str, focused: bool) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let text = if focused {
        format!("▶ {label} ◀")
    } else {
        label.to_string()
    };
    let style = if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            truncate_to_width(&format!(" {text} "), area.width as usize),
            style,
        ))
        .alignment(Alignment::Center),
        area,
    );
}

// ---------------------------------------------------------------------------
// Case setup
// ---------------------------------------------------------------------------

fn source_line(row: &SourceRow) -> Line<'static> {
    // Path, serial and size first: they identify the drive; the model last
    let mut spans = vec![
        Span::styled(" Source ", bold(Color::Cyan)),
        Span::styled(row.device.path.clone(), bold(Color::White)),
        Span::styled(" · S/N ", dim()),
        Span::styled(row.serial(), bold(Color::Yellow)),
        Span::styled(
            format!(
                " · {} · {} ",
                format_iec(row.device.size_bytes),
                row.kind_label()
            ),
            dim(),
        ),
    ];
    spans.extend(badge_spans(row).spans);
    spans.push(Span::raw(" "));
    spans.push(Span::raw(row.model()));
    Line::from(spans)
}

fn render_case_setup(frame: &mut Frame, app: &App, area: Rect) {
    let invalid_lines = app
        .source_invalid
        .as_ref()
        .map(|r| {
            wrap_text(
                &format!("SOURCE NO LONGER VALID: {r} (Esc: back to the list)"),
                area.width as usize,
            )
        })
        .unwrap_or_default();
    let src_h = 1 + invalid_lines.len().min(2) as u16;
    let button_h = if area.height >= 21 + src_h { 3 } else { 1 };
    let [src, cols, preview, btn] = Layout::vertical([
        Constraint::Length(src_h),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(button_h),
    ])
    .areas(area);

    let mut src_lines = vec![match &app.source {
        Some(row) => source_line(row),
        None => Line::from(Span::styled(" No source selected", bold(Color::Red))),
    }];
    for l in invalid_lines.into_iter().take(2) {
        src_lines.push(Line::from(Span::styled(l, bold(Color::Red))));
    }
    frame.render_widget(
        Paragraph::new(
            src_lines
                .into_iter()
                .map(|l| truncate_line(l, src.width as usize))
                .collect::<Vec<_>>(),
        ),
        src,
    );

    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(cols);
    let lw = left.width.saturating_sub(2) as usize;
    let rw = right.width.saturating_sub(2) as usize;

    let mut left_lines = Vec::new();
    for f in Field::CASE {
        let text = case_text(&app.case, f).cloned().unwrap_or_default();
        let focused = app.field == f;
        let missing = app.show_required && f.is_required() && text.trim().is_empty();
        let suggestion = app.suggestion(f);
        left_lines.push(text_row(
            RowSpec {
                label: f.label(),
                focused,
                required: f.is_required(),
                missing,
                applies: true,
            },
            &text,
            if focused { app.cursor } else { text.len() },
            lw,
            f.placeholder(),
            suggestion.as_deref(),
        ));
    }
    frame.render_widget(
        Paragraph::new(left_lines).block(block(" Case & evidence (* required) ", Color::Cyan)),
        left,
    );

    let engine = app.form.engine;
    let mut right_lines = vec![text_row(
        RowSpec {
            label: Field::Destination.label(),
            focused: app.field == Field::Destination,
            required: true,
            missing: app.show_required && app.form.destination.trim().is_empty(),
            applies: true,
        },
        &app.form.destination,
        if app.field == Field::Destination {
            app.cursor
        } else {
            app.form.destination.len()
        },
        rw,
        Field::Destination.placeholder(),
        None,
    )];
    right_lines.push(destination_info(app, rw));
    for f in Field::OPTIONS.into_iter().skip(1) {
        right_lines.push(choice_row(
            RowSpec {
                label: f.label(),
                focused: app.field == f,
                required: false,
                missing: false,
                applies: f.applies(engine),
            },
            &app.form.value_text(f),
            rw,
        ));
    }
    frame.render_widget(
        Paragraph::new(right_lines).block(block(" Acquisition ", Color::Cyan)),
        right,
    );

    let preview_text = match app.base_name_preview() {
        Some(base) => format!(
            " Files: {base}.{} · {base}.info · {base}.info.json",
            image_extension(engine)
        ),
        None => " Files: fill in case number, evidence number and examiner".to_string(),
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            truncate_to_width(&preview_text, preview.width as usize),
            Style::default().fg(Color::Green),
        )),
        preview,
    );
    let btn_area = if btn.height >= 3 {
        Rect::new(btn.x, btn.y + 1, btn.width, 1)
    } else {
        btn
    };
    button(
        frame,
        btn_area,
        "Review and confirm · F5",
        app.field == Field::Start,
    );
}

/// The destination line: filesystem, free space and warnings.
fn destination_info(app: &App, width: usize) -> Line<'static> {
    let prefix = "  ".to_string() + &" ".repeat(LABEL_WIDTH + 1);
    let (text, style) = match &app.destination_facts {
        _ if app.form.destination.trim().is_empty() => (
            "choose where the image and its report go".to_string(),
            placeholder_style(),
        ),
        None => ("checking…".to_string(), dim()),
        Some((dir, _)) if *dir != app.form.output_dir() => ("checking…".to_string(), dim()),
        Some((_, Err(e))) => (
            format!("cannot inspect: {e}"),
            Style::default().fg(Color::Red),
        ),
        Some((_, Ok(facts))) => {
            let fs = facts.fs_type.clone().unwrap_or_default();
            if is_memory_fs(&fs) {
                (
                    format!(
                        "{fs}: RAM-backed, refused as a destination (data is lost at power-off)"
                    ),
                    bold(Color::Red),
                )
            } else if facts.read_only_mount {
                ("mounted read-only: refused".to_string(), bold(Color::Red))
            } else {
                let mut s = facts.summary();
                let size = app
                    .source
                    .as_ref()
                    .map(|r| r.device.size_bytes)
                    .unwrap_or(0);
                let style = match facts.free_bytes {
                    Some(free) if size > 0 && free < size => {
                        s.push_str(&format!(" (source {})", format_iec(size)));
                        Style::default().fg(Color::Yellow)
                    }
                    _ => Style::default().fg(Color::Green),
                };
                (s, style)
            }
        }
    };
    Line::from(vec![
        Span::raw(prefix),
        Span::styled(
            truncate_to_width(&sanitize_line(&text), width.saturating_sub(LABEL_WIDTH + 3)),
            style,
        ),
    ])
}

fn truncate_line(line: Line<'static>, width: usize) -> Line<'static> {
    let mut used = 0;
    let mut spans = Vec::new();
    for s in line.spans {
        let w = s.width();
        if used + w <= width {
            used += w;
            spans.push(s);
        } else {
            let rest = width.saturating_sub(used);
            if rest > 0 {
                spans.push(Span::styled(truncate_to_width(&s.content, rest), s.style));
            }
            break;
        }
    }
    Line::from(spans)
}

// ---------------------------------------------------------------------------
// Confirmation sheet
// ---------------------------------------------------------------------------

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(title.to_string(), bold(Color::Cyan)))
}

/// Width of the label column of the confirmation sheets: the longest
/// label ("Authority / Agency", "Second Source Read") and two spaces.
const SHEET_LABEL_WIDTH: usize = 20;

fn sheet_row(label: &str, value: &str, style: Style) -> Line<'static> {
    // I-R3-1: at least one space between label and value, whatever the label
    let pad = SHEET_LABEL_WIDTH.max(str_width(label) + 1) - str_width(label);
    Line::from(vec![
        Span::styled(format!("  {label}{}", " ".repeat(pad)), dim()),
        Span::styled(sanitize_line(value), style),
    ])
}

/// The lines of the confirmation sheet (unwrapped).
pub fn sheet_lines(app: &App) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let Some(c) = &app.confirm else {
        return out;
    };
    let white = Style::default().fg(Color::White);
    let strong = bold(Color::Yellow);
    let conversion = matches!(c.subject, ConfirmSubject::Conversion { .. });
    // What was checked differs: the acquisition's dry run runs every check of
    // the session; the converter's sheet only looked at the source file (and
    // the destination's filesystem), the converter checks the rest at start
    let (pending, ready, not_ready) = if conversion {
        (
            "Looking at the source image and the destination…",
            "READY TO START: the source image exists. The converter checks the image, the destination and existing outputs when it starts. Nothing has been written yet.",
            "NOT READY: the source image was not found or is not a regular file. Nothing has been written or changed.".to_string(),
        )
    } else {
        (
            "Running the pre-flight checks (identity, safety, destination, hidden areas)…",
            "READY: every pre-flight check passed. Nothing has been written or changed yet.",
            // "Refused" only when a rule refused: a missing tool is named
            c.not_ready().map(|why| why.headline()).unwrap_or_default(),
        )
    };
    if c.pending {
        out.push(Line::from(Span::styled(
            format!("{} {pending}", spinner(app)),
            bold(Color::Cyan),
        )));
    } else if c.ready() {
        out.push(Line::from(Span::styled(ready, bold(Color::Green))));
    } else {
        out.push(Line::from(Span::styled(not_ready, bold(Color::Red))));
    }
    match &c.subject {
        ConfirmSubject::Acquisition {
            request,
            base_name,
            check,
            destination,
        } => {
            if let Some(check) = check {
                for p in &check.problems {
                    out.push(Line::from(Span::styled(
                        format!(
                            "  ✖ {} [{}]: {}",
                            p.kind.label(),
                            p.step,
                            sanitize_line(&p.message)
                        ),
                        bold(Color::Red),
                    )));
                }
            }
            if let Some((free, size)) = app.low_space_offer() {
                out.push(Line::from(Span::styled(
                    format!(
                        "  F6: proceed although only {} are free for a {} source (E01 compresses; the decision is recorded in the report)",
                        format_iec(free),
                        format_iec(size)
                    ),
                    bold(Color::Yellow),
                )));
            }
            if request.config.allow_low_space {
                out.push(Line::from(Span::styled(
                    "  Less free space than the source size accepted by the examiner (recorded).",
                    Style::default().fg(Color::Yellow),
                )));
            }
            out.push(Line::raw(""));
            out.push(section("SOURCE"));
            let id = check.as_ref().and_then(|c| c.identity.as_ref());
            match id {
                Some(id) => {
                    out.push(sheet_row(
                        "Path",
                        &format!("{} ({})", id.path, id.kind.label()),
                        bold(Color::White),
                    ));
                    if let Some(p) = check.as_ref().and_then(|c| c.tool_source_path.as_ref()) {
                        if p != &id.path {
                            out.push(sheet_row("Tools read", p, white));
                        }
                    }
                    if !id.parent_disks.is_empty() {
                        out.push(sheet_row("On disk", &id.parent_disks.join(", "), white));
                    }
                    out.push(sheet_row("Model", &id.display_name(), white));
                    out.push(sheet_row("Serial", &id.serial_with_provenance(), strong));
                    if let Some(n) = id.serial_note() {
                        out.push(sheet_row("", &n, Style::default().fg(Color::Yellow)));
                    }
                    out.push(sheet_row(
                        "WWN",
                        id.wwn.as_deref().unwrap_or("(none)"),
                        white,
                    ));
                    out.push(sheet_row(
                        "Size",
                        &format!(
                            "{} bytes ({}), {}-byte sectors",
                            id.size_bytes,
                            format_iec(id.size_bytes),
                            id.logical_sector_size
                        ),
                        strong,
                    ));
                }
                None => {
                    out.push(sheet_row("Path", &request.device.path, bold(Color::White)));
                    out.push(sheet_row("Model", &request.device.display_name(), white));
                    out.push(sheet_row(
                        "Serial",
                        request.device.serial.as_deref().unwrap_or("(none)"),
                        strong,
                    ));
                    out.push(sheet_row(
                        "Size",
                        &format!(
                            "{} bytes ({})",
                            request.device.size_bytes,
                            format_iec(request.device.size_bytes)
                        ),
                        strong,
                    ));
                }
            }
            if let Some(check) = check {
                let (hidden, style) = match &check.capacity {
                    Some(cap) => (
                        cap.summary(),
                        if cap.hidden_area() == Some(true) {
                            bold(Color::Red)
                        } else {
                            white
                        },
                    ),
                    None => ("not probed (another check failed first)".into(), dim()),
                };
                out.push(sheet_row("HPA / DCO", &hidden, style));
                if let Some(wp) = &check.write_protection {
                    out.push(sheet_row(
                        "Write prot.",
                        &format!("now: {}", wp.summary()),
                        white,
                    ));
                }
                if let Some(plan) = &check.write_protection_plan {
                    out.push(sheet_row("", &format!("plan: {plan}"), white));
                }
            }
            if !request.unmounted_by_dfdisk.is_empty() {
                out.push(sheet_row(
                    "Unmounted",
                    &format!(
                        "by dfdisk (audited): {}",
                        request.unmounted_by_dfdisk.join(", ")
                    ),
                    Style::default().fg(Color::Yellow),
                ));
            }
            out.push(Line::raw(""));
            out.push(section("DESTINATION"));
            out.push(sheet_row(
                "Directory",
                &request.config.output_dir.display().to_string(),
                bold(Color::White),
            ));
            match destination {
                Some(Ok(facts)) => out.push(sheet_row("Filesystem", &facts.summary(), white)),
                Some(Err(e)) => out.push(sheet_row(
                    "Filesystem",
                    &format!("cannot inspect: {e}"),
                    Style::default().fg(Color::Red),
                )),
                None => {}
            }
            out.push(sheet_row(
                "Files",
                &format!(
                    "{base_name}.{} · .info · .info.json",
                    image_extension(request.engine())
                ),
                white,
            ));
            out.push(Line::raw(""));
            out.push(section("ENGINE AND SETTINGS"));
            out.push(sheet_row("Engine", engine_choice(request.engine()), strong));
            // The settings of the run as it will start, for the source the
            // check identified. Not the check's own: its dry run sends no SMART
            // command, so its configuration says SMART off
            let effective = check
                .as_ref()
                .filter(|c| c.effective_config.is_some())
                .map(|c| EffectiveConfig::build(&request.config, c.identity.as_ref()));
            match effective {
                Some(eff) => {
                    // The engine is the row above
                    for (k, v) in eff.rows().into_iter().filter(|(k, _)| k != "Engine") {
                        out.push(sheet_row(&k, &v, white));
                    }
                }
                None => {
                    let digests: Vec<&str> =
                        crate::models::config::HashSelection::for_engine(&request.config)
                            .algorithms()
                            .iter()
                            .map(|a| a.label())
                            .collect();
                    out.push(sheet_row("Digests", &digests.join(", "), white));
                }
            }
            if request.engine() == EngineKind::Rescue && request.config.resume {
                out.push(sheet_row(
                    "Resume",
                    "continue the interrupted rescue from its map",
                    Style::default().fg(Color::Yellow),
                ));
            }
            out.push(Line::raw(""));
            out.push(section("CASE"));
            for (k, v) in request.case.report_rows() {
                out.push(sheet_row(k, &v, white));
            }
            if let Some(check) = check {
                if !check.notes.is_empty() {
                    out.push(Line::raw(""));
                    out.push(section("NOTES"));
                    for n in &check.notes {
                        out.push(sheet_row("", n, Style::default().fg(Color::Yellow)));
                    }
                }
            }
        }
        ConfirmSubject::Conversion {
            request,
            facts,
            destination,
            case,
        } => {
            out.push(Line::raw(""));
            out.push(section("SOURCE IMAGE"));
            out.push(sheet_row(
                "Path",
                &request.source.display().to_string(),
                bold(Color::White),
            ));
            if let Some(f) = facts {
                out.push(sheet_row(
                    "Size",
                    &match (f.exists, f.size) {
                        (true, Some(s)) => format!("{s} bytes ({})", format_iec(s)),
                        _ => "NOT FOUND or not a regular file".into(),
                    },
                    if f.exists { white } else { bold(Color::Red) },
                ));
                match &f.report {
                    Some(r) => {
                        out.push(sheet_row("Report", &r.path.display().to_string(), white));
                        out.push(sheet_row("Acquired", &r.device, strong));
                        out.push(sheet_row("Outcome", &r.outcome, white));
                    }
                    None => out.push(sheet_row(
                        "Report",
                        "none found next to the image that lists it",
                        Style::default().fg(Color::Yellow),
                    )),
                }
                // Reports next to the image the conversion does not use
                for n in &f.report_notes {
                    out.push(sheet_row("Note", n, Style::default().fg(Color::Yellow)));
                }
            }
            out.push(Line::raw(""));
            out.push(section("TARGET"));
            out.push(sheet_row(
                "Format",
                match request.target {
                    ConversionTarget::E01 => "E01 (Expert Witness)",
                    ConversionTarget::Raw => "RAW (single file)",
                },
                strong,
            ));
            out.push(sheet_row(
                "Directory",
                &request.output_dir.display().to_string(),
                bold(Color::White),
            ));
            match destination {
                Some(Ok(facts)) => out.push(sheet_row("Filesystem", &facts.summary(), white)),
                Some(Err(e)) => out.push(sheet_row(
                    "Filesystem",
                    &format!("cannot inspect: {e}"),
                    Style::default().fg(Color::Red),
                )),
                None => {}
            }
            if request.target == ConversionTarget::E01 {
                out.push(sheet_row(
                    "Compression",
                    &format!("{:?}", request.compression).to_lowercase(),
                    white,
                ));
                out.push(sheet_row(
                    "Segments",
                    &request.split_size.display_name(),
                    white,
                ));
            }
            out.push(Line::raw(""));
            // I-N1: what the conversion will record (E01 header < source
            // report < the form), each value with where it comes from
            out.push(section("CASE (as recorded)"));
            match case {
                Some(Ok(preview)) => {
                    for (k, v, origin) in preview.rows() {
                        let text = match origin {
                            Some(from) => format!("{v}  [{from}]"),
                            None => v,
                        };
                        out.push(sheet_row(k, &text, white));
                    }
                    for n in &preview.notes {
                        out.push(sheet_row("Note", n, Style::default().fg(Color::Yellow)));
                    }
                }
                Some(Err(e)) => {
                    out.push(sheet_row(
                        "Case",
                        &format!(
                            "the values the conversion records could not be determined ({e}); the form's values follow, the conversion may add values from the image's report or E01 header"
                        ),
                        Style::default().fg(Color::Yellow),
                    ));
                    if let Some(given) = &request.case {
                        for (k, v) in given.report_rows() {
                            out.push(sheet_row(k, &v, white));
                        }
                    }
                }
                None => out.push(sheet_row(
                    "Case",
                    "determining the values the conversion records...",
                    white,
                )),
            }
            for n in &request.notes {
                out.push(sheet_row("Note", n, Style::default().fg(Color::Yellow)));
            }
        }
    }
    out
}

/// Wrap styled lines to `width` (each line keeps the style of its last span).
fn wrap_lines(lines: Vec<Line<'static>>, width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for line in lines {
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        if str_width(&text) <= width {
            out.push(line);
            continue;
        }
        let style = line.spans.last().map(|s| s.style).unwrap_or_default();
        for (i, w) in wrap_text(&text, width).into_iter().enumerate() {
            if i == 0 {
                out.push(truncate_line(line.clone(), width));
            } else {
                out.push(Line::from(Span::styled(
                    format!("    {}", w.trim_start()),
                    style,
                )));
            }
        }
    }
    // The first wrapped piece of a line is its truncated original; the rest
    // repeats from the wrap so nothing is lost
    out
}

fn render_confirm(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(c) = &app.confirm else {
        return;
    };
    let [sheet, prompt, status] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(area);
    let kind = match c.subject {
        ConfirmSubject::Acquisition { .. } => "ACQUISITION",
        ConfirmSubject::Conversion { .. } => "CONVERSION",
    };
    let color = if c.pending {
        Color::Cyan
    } else if c.ready() {
        Color::Green
    } else {
        Color::Red
    };
    let inner_w = sheet.width.saturating_sub(2) as usize;
    let lines = wrap_lines(sheet_lines(app), inner_w);
    let visible = sheet.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    let scroll = c.scroll.min(max_scroll);
    let title = format!(
        " CONFIRM {kind}: check every value against the drive and the paperwork ({}/{}) ",
        (scroll + visible).min(lines.len()),
        lines.len()
    );
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(scroll).collect::<Vec<_>>())
            .block(block(truncate_to_width(&title, inner_w), color)),
        sheet,
    );

    let (prompt_title, enabled) = match &c.target {
        Some(t) if c.ready() => (t.prompt(), true),
        _ if c.pending => ("Waiting for the pre-flight checks".to_string(), false),
        _ => (
            "Start is not possible: see the problems above".to_string(),
            false,
        ),
    };
    let pw = prompt.width.saturating_sub(2) as usize;
    let input = if enabled {
        Line::from(input_spans(&c.typed, c.cursor, pw, true, "", None))
    } else {
        Line::from(Span::styled("—", dim()))
    };
    frame.render_widget(
        Paragraph::new(input).block(block(
            format!(
                " {} ",
                truncate_to_width(&prompt_title, pw.saturating_sub(2))
            ),
            if enabled {
                Color::Yellow
            } else {
                Color::DarkGray
            },
        )),
        prompt,
    );
    let status_text = match &c.error {
        Some(e) => Span::styled(
            truncate_to_width(e, status.width as usize),
            bold(Color::Red),
        ),
        None => Span::styled(
            truncate_to_width(
                "Enter starts when the confirmation matches · Esc goes back without starting",
                status.width as usize,
            ),
            dim(),
        ),
    };
    frame.render_widget(Paragraph::new(status_text), status);
    // Keep the offset inside the sheet so scrolling back responds at once
    if let Some(c) = app.confirm.as_mut() {
        c.scroll = scroll;
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

fn phase_index(status: &AcquisitionStatus) -> usize {
    match status {
        AcquisitionStatus::Idle | AcquisitionStatus::Preparing => 0,
        AcquisitionStatus::Acquiring => 1,
        AcquisitionStatus::Flushing => 2,
        AcquisitionStatus::Verifying => 3,
        AcquisitionStatus::SourceReread => 4,
        AcquisitionStatus::Finalizing => 5,
        _ => 6,
    }
}

fn render_running(frame: &mut Frame, app: &App, area: Rect) {
    let Some(job) = &app.job else {
        return;
    };
    let t = &job.telemetry;
    let summary_h = (job.summary.len() as u16 + 2).min(7);
    let [summary, stepper, g1, g2, metrics, log] = Layout::vertical([
        Constraint::Length(summary_h),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(area);

    let sw = summary.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = job
        .summary
        .iter()
        .map(|(k, v)| truncate_line(kv(k, v.clone(), Color::White), sw))
        .collect();
    let title = match job.kind {
        JobKind::Acquisition => " Acquiring ",
        JobKind::Conversion => " Converting ",
        JobKind::Verification => " Re-verifying ",
    };
    frame.render_widget(
        Paragraph::new(lines).block(block(title, Color::Cyan)),
        summary,
    );

    // Phase stepper
    let current = phase_index(&t.status);
    let mut phases: Vec<(&str, usize)> = match job.kind {
        JobKind::Acquisition => vec![
            ("prepare", 0),
            ("acquire", 1),
            ("flush", 2),
            ("verify image", 3),
            ("re-read source", 4),
            ("report", 5),
        ],
        JobKind::Conversion => vec![("prepare", 0), ("convert", 1), ("verify", 3), ("report", 5)],
        JobKind::Verification => vec![("verify image", 3)],
    };
    if !job.verify_source {
        phases.retain(|(_, i)| *i != 4);
    }
    let mut spans = vec![Span::raw(" ")];
    for (n, (name, idx)) in phases.iter().enumerate() {
        if n > 0 {
            spans.push(Span::styled(" › ", dim()));
        }
        let style = if *idx == current {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if *idx < current {
            Style::default().fg(Color::Green)
        } else {
            dim()
        };
        spans.push(Span::styled(format!(" {name} "), style));
    }
    if job.abort_requested {
        spans.push(Span::styled(
            if job.force_requested {
                "  FORCED STOP REQUESTED"
            } else {
                "  ABORT REQUESTED"
            },
            bold(Color::Magenta),
        ));
    }
    frame.render_widget(
        Paragraph::new(truncate_line(Line::from(spans), stepper.width as usize)),
        stepper,
    );

    // Acquisition gauge
    let acq_label = match t.status {
        AcquisitionStatus::Preparing | AcquisitionStatus::Idle => {
            format!(
                "{} waiting: checks, audit record, write protection, SMART",
                spinner(app)
            )
        }
        _ if t.total_bytes > 0 => format!(
            "{:.1}% · {} of {}",
            t.percentage.clamp(0.0, 100.0),
            format_iec(t.bytes_processed),
            format_iec(t.total_bytes)
        ),
        _ => format!(
            "{} processed (total size unknown)",
            format_iec(t.bytes_processed)
        ),
    };
    let acq_ratio = if t.total_bytes > 0 || t.percentage > 0.0 {
        (t.percentage / 100.0).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let acq_title = match job.kind {
        JobKind::Verification => " Image re-read ",
        JobKind::Conversion => " Conversion ",
        JobKind::Acquisition => " Acquisition (source → image) ",
    };
    if job.kind == JobKind::Verification {
        render_verify_gauge(frame, app, g1, " Image re-read ");
        frame.render_widget(block(" ", Color::DarkGray), g2);
    } else {
        frame.render_widget(
            Gauge::default()
                .block(block(acq_title, Color::Cyan))
                .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 30, 40)))
                .ratio(acq_ratio)
                .label(truncate_to_width(
                    &acq_label,
                    g1.width.saturating_sub(4) as usize,
                )),
            g1,
        );
        let title = if t.status == AcquisitionStatus::SourceReread {
            " Second source read "
        } else {
            " Verification (image re-read) "
        };
        render_verify_gauge(frame, app, g2, title);
    }

    let metrics_text = format!(
        " Speed {} (avg {}) · Elapsed {} · ETA {} · Read errors reported so far: {}{}",
        t.human_speed(),
        t.human_avg_speed(),
        t.human_elapsed(),
        t.human_eta(),
        t.bad_sectors,
        t.compression_ratio
            .map(|r| format!(" · compression {r:.2}x"))
            .unwrap_or_default()
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            truncate_to_width(&metrics_text, metrics.width as usize),
            Style::default().fg(Color::Gray),
        )),
        metrics,
    );

    let lw = log.width.saturating_sub(2) as usize;
    let visible = log.height.saturating_sub(2) as usize;
    let log_lines: Vec<Line> = t
        .log_messages
        .iter()
        .rev()
        .take(visible)
        .rev()
        .map(|m| {
            let style = if m.starts_with("WARNING") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(
                truncate_to_width(&sanitize_line(m), lw),
                style,
            ))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(log_lines).block(block(
            format!(" Log · {} ", t.status.display_str()),
            Color::DarkGray,
        )),
        log,
    );
}

fn render_verify_gauge(frame: &mut Frame, app: &App, area: Rect, title: &str) {
    let Some(job) = &app.job else {
        return;
    };
    let t = &job.telemetry;
    let active = matches!(
        t.status,
        AcquisitionStatus::Verifying | AcquisitionStatus::SourceReread
    );
    let done = phase_index(&t.status) > 4 && job.kind != JobKind::Verification;
    let (ratio, label) = match (&t.verify_progress, active) {
        (Some(p), true) => (
            (p.percentage / 100.0).clamp(0.0, 1.0),
            if p.total_bytes > 0 {
                format!(
                    "{:.1}% · {} of {}",
                    p.percentage.clamp(0.0, 100.0),
                    format_iec(p.bytes_done),
                    format_iec(p.total_bytes)
                )
            } else {
                format!("{} read", format_iec(p.bytes_done))
            },
        ),
        (None, true) => (
            0.0,
            format!("{} running (the tool reports no progress)", spinner(app)),
        ),
        _ if done => (1.0, "finished".to_string()),
        _ => (0.0, "not started".to_string()),
    };
    frame.render_widget(
        Gauge::default()
            .block(block(
                title.to_string(),
                if active { Color::Cyan } else { Color::DarkGray },
            ))
            .gauge_style(Style::default().fg(Color::Green).bg(Color::Rgb(30, 30, 40)))
            .ratio(ratio)
            .label(truncate_to_width(
                &label,
                area.width.saturating_sub(4) as usize,
            )),
        area,
    );
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

fn tail_to_width(s: &str, width: usize) -> String {
    if str_width(s) <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<char> = Vec::new();
    let mut used = 1;
    for c in chars.iter().rev() {
        let w = crate::tui::input::char_width(*c);
        if used + w > width {
            break;
        }
        used += w;
        out.push(*c);
    }
    out.reverse();
    format!("…{}", out.into_iter().collect::<String>())
}

fn render_result(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(r) = &app.result else {
        return;
    };
    let color = tone_color(r.tone());
    let inner_w = area.width.saturating_sub(2) as usize;
    let mut banner: Vec<Line> = vec![Line::from(Span::styled(
        truncate_to_width(&format!(" ■ {} ", r.title()), inner_w),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    ))];
    for l in r.lines() {
        for w in wrap_text(&l, inner_w) {
            banner.push(Line::from(Span::styled(w, Style::default().fg(color))));
        }
    }
    let files = r.files();
    let max_banner = (area.height / 2).max(4);
    let banner_h = (banner.len() as u16 + 2).min(max_banner);
    let files_h = if files.is_empty() {
        0
    } else {
        (files.len() as u16 + 2).min(5)
    };
    let [b, f, rep] = Layout::vertical([
        Constraint::Length(banner_h),
        Constraint::Length(files_h),
        Constraint::Min(0),
    ])
    .areas(area);
    let what = match r.kind() {
        JobKind::Acquisition => " ACQUISITION RESULT ",
        JobKind::Conversion => " CONVERSION RESULT ",
        JobKind::Verification => " VERIFICATION RESULT ",
    };
    frame.render_widget(
        Paragraph::new(banner).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(Style::default().fg(color))
                .title(Span::styled(what, bold(color))),
        ),
        b,
    );
    if files_h > 0 {
        let fw = f.width.saturating_sub(2) as usize;
        let lines: Vec<Line> = files
            .iter()
            .map(|(label, path)| {
                Line::from(vec![
                    Span::styled(format!("{:<13}", label), dim()),
                    Span::styled(
                        tail_to_width(path, fw.saturating_sub(13)),
                        Style::default().fg(Color::White),
                    ),
                ])
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines)
                .block(block(format!(" Files ({}) ", files.len()), Color::DarkGray)),
            f,
        );
    }
    let rw = rep.width.saturating_sub(2) as usize;
    let lines: Vec<String> = r
        .text()
        .split('\n')
        .flat_map(|l| {
            // Rules ("====") are cut to the width instead of wrapped
            let rule = l.len() > 3 && l.chars().all(|c| c == '=' || c == '-');
            if rule {
                vec![l.chars().take(rw).collect()]
            } else {
                wrap_text(l, rw)
            }
        })
        .collect();
    let visible = rep.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    let scroll = app.result_scroll.min(max_scroll);
    let title = format!(
        " Full report · lines {}-{} of {} · ↑↓ PgUp PgDn ",
        if lines.is_empty() { 0 } else { scroll + 1 },
        (scroll + visible).min(lines.len()),
        lines.len()
    );
    let text: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(visible)
        .map(|l| Line::from(Span::styled(l, Style::default().fg(Color::Gray))))
        .collect();
    frame.render_widget(
        Paragraph::new(text).block(block(truncate_to_width(&title, rw), Color::DarkGray)),
        rep,
    );
    app.result_scroll = scroll;
}

/// Colour of an outcome (for the screenshots and tests).
pub fn outcome_color(outcome: Outcome) -> Color {
    tone_color(crate::tui::app::outcome_tone(outcome))
}

// ---------------------------------------------------------------------------
// Converter and re-verification
// ---------------------------------------------------------------------------

fn render_converter(frame: &mut Frame, app: &App, area: Rect) {
    let [form, info, btn] = Layout::vertical([
        Constraint::Length(ConvField::ALL.len() as u16 + 1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);
    let w = form.width.saturating_sub(2) as usize;
    let mut lines = Vec::new();
    for f in ConvField::ALL {
        if f == ConvField::Start {
            continue;
        }
        let focused = app.conv.field == f;
        let applies = f.applies(app.conv.target);
        let spec = RowSpec {
            label: f.label(),
            focused,
            required: f.is_required(),
            missing: false,
            applies,
        };
        if f.is_text() {
            let text = app.conv.text(f).cloned().unwrap_or_default();
            lines.push(text_row(
                spec,
                &text,
                if focused { app.conv.cursor } else { text.len() },
                w,
                f.placeholder(),
                None,
            ));
        } else {
            let value = if applies {
                app.conv.value_text(f)
            } else {
                "n/a (E01 target only)".into()
            };
            lines.push(choice_row(spec, &value, w));
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(block(" Convert an image (RAW ⇄ E01) ", Color::Cyan)),
        form,
    );
    let mut info_lines = Vec::new();
    match &app.conv.facts {
        Some(f) if f.exists => {
            info_lines.push(kv(
                "Source",
                format!(
                    "{} bytes ({})",
                    f.size.unwrap_or(0),
                    format_iec(f.size.unwrap_or(0))
                ),
                Color::Green,
            ));
            match &f.report {
                Some(r) => {
                    info_lines.push(kv("Report", r.path.display().to_string(), Color::White));
                    info_lines.push(kv("Acquired", r.device.clone(), Color::Yellow));
                }
                None => info_lines.push(kv(
                    "Report",
                    "none found next to the image: enter the case fields",
                    Color::Yellow,
                )),
            }
        }
        Some(_) => info_lines.push(kv("Source", "not found or not a regular file", Color::Red)),
        None if app.conv.source.trim().is_empty() => {}
        None => info_lines.push(kv("Source", "checking…", Color::DarkGray)),
    }
    for n in &app.conv.notes {
        info_lines.push(kv("Note", n.clone(), Color::Yellow));
    }
    info_lines.push(Line::from(Span::styled(
        "The converter refuses existing outputs, verifies the result against the source digests and writes its own .info/.info.json report.",
        dim(),
    )));
    let iw = info.width as usize;
    frame.render_widget(Paragraph::new(wrap_lines(info_lines, iw.max(1))), info);
    button(
        frame,
        btn,
        "Review and confirm · F5",
        app.conv.field == ConvField::Start,
    );
}

fn render_verify(frame: &mut Frame, app: &App, area: Rect) {
    let [form, info, btn] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);
    let w = form.width.saturating_sub(2) as usize;
    let mut lines = Vec::new();
    for f in [VerField::Image, VerField::Report] {
        let focused = app.verify.field() == f;
        let text = app.verify.text(f).cloned().unwrap_or_default();
        lines.push(text_row(
            RowSpec {
                label: f.label(),
                focused,
                required: f == VerField::Image,
                missing: false,
                applies: true,
            },
            &text,
            if focused {
                app.verify.cursor
            } else {
                text.len()
            },
            w,
            f.placeholder(),
            None,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block(" Re-verify an image ", Color::Cyan)),
        form,
    );
    let mut text = vec![
        "The image is re-read (EWF through ewfverify, anything else hashed by dfdisk) and compared with the digests of the report.".to_string(),
        "The result is written as an addendum <base>.verify-<UTC>.txt next to the image and as an audit record; the image is never changed.".to_string(),
    ];
    if app.verify.report_auto {
        text.push("The report was found next to the image.".into());
    }
    if app.verify.report.trim().is_empty() {
        text.push("Without a report the digests are only computed: nothing is compared, so nothing is verified.".into());
    }
    let iw = info.width as usize;
    let lines: Vec<Line> = text
        .iter()
        .flat_map(|t| wrap_text(t, iw.max(1)))
        .map(|l| Line::from(Span::styled(l, dim())))
        .collect();
    frame.render_widget(Paragraph::new(lines), info);
    button(
        frame,
        btn,
        "Start verification · F5",
        app.verify.field() == VerField::Start,
    );
}

// ---------------------------------------------------------------------------
// Completion list and modals
// ---------------------------------------------------------------------------

fn render_completion(frame: &mut Frame, app: &App, body: Rect) {
    let Some(c) = &app.completion else {
        return;
    };
    let same_screen = matches!(
        (c.input, app.screen),
        (Input::Case(_), Screen::CaseSetup)
            | (Input::Conv(_), Screen::Converter)
            | (Input::Verify(_), Screen::Verify)
    );
    if !same_screen {
        return;
    }
    let mut lines: Vec<Line> = Vec::new();
    if c.pending {
        lines.push(Line::from(Span::styled(
            format!("{} listing…", spinner(app)),
            dim(),
        )));
    } else {
        let max = 8usize;
        let start = c.index.unwrap_or(0).saturating_sub(max - 1);
        for (i, cand) in c.candidates.iter().enumerate().skip(start).take(max) {
            let style = if Some(i) == c.index {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(Span::styled(
                tail_to_width(cand, body.width.saturating_sub(6) as usize),
                style,
            )));
        }
        if c.candidates.len() > max {
            lines.push(Line::from(Span::styled(
                format!("… {} candidates", c.candidates.len()),
                dim(),
            )));
        }
    }
    let h = (lines.len() as u16 + 2).min(body.height);
    let w = body.width.saturating_sub(4);
    if h < 3 || w < 10 {
        return;
    }
    let area = Rect::new(body.x + 2, body.y + body.height - h, w, h);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(block(
            " Paths · F4 next · any other key keeps the text ",
            Color::Yellow,
        )),
        area,
    );
}

/// A rectangle for `lines` of content centred in `area` (content-sized,
/// never larger than the area).
pub fn modal_rect(area: Rect, content_w: usize, content_h: usize) -> Rect {
    let w = (content_w as u16 + 4).min(area.width);
    let h = (content_h as u16 + 2).min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn help_lines(app: &App) -> Vec<String> {
    let mut l = vec![
        "Everywhere: F1 help · Esc back · Ctrl+C quit (asks while a run or an unmount is busy) · Ctrl+X dismiss the messages shown (the next ones move up)".to_string(),
        "Text fields: ←→ Home End move · Backspace Delete · Ctrl+U clear · Ctrl+W delete word".to_string(),
        "Forms: Tab / Shift+Tab next / previous field · Space ←→ change a choice · F4 path completion".to_string(),
        String::new(),
    ];
    let screen: &[&str] = match app.screen {
        Screen::Explorer => &[
            "Sources: every disk and partition can be selected; the selection follows the device's identity across refreshes.",
            "Enter/A acquire · U unmount (audited, asks) · H probe hidden areas (HPA/DCO) · R refresh",
            "C converter · V re-verify an image · L last result · Q quit",
            "Badges: SYSTEM / PROTECTED / MOUNTED are refused; RO read-only; IN-USE has holders; HPA / DCO hidden area found.",
        ],
        Screen::CaseSetup => &[
            "Case number, evidence number, examiner and destination are required; grey text is an example, never a value.",
            "→ or End in an empty case/evidence field accepts the suggestion from your last acquisition.",
            "Options that do not apply to the engine are greyed and skipped; E01 always computes MD5.",
            "F5 opens the confirmation sheet (dry run of every check; nothing is written yet).",
        ],
        Screen::Confirm => &[
            "The sheet shows what the checks found. Compare the serial with the drive label.",
            "Type the requested characters (last 4 of the serial, or the evidence number) and press Enter to start.",
            "F6 appears only when an E01 destination has less free space than the source size.",
        ],
        Screen::Running => &[
            "A asks before aborting; an abort stops the tool gracefully and still writes an ABORTED report.",
            "After an abort, A or Ctrl+C asks whether to kill external tools at once.",
            "Esc never aborts. If the terminal is lost (SIGHUP) the run continues and writes its report.",
        ],
        Screen::Result => &[
            "The verdict comes first; the full report scrolls below. The result stays until you acknowledge it.",
            "V re-verifies the image (addendum + audit record); C converts a rescue image to E01.",
        ],
        Screen::Converter => &[
            "RAW (.raw/.dd/.img/.001) converts to E01, EWF (.E01...) to RAW.",
            "Empty case, evidence, examiner and description fields are filled from the source's .info.json when one is found next to it; its other case values are taken over by the converter.",
            "F5 opens the confirmation sheet.",
        ],
        Screen::Verify => &[
            "Give the image and (optionally) its .info.json with the expected digests.",
            "Without expected digests nothing is compared: the result says so.",
        ],
    };
    l.extend(screen.iter().map(|s| s.to_string()));
    l.push(String::new());
    l.push("Any key closes this help.".into());
    l
}

fn render_modal(frame: &mut Frame, app: &App, area: Rect) {
    let Some(modal) = &app.modal else {
        return;
    };
    let max_w = (area.width as usize).saturating_sub(8).max(20);
    let (title, color, text): (String, Color, Vec<String>) = match modal {
        Modal::Help => (" Help ".into(), Color::Cyan, help_lines(app)),
        Modal::Unmount {
            device, mounts, ..
        } => (
            " Unmount the source? ".into(),
            Color::Yellow,
            vec![
                format!("{} has mounted filesystems:", device.path),
                format!("  {}", mounts.join(", ")),
                String::new(),
                "dfdisk unmounts every filesystem of this source tree, deepest first, never lazy or forced,".into(),
                "verifies that nothing stays mounted and writes an audit record.".into(),
                "Open LUKS/LVM/md holders are reported, not closed.".into(),
                String::new(),
                "Unmount now? [y/N]".into(),
            ],
        ),
        Modal::Abort => (
            " Abort? ".into(),
            Color::Magenta,
            vec![
                "Abort the running job?".into(),
                "The tool is stopped gracefully; the partial output is kept and an ABORTED report".into(),
                "and audit record are still written.".into(),
                String::new(),
                "Abort now? [y/N]".into(),
            ],
        ),
        Modal::Force => (
            " Stop immediately? ".into(),
            Color::Red,
            vec![
                "An abort is in progress. Kill the external tools at once?".into(),
                "The report is still written; a tool killed hard may not finalise its own files.".into(),
                String::new(),
                "Kill now? [y/N]".into(),
            ],
        ),
        Modal::Quit if app.job.is_none() => (
            " Quit? ".into(),
            Color::Magenta,
            vec![
                format!(
                    "An audited unmount of {} is running.",
                    app.unmounting.as_deref().unwrap_or("the source")
                ),
                "It is not interrupted: dfdisk quits once it has finished, checked that nothing".into(),
                "stayed mounted and written its audit record.".into(),
                String::new(),
                "Quit then? [y/N]".into(),
            ],
        ),
        Modal::Quit => (
            " Quit? ".into(),
            Color::Magenta,
            vec![
                "A job is running.".into(),
                "Abort it gracefully and quit once its report is written?".into(),
                String::new(),
                "Abort and quit? [y/N]".into(),
            ],
        ),
        Modal::Resume { map } => (
            " Resume the rescue? ".into(),
            Color::Yellow,
            vec![
                "A ddrescue map of this base name exists:".into(),
                format!("  {}", map.display()),
                String::new(),
                "Resume continues that rescue (same device required, checked) and keeps the earlier report.".into(),
                "Resume? [y/N]  (N: go back and choose another evidence number or destination)".into(),
            ],
        ),
    };
    let lines: Vec<String> = text
        .iter()
        .flat_map(|t| {
            if t.is_empty() {
                vec![String::new()]
            } else {
                wrap_text(&sanitize_line(t), max_w)
            }
        })
        .collect();
    let content_w = lines
        .iter()
        .map(|l| str_width(l))
        .max()
        .unwrap_or(0)
        .max(str_width(&title));
    let rect = modal_rect(area, content_w, lines.len());
    frame.render_widget(Clear, rect);
    let para: Vec<Line> = lines
        .into_iter()
        .map(|l| Line::from(Span::styled(l, Style::default().fg(Color::White))))
        .collect();
    frame.render_widget(
        Paragraph::new(para).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(color))
                .title(Span::styled(title, bold(color))),
        ),
        rect,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_file_name() {
        assert_eq!(tail_to_width("/a/b/file.E01", 8), "…ile.E01");
        assert_eq!(tail_to_width("short", 8), "short");
        assert_eq!(str_width(&tail_to_width("/x/ケース/データ", 7)), 7);
    }

    #[test]
    fn result_offers_the_conversion_only_for_a_rescue() {
        use crate::models::case::CaseMetadata;
        use crate::models::config::{AcquisitionConfig, EffectiveConfig};
        use crate::models::identity::SourceIdentity;
        use crate::models::info_report::ForensicInfoReport;
        use crate::tui::app::RunResult;
        let mut app = App::with_devices(Vec::new());
        app.screen = Screen::Result;
        for (engine, offered) in [(EngineKind::Rescue, true), (EngineKind::Ewf, false)] {
            let config = AcquisitionConfig::for_engine(engine, "/cases/x");
            let report = ForensicInfoReport::new(
                engine,
                &CaseMetadata::default(),
                SourceIdentity::default(),
                EffectiveConfig::build(&config, None),
            );
            app.result = Some(RunResult::Acquisition {
                report: Box::new(report),
                text: String::new(),
            });
            assert_eq!(
                footer_hints(&app).contains("convert rescue to E01"),
                offered,
                "{engine:?}"
            );
        }
    }

    #[test]
    fn modal_rect_fits_the_area() {
        let area = Rect::new(0, 0, 80, 24);
        let r = modal_rect(area, 200, 100);
        assert!(r.width <= 80 && r.height <= 24);
        let r = modal_rect(area, 10, 3);
        assert_eq!((r.width, r.height), (14, 5));
    }
}
