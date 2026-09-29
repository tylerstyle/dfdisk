use crate::models::device::DeviceSafety;
use crate::tui::app::{App, Screen};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Gauge, List, ListItem, Paragraph, Row, Table},
    Frame,
};

pub fn render(frame: &mut Frame, app: &mut App) {
    let size = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    render_header(frame, app, chunks[0]);

    match app.current_screen {
        Screen::DeviceExplorer | Screen::UnmountPrompt | Screen::SystemDiskWarning => {
            render_device_explorer(frame, app, chunks[1]);
            if app.current_screen == Screen::UnmountPrompt {
                render_unmount_modal(frame, app, size);
            } else if app.current_screen == Screen::SystemDiskWarning {
                render_system_warning_modal(frame, app, size);
            }
        }
        Screen::CaseSetup => render_case_setup(frame, app, chunks[1]),
        Screen::AcquisitionRunning => render_acquisition(frame, app, chunks[1]),
        Screen::ReportSummary => render_report_summary(frame, app, chunks[1]),
        Screen::Converter => render_converter(frame, app, chunks[1]),
    }

    render_footer(frame, app, chunks[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let is_root = nix_is_root();
    let root_badge = if is_root {
        Span::styled(
            " [● ROOT PRIVILEGES] ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " [⚠ NON-ROOT USER - RUN WITH SUDO] ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };

    let title_spans = vec![
        Span::styled(
            " dfdisk ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("v{} ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "│ FORENSIC DISK IMAGER & CONVERTER ",
            Style::default().fg(Color::White),
        ),
        root_badge.clone(),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let info_opt: Option<(String, bool)> = if let Some((text, is_err)) = &app.notification_msg {
        Some((text.clone(), *is_err))
    } else if app.current_screen == Screen::AcquisitionRunning {
        if app.abort_flag.load(std::sync::atomic::Ordering::Relaxed) {
            Some(("Aborting acquisition...".to_string(), true))
        } else if !app.telemetry.status_message.is_empty() {
            Some((app.telemetry.status_message.clone(), false))
        } else {
            None
        }
    } else {
        None
    };

    if let Some((text, is_err)) = info_opt {
        let (icon, color) = if is_err {
            ("⚠ ", Color::Red)
        } else {
            ("ℹ ", Color::Cyan)
        };
        let info_span = Span::styled(
            format!("{}{}", icon, text),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        );
        let info_width = (text.chars().count().saturating_add(3)).min(u16::MAX as usize) as u16;

        let left_spans = if inner.width.saturating_sub(72) < info_width {
            vec![
                Span::styled(
                    " dfdisk ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("v{} ", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(Color::DarkGray),
                ),
                root_badge,
            ]
        } else {
            title_spans
        };

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(info_width.min(inner.width)),
            ])
            .split(inner);

        frame.render_widget(Paragraph::new(Line::from(left_spans)), chunks[0]);
        frame.render_widget(
            Paragraph::new(Line::from(info_span)).alignment(Alignment::Right),
            chunks[1],
        );
    } else {
        frame.render_widget(Paragraph::new(Line::from(title_spans)), inner);
    }
}

fn render_device_explorer(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Top table: Block devices
    let header_cells = [
        "Device",
        "Type",
        "Vendor / Model",
        "Serial Number",
        "Size",
        "Status",
    ]
    .into_iter()
    .map(|h| {
        Span::styled(
            h,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header_row = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = app
        .devices
        .iter()
        .enumerate()
        .map(|(idx, dev)| {
            let is_selected = idx == app.selected_device_idx;
            let (status_text, status_style) = match &dev.safety {
                DeviceSafety::Safe => (
                    "SAFE",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                DeviceSafety::Mounted(_) => (
                    "MOUNTED",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                DeviceSafety::SystemDisk(_) => (
                    "SYSTEM (CRITICAL)",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(20, 35, 55)).fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            let cells = vec![
                Span::styled(
                    format!(" {} ", dev.path),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(dev.bus_type.clone(), Style::default().fg(Color::Cyan)),
                Span::styled(dev.display_name(), Style::default().fg(Color::White)),
                Span::styled(dev.display_serial(), Style::default().fg(Color::Yellow)),
                Span::styled(dev.human_size(), Style::default().fg(Color::White)),
                Span::styled(format!(" [{}] ", status_text), status_style),
            ];

            Row::new(cells).style(row_style).height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Length(18),
            Constraint::Length(20),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Storage Media Explorer "),
    );

    frame.render_widget(table, chunks[0]);

    // Bottom pane: Partitions + Hardware Detail
    let detail_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    if let Some(dev) = app.selected_device() {
        // Partitions list
        let mut part_items = Vec::new();
        if dev.partitions.is_empty() {
            part_items.push(ListItem::new("  (No partition table / Raw disk)"));
        } else {
            for p in &dev.partitions {
                let mp_str = p.mountpoint.as_deref().unwrap_or("unmounted");
                let fs_str = p.fstype.as_deref().unwrap_or("raw");
                let is_mounted = p.mountpoint.is_some();
                let color = if is_mounted {
                    Color::Yellow
                } else {
                    Color::Green
                };

                part_items.push(ListItem::new(vec![Line::from(vec![
                    Span::styled(
                        format!("  • {} ", p.path),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("({}) ", crate::models::device::format_bytes(p.size_bytes)),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(format!("[{}] ", fs_str), Style::default().fg(Color::Cyan)),
                    Span::styled(format!("-> {}", mp_str), Style::default().fg(color)),
                ])]));
            }
        }

        let part_list = List::new(part_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Partitions & Mountpoints "),
        );
        frame.render_widget(part_list, detail_chunks[0]);

        // Hardware info & SMART
        let mut hw_lines = vec![
            Line::from(vec![
                Span::styled("Device Node    : ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &dev.path,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Media Type     : ", Style::default().fg(Color::DarkGray)),
                Span::styled(dev.media_type_str(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Sector Size    : ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!(
                        "Logical {} B | Physical {} B",
                        dev.logical_sector_size, dev.physical_sector_size
                    ),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Partition Table: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    dev.partition_table_type
                        .as_deref()
                        .unwrap_or("None")
                        .to_uppercase(),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ];

        if let Some(smart) = &dev.smart {
            hw_lines.push(Line::from(vec![
                Span::styled("SMART Health   : ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &smart.assessment,
                    if smart.passed {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::Red)
                    },
                ),
            ]));
        }

        let hw_info = Paragraph::new(hw_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Hardware Specifications "),
        );
        frame.render_widget(hw_info, detail_chunks[1]);
    }
}

fn render_case_setup(frame: &mut Frame, app: &App, area: Rect) {
    let is_compact = area.height < 21;
    let preview_height = if is_compact { 3 } else { 5 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12),             // Fields grid
            Constraint::Length(preview_height), // Live Filename Preview Banner
            Constraint::Min(0),                 // Flexible spacer on taller screens
            Constraint::Length(3),              // Action button
        ])
        .split(area);

    let form_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    // Left Column: Case details
    let mut left_lines = Vec::new();
    let fields = [
        (
            "Case Number   ",
            &app.case_metadata.case_number,
            "VG12345/26",
            0,
        ),
        ("Location / EA ", &app.case_metadata.location_ea, "01", 1),
        (
            "Evidence Nr.  ",
            &app.case_metadata.evidence_number,
            "cf01",
            2,
        ),
        (
            "Authority     ",
            &app.case_metadata.authority,
            "Police Dept / CID",
            3,
        ),
        (
            "Examiner      ",
            &app.case_metadata.examiner,
            "J. Doe #4192",
            4,
        ),
        (
            "Description   ",
            &app.case_metadata.description,
            "Suspect Storage Media",
            5,
        ),
        (
            "Notes         ",
            &app.case_metadata.notes,
            "Optional notes",
            6,
        ),
    ];

    for (label, val, placeholder, idx) in fields {
        let is_active = app.active_field == idx;
        let prefix = if is_active { "▶ " } else { "  " };

        let mut field_spans = vec![Span::styled(
            format!("{}{:<15}: [ ", prefix, label),
            Style::default().fg(if is_active {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        )];

        if val.is_empty() {
            if is_active {
                field_spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
                field_spans.push(Span::styled(
                    placeholder,
                    Style::default().fg(Color::Rgb(90, 100, 110)),
                ));
            } else {
                field_spans.push(Span::styled(
                    placeholder,
                    Style::default().fg(Color::Rgb(70, 75, 85)),
                ));
            }
        } else if is_active {
            let (before, after) = safe_split_at(val, app.cursor_pos);
            field_spans.push(Span::styled(
                before,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
            field_spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
            field_spans.push(Span::styled(
                after,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            field_spans.push(Span::styled(val, Style::default().fg(Color::White)));
        }

        field_spans.push(Span::styled(" ]", Style::default().fg(Color::DarkGray)));
        left_lines.push(Line::from(field_spans));
    }

    let left_para = Paragraph::new(left_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Case & Evidence Information (Ctrl+U to clear) "),
    );
    frame.render_widget(left_para, form_chunks[0]);

    // Right Column: Acquisition Parameters
    let mut right_lines = Vec::new();

    // Target dir
    let is_dir_active = app.active_field == 7;
    let mut dir_spans = vec![
        Span::styled(
            if is_dir_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "Target Dir    : [ ",
            Style::default().fg(if is_dir_active {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        ),
    ];
    if is_dir_active {
        let (before, after) = safe_split_at(&app.target_dir_str, app.cursor_pos);
        dir_spans.push(Span::styled(
            before,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
        dir_spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
        dir_spans.push(Span::styled(
            after,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        dir_spans.push(Span::styled(
            &app.target_dir_str,
            Style::default().fg(Color::White),
        ));
    }
    dir_spans.push(Span::styled(" ]", Style::default().fg(Color::DarkGray)));
    right_lines.push(Line::from(dir_spans));

    // Format
    let is_fmt_active = app.active_field == 8;
    right_lines.push(Line::from(vec![
        Span::styled(
            if is_fmt_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("Output Format : ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("[ {} ]", app.config.format.display_name()),
            if is_fmt_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Yellow)
            },
        ),
        Span::styled(
            "  (Space/Arrows to toggle)",
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    // Split size
    let is_split_active = app.active_field == 9;
    right_lines.push(Line::from(vec![
        Span::styled(
            if is_split_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("Split Size    : ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("[ {} ]", app.config.split_size.display_name()),
            if is_split_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Yellow)
            },
        ),
    ]));

    // Compression
    let is_comp_active = app.active_field == 10;
    right_lines.push(Line::from(vec![
        Span::styled(
            if is_comp_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("Compression   : ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("[ {:?} ]", app.config.compression),
            if is_comp_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Yellow)
            },
        ),
    ]));

    // Hashes
    let hash_md5_active = app.active_field == 11;
    let hash_sha1_active = app.active_field == 12;
    let hash_sha256_active = app.active_field == 13;
    right_lines.push(Line::from(vec![
        Span::styled("  Hashes        : ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            if app.config.calc_md5 {
                "[X] MD5 "
            } else {
                "[ ] MD5 "
            },
            if hash_md5_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            },
        ),
        Span::styled(
            if app.config.calc_sha1 {
                "[X] SHA-1 "
            } else {
                "[ ] SHA-1 "
            },
            if hash_sha1_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            },
        ),
        Span::styled(
            if app.config.calc_sha256 {
                "[X] SHA-256 "
            } else {
                "[ ] SHA-256 "
            },
            if hash_sha256_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            },
        ),
    ]));

    // Rescue mode
    let is_rescue_active = app.active_field == 14;
    right_lines.push(Line::from(vec![
        Span::styled(
            if is_rescue_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("Engine Mode   : ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            if app.config.rescue_mode {
                "[ RESCUE (ddrescue) - FOR DAMAGED DISKS ]"
            } else {
                "[ STANDARD (ewfacquire E01) ]"
            },
            if is_rescue_active {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::Green)
            },
        ),
    ]));

    let right_para = Paragraph::new(right_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Acquisition Parameters "),
    );
    frame.render_widget(right_para, form_chunks[1]);

    // Live Generated Preview Banner
    let preview_e01 = app.generated_preview_filename();
    let serial = app
        .selected_device()
        .map(|d| d.display_serial())
        .unwrap_or_else(|| "SERIAL".to_string());
    let preview_info = app.case_metadata.generate_filename(&serial, "info");

    let preview_lines = if preview_height >= 4 {
        vec![
            Line::from(vec![
                Span::styled(
                    "  Target Image File       : ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    preview_e01,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "  Forensic Certificate    : ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    preview_info,
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
        ]
    } else {
        vec![Line::from(vec![
            Span::styled(
                " Target: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                preview_e01,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │ Cert: ", Style::default().fg(Color::DarkGray)),
            Span::styled(preview_info, Style::default().fg(Color::Green)),
        ])]
    };

    let preview_box = Paragraph::new(preview_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(0, 180, 216)))
            .title(" Generated Evidence Output Filenames (Auto-Sanitized) "),
    );
    frame.render_widget(preview_box, chunks[1]);

    // Action button
    let fields = crate::tui::app::FormField::all();
    let is_start_active =
        fields[app.active_field % fields.len()] == crate::tui::app::FormField::StartButton;
    render_action_button(
        frame,
        chunks[3],
        "Start Forensic Acquisition",
        "F5",
        is_start_active,
        false,
        "",
    );
}

fn render_acquisition(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Gauge
            Constraint::Length(6), // Metrics 4-box grid
            Constraint::Min(6),    // Live Log console
        ])
        .split(area);

    // Progress Gauge
    let gauge_title = format!(
        " Acquisition Progress: {:.1}%  ({} / {}) ",
        app.telemetry.percentage,
        crate::models::device::format_bytes(app.telemetry.bytes_processed),
        crate::models::device::format_bytes(app.telemetry.total_bytes)
    );

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan))
                .title(gauge_title),
        )
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
        .percent(app.telemetry.percentage.clamp(0.0, 100.0) as u16);

    frame.render_widget(gauge, chunks[0]);

    // Metrics grid
    let metric_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[1]);

    // 1: Speed
    let speed_para = Paragraph::new(vec![
        Line::from(Span::styled(
            "Current Speed",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            app.telemetry.human_speed(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("Avg: {}", app.telemetry.human_avg_speed()),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(speed_para, metric_chunks[0]);

    // 2: Elapsed / ETA
    let eta_para = Paragraph::new(vec![
        Line::from(Span::styled(
            "Elapsed / ETA",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("ETA: {}", app.telemetry.human_eta()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("Elapsed: {}", app.telemetry.human_elapsed()),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(eta_para, metric_chunks[1]);

    // 3: Status & Compression
    let comp_str = match app.telemetry.compression_ratio {
        Some(r) => format!("Ratio: {:.2}x", r),
        None => "Ratio: --".to_string(),
    };
    let status_para = Paragraph::new(vec![
        Line::from(Span::styled(
            "Phase & Compression",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            app.telemetry.status.display_str(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(comp_str, Style::default().fg(Color::White))),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status_para, metric_chunks[2]);

    // 4: Bad blocks / Errors
    let bad_color = if app.telemetry.bad_sectors > 0 {
        Color::Red
    } else {
        Color::Green
    };
    let bad_para = Paragraph::new(vec![
        Line::from(Span::styled(
            "Bad Sectors",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("{} sectors", app.telemetry.bad_sectors),
            Style::default().fg(bad_color).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            if app.telemetry.bad_sectors == 0 {
                "Clean stream"
            } else {
                "Wiped with zero"
            },
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(bad_para, metric_chunks[3]);

    // Live Log Console
    let log_items: Vec<ListItem> = app
        .telemetry
        .log_messages
        .iter()
        .rev()
        .take(15)
        .map(|msg| ListItem::new(format!("  {}", msg)))
        .collect();

    let log_list = List::new(log_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Live Engine Telemetry & Log Console "),
    );
    frame.render_widget(log_list, chunks[2]);
}

fn render_report_summary(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(report) = &app.final_report {
        let text = report.render_text();
        let para = Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green))
                .title(" Forensic Acquisition Certificate Summary (Saved to .info) "),
        );
        frame.render_widget(para, area);
    }
}

fn render_converter(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // Form and status box
            Constraint::Min(4),    // Converter help & instructions (expands on taller screens)
            Constraint::Length(3), // Action button anchored at the bottom
        ])
        .split(area);

    let mut lines = Vec::new();

    // Source Image Path (active_field == 0)
    let is_src_active = app.conv_active_field == 0;
    let mut src_spans = vec![
        Span::styled(
            if is_src_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "Source Image Path  : [ ",
            Style::default().fg(if is_src_active {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        ),
    ];
    if is_src_active {
        let (before, after) = safe_split_at(&app.conv_source_path, app.conv_cursor_pos);
        src_spans.push(Span::styled(
            before,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
        src_spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
        src_spans.push(Span::styled(
            after,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    } else if app.conv_source_path.is_empty() {
        src_spans.push(Span::styled(
            "/path/to/evidence.raw or .E01",
            Style::default().fg(Color::Rgb(70, 75, 85)),
        ));
    } else {
        src_spans.push(Span::styled(
            &app.conv_source_path,
            Style::default().fg(Color::White),
        ));
    }
    src_spans.push(Span::styled(" ]", Style::default().fg(Color::DarkGray)));
    lines.push(Line::from(src_spans));

    // Conversion Mode (active_field == 1)
    let is_mode_active = app.conv_active_field == 1;
    lines.push(Line::from(vec![
        Span::styled(
            if is_mode_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "Conversion Mode    : ",
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            if app.conv_to_e01 {
                "[ RAW -> E01 (Expert Witness) ]"
            } else {
                "[ E01 -> RAW (Raw Disk Image) ]"
            },
            if is_mode_active {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow)
            },
        ),
        Span::styled(
            "  (Space/Arrows to toggle)",
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    // Destination Dir (active_field == 2)
    let is_dst_active = app.conv_active_field == 2;
    let mut dst_spans = vec![
        Span::styled(
            if is_dst_active { "▶ " } else { "  " },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            "Destination Dir    : [ ",
            Style::default().fg(if is_dst_active {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        ),
    ];
    if is_dst_active {
        let (before, after) = safe_split_at(&app.conv_target_dir, app.conv_cursor_pos);
        dst_spans.push(Span::styled(
            before,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
        dst_spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
        dst_spans.push(Span::styled(
            after,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    } else if app.conv_target_dir.is_empty() {
        dst_spans.push(Span::styled(
            "/path/to/destination/dir",
            Style::default().fg(Color::Rgb(70, 75, 85)),
        ));
    } else {
        dst_spans.push(Span::styled(
            &app.conv_target_dir,
            Style::default().fg(Color::White),
        ));
    }
    dst_spans.push(Span::styled(" ]", Style::default().fg(Color::DarkGray)));
    lines.push(Line::from(dst_spans));

    // Spacer
    lines.push(Line::from(""));

    // Status message
    lines.push(Line::from(vec![
        Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
        Span::styled(&app.conv_status_msg, Style::default().fg(Color::Yellow)),
    ]));

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Forensic Image Format Converter (RAW <-> E01) "),
    );
    frame.render_widget(para, chunks[0]);

    // Converter Instructions in chunk[1] (expands vertically on taller screens)
    let help_lines = vec![
        Line::from(vec![
            Span::styled(
                "• RAW -> E01: ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Encapsulates raw image (.raw, .dd, .img) into Expert Witness Format with SHA-256 integrity hash.",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "• E01 -> RAW: ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Extracts and decompresses E01 evidence container to raw byte stream.",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "• TAB Autocomplete: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Press Tab on Path fields to autocomplete paths. Repeated Tab cycles candidates.",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "• Field Navigation: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Use ↑ / ↓ arrow keys or Enter to switch fields. Press F5 to start conversion.",
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    let help_para = Paragraph::new(help_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Converter Help & Instructions "),
    );
    frame.render_widget(help_para, chunks[1]);

    // Action button anchored at the bottom in chunk[2]
    let conv_fields = crate::tui::app::ConverterField::all();
    let is_btn_active = conv_fields[app.conv_active_field % conv_fields.len()]
        == crate::tui::app::ConverterField::StartButton;
    let is_busy = app.conv_rx.is_some();
    render_action_button(
        frame,
        chunks[2],
        "Start Conversion",
        "F5",
        is_btn_active,
        is_busy,
        "Conversion in Progress...",
    );
}

fn render_unmount_modal(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" ⚠ UNMOUNT CONFIRMATION ");

    let modal_area = centered_rect(60, 30, area);
    frame.render_widget(Clear, modal_area);

    let dev_name = app.selected_device().map(|d| d.path.as_str()).unwrap_or("");
    let mount_list = app
        .selected_device()
        .map(|d| d.mountpoints.join(", "))
        .unwrap_or_default();

    let text = vec![
        Line::from(vec![
            Span::styled("Device ", Style::default().fg(Color::White)),
            Span::styled(
                dev_name,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " currently has active mountpoints:",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(Span::styled(
            format!("  {}", mount_list),
            Style::default().fg(Color::Red),
        )),
        Line::from(""),
        Line::from("Imaging a mounted filesystem can lead to inconsistent forensics."),
        Line::from("Do you want dfdisk to safely unmount all partitions?"),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " [Y / Enter] Safe Unmount & Proceed ",
                Style::default()
                    .bg(Color::Green)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("    ", Style::default()),
            Span::styled(
                " [N / Esc] Cancel ",
                Style::default().bg(Color::DarkGray).fg(Color::White),
            ),
        ]),
    ];

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    frame.render_widget(para, modal_area);
}

fn render_system_warning_modal(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Red))
        .title(" ⛔ DANGER: SYSTEM / ROOT DISK DETECTED ");

    let modal_area = centered_rect(70, 35, area);
    frame.render_widget(Clear, modal_area);

    let dev_name = app.selected_device().map(|d| d.path.as_str()).unwrap_or("");

    let text = vec![
        Line::from(Span::styled("CRITICAL FORENSIC SAFETY WARNING", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Device ", Style::default().fg(Color::White)),
            Span::styled(dev_name, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(" contains the live host operating system (/, /boot, or swap)!", Style::default().fg(Color::White)),
        ]),
        Line::from("Imaging your live OS drive may acquire changing memory caches and cannot be unmounted."),
        Line::from(""),
        Line::from("Are you absolutely sure you want to image the system drive?"),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [Y] Proceed Anyway (Expert) ", Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("    ", Style::default()),
            Span::styled(" [N / Esc] ABORT (Recommended) ", Style::default().bg(Color::Green).fg(Color::Black).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    frame.render_widget(para, modal_area);
}

pub(crate) fn render_action_button(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    shortcut: &str,
    is_focused: bool,
    is_busy: bool,
    busy_label: &str,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }

    // Determine target width: clamp between 20 and 48 columns, reserving side margins
    let max_avail = area.width.saturating_sub(4);
    let btn_width = max_avail.clamp(20, 48).min(area.width);
    let x_offset = area.x + (area.width.saturating_sub(btn_width)) / 2;
    let btn_area = Rect {
        x: x_offset,
        y: area.y,
        width: btn_width,
        height: area.height.min(3),
    };

    // Calculate available inner text width before branching on height
    let inner_width = btn_width.saturating_sub(if btn_area.height >= 3 { 2 } else { 0 });
    let avail_text_width = if is_focused {
        inner_width.saturating_sub(4)
    } else {
        inner_width
    };

    let base_text = if is_busy {
        if avail_text_width >= busy_label.len() as u16 {
            busy_label.to_string()
        } else {
            "Busy...".to_string()
        }
    } else {
        let full_text = format!("{} · {}", label, shortcut);
        if avail_text_width >= full_text.len() as u16 {
            full_text
        } else {
            let short_label = label
                .strip_prefix("Start Forensic ")
                .map(|s| format!("Start {}", s))
                .unwrap_or_else(|| label.to_string());
            let medium_text = format!("{} · {}", short_label, shortcut);
            if avail_text_width >= medium_text.len() as u16 {
                medium_text
            } else {
                format!("Start · {}", shortcut)
            }
        }
    };

    let display_text = if is_focused {
        format!("▶ {} ◀", base_text)
    } else {
        base_text
    };

    if btn_area.height < 3 {
        let style = if is_busy {
            Style::default().fg(Color::Yellow)
        } else if is_focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White).bg(Color::DarkGray)
        };
        let p = Paragraph::new(display_text)
            .alignment(Alignment::Center)
            .style(style);
        frame.render_widget(p, btn_area);
        return;
    }

    if is_busy {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray));
        let p = Paragraph::new(display_text)
            .alignment(Alignment::Center)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(block);
        frame.render_widget(p, btn_area);
        return;
    }

    if is_focused {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Green));
        let p = Paragraph::new(display_text)
            .alignment(Alignment::Center)
            .style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
            .block(block);
        frame.render_widget(p, btn_area);
    } else {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Gray));
        let p = Paragraph::new(display_text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::White))
            .block(block);
        frame.render_widget(p, btn_area);
    }
}

pub(crate) fn footer_hints(app: &App) -> Span<'static> {
    match app.current_screen {
        Screen::DeviceExplorer => Span::styled(
            " [Enter/A] Select Disk  [U] Unmount  [R] Refresh  [C] Converter  [Esc/Q] Quit ",
            Style::default().fg(Color::Gray),
        ),
        Screen::CaseSetup => {
            let fields = crate::tui::app::FormField::all();
            let cur = &fields[app.active_field % fields.len()];
            match cur {
                crate::tui::app::FormField::TargetDir => Span::styled(
                    " [Tab] Autocomplete  [↓/Enter] Next Field  [Ctrl+U] Clear  [F5] Start  [Esc] Back ",
                    Style::default().fg(Color::Gray),
                ),
                crate::tui::app::FormField::Format
                | crate::tui::app::FormField::SplitSize
                | crate::tui::app::FormField::Compression
                | crate::tui::app::FormField::HashMd5
                | crate::tui::app::FormField::HashSha1
                | crate::tui::app::FormField::HashSha256
                | crate::tui::app::FormField::RescueMode => Span::styled(
                    " [Space/←/→] Toggle  [Tab/↓/Enter] Next Field  [F5] Start  [Esc] Back ",
                    Style::default().fg(Color::Gray),
                ),
                crate::tui::app::FormField::StartButton => Span::styled(
                    " [Enter/Space/F5] Start Acquisition  [Shift+Tab/↑] Prev Field  [Esc] Back ",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                _ => Span::styled(
                    " [Tab/↓/Enter] Next Field  [Ctrl+U] Clear  [F5] Start Acquisition  [Esc] Back ",
                    Style::default().fg(Color::Gray),
                ),
            }
        }
        Screen::AcquisitionRunning => Span::styled(
            " [Ctrl+C / Esc / A] Abort Acquisition ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Screen::ReportSummary => Span::styled(
            " [Enter / Esc / Q] Return to Explorer ",
            Style::default().fg(Color::Green),
        ),
        Screen::Converter => {
            if app.conv_rx.is_some() {
                Span::styled(
                    " [A] Abort  [Esc] Abort & Return to Explorer  (Conversion in progress...) ",
                    Style::default().fg(Color::Yellow),
                )
            } else {
                let conv_fields = crate::tui::app::ConverterField::all();
                let cur = &conv_fields[app.conv_active_field % conv_fields.len()];
                match cur {
                    crate::tui::app::ConverterField::SourcePath
                    | crate::tui::app::ConverterField::TargetDir => Span::styled(
                        " [Tab] Autocomplete  [↓/Enter] Next Field  [Ctrl+U] Clear  [F5] Start  [Esc] Back ",
                        Style::default().fg(Color::Gray),
                    ),
                    crate::tui::app::ConverterField::Mode => Span::styled(
                        " [Space/←/→] Toggle Mode  [Tab/↓/Enter] Next Field  [F5] Start  [Esc] Back ",
                        Style::default().fg(Color::Gray),
                    ),
                    crate::tui::app::ConverterField::StartButton => Span::styled(
                        " [Enter/Space/F5] Start Conversion  [Shift+Tab/↑] Prev Field  [Esc] Back ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                }
            }
        }
        Screen::UnmountPrompt => Span::styled(
            " [Y/Enter] Safe Unmount & Proceed  [N/Esc] Cancel ",
            Style::default().fg(Color::Yellow),
        ),
        Screen::SystemDiskWarning => Span::styled(
            " [Y] Proceed Anyway (Expert)  [N/Esc/Enter] Abort (Recommended) ",
            Style::default().fg(Color::Red),
        ),
    }
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let msg = footer_hints(app);

    let footer = Paragraph::new(Line::from(msg))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(footer, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub(crate) fn safe_split_at(s: &str, mut idx: usize) -> (&str, &str) {
    if idx > s.len() {
        idx = s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    (&s[..idx], &s[idx..])
}

pub(crate) fn nix_is_root() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_split_at_ascii() {
        let (before, after) = safe_split_at("hello world", 5);
        assert_eq!(before, "hello");
        assert_eq!(after, " world");

        let (b_zero, a_zero) = safe_split_at("hello", 0);
        assert_eq!(b_zero, "");
        assert_eq!(a_zero, "hello");

        let (b_past, a_past) = safe_split_at("hello", 100);
        assert_eq!(b_past, "hello");
        assert_eq!(a_past, "");
    }

    #[test]
    fn test_safe_split_at_multibyte_boundary() {
        // "ä" is 2 bytes (indices 0..2), "世" is 3 bytes (indices 2..5)
        let s = "ä世";
        assert_eq!(s.len(), 5);

        // Splitting right at index 1 (inside 'ä') must not panic and adjust backward to 0
        let (before, after) = safe_split_at(s, 1);
        assert_eq!(before, "");
        assert_eq!(after, "ä世");

        // Splitting at index 2 (exact boundary between 'ä' and '世')
        let (before, after) = safe_split_at(s, 2);
        assert_eq!(before, "ä");
        assert_eq!(after, "世");

        // Splitting at index 3 or 4 (inside '世') adjusts backward to 2
        let (before, after) = safe_split_at(s, 3);
        assert_eq!(before, "ä");
        assert_eq!(after, "世");

        let (before, after) = safe_split_at(s, 4);
        assert_eq!(before, "ä");
        assert_eq!(after, "世");

        // Splitting at index 5 (end)
        let (before, after) = safe_split_at(s, 5);
        assert_eq!(before, "ä世");
        assert_eq!(after, "");
    }

    #[test]
    fn test_nix_is_root_execution() {
        // Ensure nix_is_root executes cleanly without crashing
        let _ = nix_is_root();
    }

    #[test]
    fn test_safe_split_at_stress_adversarial() {
        let test_strings = [
            "",
            "a",
            "hello world",
            "äöü",
            "こんにちは世界",
            "Привет мир",
            "🚀🔒🛡️⚡🎯🎉",
            "👨‍👩‍👧‍👦",
            "Mix ä 世 🚀 123",
        ];

        for s in &test_strings {
            // Test indices from 0 up to well beyond the byte length
            for idx in 0..=s.len() + 10 {
                let (before, after) = safe_split_at(s, idx);
                assert_eq!(
                    format!("{}{}", before, after),
                    *s,
                    "Split pieces must reconstruct original string at idx {}",
                    idx
                );
            }
        }
    }

    #[test]
    fn test_footer_hints_and_notification_separation() {
        let mut app = App::new();

        // 1. DeviceExplorer screen hints
        app.current_screen = Screen::DeviceExplorer;
        let hints = footer_hints(&app);
        assert!(hints.content.contains("Select Disk"));
        assert!(hints.content.contains("Esc/Q"));
        assert!(!hints.content.contains("Setup"));

        // Setting a notification message must NOT change or overwrite footer hints
        app.notification_msg = Some(("Device list refreshed.".to_string(), false));
        let hints_with_msg = footer_hints(&app);
        assert_eq!(hints.content, hints_with_msg.content);

        // 2. AcquisitionRunning screen hints - abort must always be present
        app.current_screen = Screen::AcquisitionRunning;
        let acq_hints = footer_hints(&app);
        assert!(acq_hints.content.contains("Abort Acquisition"));

        // With notification message set, abort hint still present
        app.notification_msg = Some(("Aborting acquisition...".to_string(), true));
        let acq_hints_with_msg = footer_hints(&app);
        assert_eq!(acq_hints.content, acq_hints_with_msg.content);
        assert!(acq_hints_with_msg.content.contains("Abort Acquisition"));
    }

    #[test]
    fn test_render_header_and_footer_widgets() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(100, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut app = App::new();
        app.current_screen = Screen::DeviceExplorer;
        app.notification_msg = Some(("Device list refreshed.".to_string(), false));

        terminal
            .draw(|f| {
                render_header(f, &app, Rect::new(0, 0, 100, 3));
                render_footer(f, &app, Rect::new(0, 7, 100, 3));
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let rendered_text: String = buffer.content().iter().map(|c| c.symbol()).collect();

        // Header must contain notification text
        assert!(rendered_text.contains("Device list refreshed."));
        // Footer must contain explorer shortcuts and NOT be replaced by notification
        assert!(rendered_text.contains("Select Disk"));
        assert!(rendered_text.contains("Esc/Q"));
    }

    #[test]
    fn test_render_header_narrow_and_long_notifications() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let widths = [20, 40, 60, 80, 120];
        for &w in &widths {
            let backend = TestBackend::new(w, 5);
            let mut terminal = Terminal::new(backend).unwrap();

            let mut app = App::new();
            // Test with very long notification (300 chars)
            let long_msg = "X".repeat(300);
            app.notification_msg = Some((long_msg, true));

            terminal
                .draw(|f| {
                    render_header(f, &app, Rect::new(0, 0, w, 3));
                })
                .unwrap();

            let buffer = terminal.backend().buffer();
            let rendered_text: String = buffer.content().iter().map(|c| c.symbol()).collect();
            // Should contain error indicator without panicking
            assert!(rendered_text.contains('⚠'));
        }
    }

    #[test]
    fn test_footer_hints_all_screens_coverage() {
        let mut app = App::new();

        // DeviceExplorer
        app.current_screen = Screen::DeviceExplorer;
        assert!(footer_hints(&app).content.contains("Select Disk"));
        assert!(footer_hints(&app).content.contains("Esc/Q"));

        // CaseSetup
        app.current_screen = Screen::CaseSetup;
        app.active_field = 0;
        let hint_field0 = footer_hints(&app).content.to_string();
        assert!(hint_field0.contains("[Tab/↓/Enter] Next Field"));
        assert!(hint_field0.contains("[F5] Start Acquisition"));
        assert!(!hint_field0.contains("[F5/Enter]"));

        let target_dir_idx = crate::tui::app::FormField::all()
            .iter()
            .position(|f| *f == crate::tui::app::FormField::TargetDir)
            .unwrap();
        app.active_field = target_dir_idx;
        assert!(footer_hints(&app).content.contains("Autocomplete"));

        let start_btn_idx = crate::tui::app::FormField::all()
            .iter()
            .position(|f| *f == crate::tui::app::FormField::StartButton)
            .unwrap();
        app.active_field = start_btn_idx;
        assert!(footer_hints(&app)
            .content
            .contains("[Enter/Space/F5] Start Acquisition"));

        // AcquisitionRunning
        app.current_screen = Screen::AcquisitionRunning;
        assert!(footer_hints(&app).content.contains("Abort Acquisition"));
        assert!(footer_hints(&app).content.contains("Ctrl+C / Esc / A"));

        // ReportSummary
        app.current_screen = Screen::ReportSummary;
        assert!(footer_hints(&app).content.contains("Return to Explorer"));
        assert!(footer_hints(&app).content.contains("Enter / Esc / Q"));

        // Converter
        app.current_screen = Screen::Converter;
        app.conv_active_field = 0;
        assert!(footer_hints(&app).content.contains("Autocomplete"));
        app.conv_active_field = 1;
        assert!(footer_hints(&app).content.contains("Toggle Mode"));
        app.conv_active_field = 3;
        assert!(footer_hints(&app)
            .content
            .contains("[Enter/Space/F5] Start Conversion"));

        // Converter Busy
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        app.conv_rx = Some(rx);
        let busy_hint = footer_hints(&app).content.to_string();
        assert!(busy_hint.contains("[A] Abort"));
        assert!(busy_hint.contains("Abort & Return to Explorer"));
        assert!(busy_hint.contains("Conversion in progress..."));
        app.conv_rx = None;

        // UnmountPrompt
        app.current_screen = Screen::UnmountPrompt;
        assert!(footer_hints(&app).content.contains("Safe Unmount"));

        // SystemDiskWarning
        app.current_screen = Screen::SystemDiskWarning;
        assert!(footer_hints(&app).content.contains("Proceed Anyway"));
    }

    #[test]
    fn test_render_action_button_widget() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let widths = [25, 35, 45, 60, 80];
        for &w in &widths {
            for &h in &[1, 2, 3, 5] {
                let backend = TestBackend::new(w, h);
                let mut terminal = Terminal::new(backend).unwrap();

                // Unfocused
                terminal
                    .draw(|f| {
                        render_action_button(
                            f,
                            Rect::new(0, 0, w, h),
                            "Start Forensic Acquisition",
                            "F5",
                            false,
                            false,
                            "",
                        );
                    })
                    .unwrap();
                let unfocused_text: String = terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(
                    unfocused_text.contains("F5"),
                    "Unfocused button must retain F5 at {}x{}",
                    w,
                    h
                );

                // Focused
                terminal
                    .draw(|f| {
                        render_action_button(
                            f,
                            Rect::new(0, 0, w, h),
                            "Start Forensic Acquisition",
                            "F5",
                            true,
                            false,
                            "",
                        );
                    })
                    .unwrap();
                let focused_text: String = terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(
                    focused_text.contains("F5"),
                    "Focused button must retain F5 at {}x{}",
                    w,
                    h
                );
                assert!(
                    focused_text.contains('▶') && focused_text.contains('◀'),
                    "Focused button must retain focus markers at {}x{}",
                    w,
                    h
                );

                // Busy
                terminal
                    .draw(|f| {
                        render_action_button(
                            f,
                            Rect::new(0, 0, w, h),
                            "Start Forensic Acquisition",
                            "F5",
                            false,
                            true,
                            "Converting...",
                        );
                    })
                    .unwrap();
                let busy_text: String = terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(
                    busy_text.contains("Converting") || busy_text.contains("Busy"),
                    "Busy button must display busy indicator at {}x{}",
                    w,
                    h
                );
            }
        }
    }

    #[test]
    fn test_case_setup_and_converter_render_at_80x24() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        let mut app = App::new();

        // 1. Render CaseSetup unfocused
        app.current_screen = Screen::CaseSetup;
        app.active_field = 0;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Start"));
        assert!(text.contains("F5"));

        // 2. Render CaseSetup focused on StartButton
        let btn_idx = crate::tui::app::FormField::all()
            .iter()
            .position(|f| *f == crate::tui::app::FormField::StartButton)
            .unwrap();
        app.active_field = btn_idx;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("▶"));
        assert!(text.contains("◀"));

        // 3. Render Converter and verify button is anchored at bottom rows (18..21)
        app.current_screen = Screen::Converter;
        app.conv_active_field = 0;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut bottom_text = String::new();
        for y in 18..21 {
            for x in 0..80 {
                bottom_text.push_str(buf.get(x, y).symbol());
            }
        }
        assert!(
            bottom_text.contains("Start Conversion") || bottom_text.contains("Start · F5"),
            "Converter action button must be anchored at the bottom (rows 18..20), got: {}",
            bottom_text
        );
    }
}
