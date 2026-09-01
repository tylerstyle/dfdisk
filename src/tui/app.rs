use crate::discovery::{DeviceScanner, SafetyChecker};
use crate::engines::{EwfAcquireEngine, FormatConverter, RescueAcquireEngine};
use crate::models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, CompressionLevel, ImageFormat, SplitSize},
    device::BlockDevice,
    info_report::ForensicInfoReport,
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    DeviceExplorer,
    CaseSetup,
    AcquisitionRunning,
    ReportSummary,
    Converter,
    UnmountPrompt,
    SystemDiskWarning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormField {
    CaseNumber,
    LocationEa,
    EvidenceNumber,
    Authority,
    Examiner,
    Description,
    Notes,
    TargetDir,
    Format,
    SplitSize,
    Compression,
    HashMd5,
    HashSha1,
    HashSha256,
    RescueMode,
    StartButton,
}

impl FormField {
    pub fn all() -> &'static [FormField] {
        &[
            FormField::CaseNumber,
            FormField::LocationEa,
            FormField::EvidenceNumber,
            FormField::Authority,
            FormField::Examiner,
            FormField::Description,
            FormField::Notes,
            FormField::TargetDir,
            FormField::Format,
            FormField::SplitSize,
            FormField::Compression,
            FormField::HashMd5,
            FormField::HashSha1,
            FormField::HashSha256,
            FormField::RescueMode,
            FormField::StartButton,
        ]
    }
}

pub struct App {
    pub current_screen: Screen,
    pub devices: Vec<BlockDevice>,
    pub selected_device_idx: usize,
    pub case_metadata: CaseMetadata,
    pub config: AcquisitionConfig,
    pub active_field: usize,
    pub cursor_pos: usize,
    pub target_dir_str: String,

    // Telemetry & Results
    pub telemetry: ProgressTelemetry,
    pub final_report: Option<ForensicInfoReport>,
    pub notification_msg: Option<(String, bool)>, // text, is_error

    // Background workers
    pub progress_rx: Option<mpsc::Receiver<ProgressTelemetry>>,
    pub report_rx: Option<mpsc::Receiver<Result<ForensicInfoReport, String>>>,
    pub abort_flag: Arc<AtomicBool>,

    // Converter Screen State
    pub conv_source_path: String,
    pub conv_cursor_pos: usize,
    pub conv_target_dir: String,
    pub conv_to_e01: bool,
    pub conv_status_msg: String,

    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        let devices = DeviceScanner::scan_devices().unwrap_or_default();
        let target_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let target_dir_str = target_dir.to_string_lossy().to_string();

        Self {
            current_screen: Screen::DeviceExplorer,
            devices,
            selected_device_idx: 0,
            case_metadata: CaseMetadata::default(),
            config: AcquisitionConfig {
                output_dir: target_dir.clone(),
                ..Default::default()
            },
            active_field: 0,
            cursor_pos: 0,
            target_dir_str,
            telemetry: ProgressTelemetry::default(),
            final_report: None,
            notification_msg: None,
            progress_rx: None,
            report_rx: None,
            abort_flag: Arc::new(AtomicBool::new(false)),
            conv_source_path: "".to_string(),
            conv_cursor_pos: 0,
            conv_target_dir: target_dir.to_string_lossy().to_string(),
            conv_to_e01: true,
            conv_status_msg: "Ready to convert images.".to_string(),
            should_quit: false,
        }
    }

    pub fn refresh_devices(&mut self) {
        match DeviceScanner::scan_devices() {
            Ok(devs) => {
                self.devices = devs;
                if self.selected_device_idx >= self.devices.len() && !self.devices.is_empty() {
                    self.selected_device_idx = self.devices.len() - 1;
                }
                self.notification_msg = Some(("Device list refreshed.".to_string(), false));
            }
            Err(e) => {
                self.notification_msg = Some((format!("Scan error: {}", e), true));
            }
        }
    }

    pub fn selected_device(&self) -> Option<&BlockDevice> {
        self.devices.get(self.selected_device_idx)
    }

    pub fn generated_preview_filename(&self) -> String {
        let serial = self
            .selected_device()
            .map(|d| d.display_serial())
            .unwrap_or_else(|| "SERIAL".to_string());
        let ext = self.config.format.extension();
        self.case_metadata.generate_filename(&serial, ext)
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        match self.current_screen {
            Screen::DeviceExplorer => self.handle_key_explorer(key),
            Screen::CaseSetup => self.handle_key_case_setup(key),
            Screen::AcquisitionRunning => self.handle_key_acquisition(key),
            Screen::ReportSummary => self.handle_key_report(key),
            Screen::Converter => self.handle_key_converter(key),
            Screen::UnmountPrompt => self.handle_key_unmount_prompt(key),
            Screen::SystemDiskWarning => self.handle_key_system_warning(key),
        }
    }

    fn handle_key_explorer(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_device_idx > 0 {
                    self.selected_device_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.devices.is_empty() && self.selected_device_idx < self.devices.len() - 1 {
                    self.selected_device_idx += 1;
                }
            }
            KeyCode::Char('r') | KeyCode::F(2) => self.refresh_devices(),
            KeyCode::Char('u') | KeyCode::F(3) => {
                if let Some(dev) = self.selected_device() {
                    if dev.safety.is_mounted() {
                        self.current_screen = Screen::UnmountPrompt;
                    } else {
                        self.notification_msg = Some(("Device is already unmounted.".to_string(), false));
                    }
                }
            }
            KeyCode::Char('c') | KeyCode::F(7) => {
                self.current_screen = Screen::Converter;
            }
            KeyCode::Enter | KeyCode::Char('a') | KeyCode::F(5) => {
                if let Some(dev) = self.selected_device() {
                    if dev.safety.is_system() {
                        self.current_screen = Screen::SystemDiskWarning;
                    } else if dev.safety.is_mounted() {
                        self.current_screen = Screen::UnmountPrompt;
                    } else {
                        self.current_screen = Screen::CaseSetup;
                        self.reset_cursor_to_current_field();
                    }
                }
            }
            _ => {}
        }
    }

    fn reset_cursor_to_current_field(&mut self) {
        let fields = FormField::all();
        let cur_field = &fields[self.active_field % fields.len()];
        let len = match cur_field {
            FormField::CaseNumber => self.case_metadata.case_number.len(),
            FormField::LocationEa => self.case_metadata.location_ea.len(),
            FormField::EvidenceNumber => self.case_metadata.evidence_number.len(),
            FormField::Authority => self.case_metadata.authority.len(),
            FormField::Examiner => self.case_metadata.examiner.len(),
            FormField::Description => self.case_metadata.description.len(),
            FormField::Notes => self.case_metadata.notes.len(),
            FormField::TargetDir => self.target_dir_str.len(),
            _ => 0,
        };
        self.cursor_pos = len;
    }

    fn handle_key_unmount_prompt(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                if let Some(dev) = self.selected_device() {
                    match SafetyChecker::unmount_all(&dev.mountpoints) {
                        Ok(()) => {
                            self.notification_msg = Some(("Device successfully unmounted.".to_string(), false));
                            self.refresh_devices();
                            self.current_screen = Screen::CaseSetup;
                            self.reset_cursor_to_current_field();
                        }
                        Err(e) => {
                            self.notification_msg = Some((format!("Unmount failed: {}", e), true));
                            self.current_screen = Screen::DeviceExplorer;
                        }
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.current_screen = Screen::DeviceExplorer;
            }
            _ => {}
        }
    }

    fn handle_key_system_warning(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.current_screen = Screen::CaseSetup;
                self.reset_cursor_to_current_field();
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Enter => {
                self.current_screen = Screen::DeviceExplorer;
            }
            _ => {}
        }
    }

    fn handle_key_case_setup(&mut self, key: KeyEvent) {
        let fields = FormField::all();
        let cur_field = &fields[self.active_field % fields.len()];

        match key.code {
            KeyCode::Esc => {
                self.current_screen = Screen::DeviceExplorer;
            }
            KeyCode::Tab | KeyCode::Down => {
                self.active_field = (self.active_field + 1) % fields.len();
                self.reset_cursor_to_current_field();
            }
            KeyCode::BackTab | KeyCode::Up => {
                if self.active_field == 0 {
                    self.active_field = fields.len() - 1;
                } else {
                    self.active_field -= 1;
                }
                self.reset_cursor_to_current_field();
            }
            KeyCode::Enter => {
                if *cur_field == FormField::StartButton {
                    self.start_acquisition();
                } else {
                    self.active_field = (self.active_field + 1) % fields.len();
                    self.reset_cursor_to_current_field();
                }
            }
            KeyCode::F(5) => {
                self.start_acquisition();
            }
            _ => {
                self.handle_field_input(cur_field, key);
            }
        }
    }

    fn handle_field_input(&mut self, field: &FormField, key: KeyEvent) {
        match field {
            FormField::CaseNumber => edit_text(&mut self.case_metadata.case_number, &mut self.cursor_pos, key),
            FormField::LocationEa => edit_text(&mut self.case_metadata.location_ea, &mut self.cursor_pos, key),
            FormField::EvidenceNumber => edit_text(&mut self.case_metadata.evidence_number, &mut self.cursor_pos, key),
            FormField::Authority => edit_text(&mut self.case_metadata.authority, &mut self.cursor_pos, key),
            FormField::Examiner => edit_text(&mut self.case_metadata.examiner, &mut self.cursor_pos, key),
            FormField::Description => edit_text(&mut self.case_metadata.description, &mut self.cursor_pos, key),
            FormField::Notes => edit_text(&mut self.case_metadata.notes, &mut self.cursor_pos, key),
            FormField::TargetDir => {
                edit_text(&mut self.target_dir_str, &mut self.cursor_pos, key);
                self.config.output_dir = PathBuf::from(&self.target_dir_str);
            }
            FormField::Format => {
                if key.code == KeyCode::Left || key.code == KeyCode::Right || key.code == KeyCode::Char(' ') {
                    self.config.format = match self.config.format {
                        ImageFormat::E01 => ImageFormat::Raw,
                        ImageFormat::Raw => ImageFormat::E01,
                    };
                }
            }
            FormField::SplitSize => {
                if key.code == KeyCode::Left || key.code == KeyCode::Right || key.code == KeyCode::Char(' ') {
                    self.config.split_size = match self.config.split_size {
                        SplitSize::TwoGb => SplitSize::FourGb,
                        SplitSize::FourGb => SplitSize::None,
                        SplitSize::None => SplitSize::TwoGb,
                        SplitSize::Custom(_) => SplitSize::TwoGb,
                    };
                }
            }
            FormField::Compression => {
                if key.code == KeyCode::Left || key.code == KeyCode::Right || key.code == KeyCode::Char(' ') {
                    self.config.compression = match self.config.compression {
                        CompressionLevel::Fast => CompressionLevel::Best,
                        CompressionLevel::Best => CompressionLevel::None,
                        CompressionLevel::None => CompressionLevel::Fast,
                    };
                }
            }
            FormField::HashMd5 => {
                if key.code == KeyCode::Char(' ') || key.code == KeyCode::Left || key.code == KeyCode::Right {
                    self.config.calc_md5 = !self.config.calc_md5;
                }
            }
            FormField::HashSha1 => {
                if key.code == KeyCode::Char(' ') || key.code == KeyCode::Left || key.code == KeyCode::Right {
                    self.config.calc_sha1 = !self.config.calc_sha1;
                }
            }
            FormField::HashSha256 => {
                if key.code == KeyCode::Char(' ') || key.code == KeyCode::Left || key.code == KeyCode::Right {
                    self.config.calc_sha256 = !self.config.calc_sha256;
                }
            }
            FormField::RescueMode => {
                if key.code == KeyCode::Char(' ') || key.code == KeyCode::Left || key.code == KeyCode::Right {
                    self.config.rescue_mode = !self.config.rescue_mode;
                }
            }
            FormField::StartButton => {}
        }
    }

    pub fn start_acquisition(&mut self) {
        let device = match self.selected_device() {
            Some(d) => d.clone(),
            None => return,
        };

        self.config.output_dir = PathBuf::from(&self.target_dir_str);
        if let Err(e) = std::fs::create_dir_all(&self.config.output_dir) {
            self.notification_msg = Some((format!("Cannot create target dir: {}", e), true));
            return;
        }

        self.abort_flag.store(false, Ordering::Relaxed);
        let abort_flag_clone = self.abort_flag.clone();

        let (prog_tx, prog_rx) = mpsc::channel(100);
        let (rep_tx, rep_rx) = mpsc::channel(1);

        self.progress_rx = Some(prog_rx);
        self.report_rx = Some(rep_rx);
        self.telemetry = ProgressTelemetry {
            status: AcquisitionStatus::Preparing,
            total_bytes: device.size_bytes,
            status_message: "Initializing forensic engine...".to_string(),
            ..Default::default()
        };

        let dev_clone = device.clone();
        let case_clone = self.case_metadata.clone();
        let cfg_clone = self.config.clone();

        tokio::spawn(async move {
            let res = if cfg_clone.rescue_mode {
                RescueAcquireEngine::run_rescue(dev_clone, case_clone, cfg_clone, prog_tx, abort_flag_clone).await
            } else {
                EwfAcquireEngine::run_acquisition(dev_clone, case_clone, cfg_clone, prog_tx, abort_flag_clone).await
            };

            let _ = rep_tx.send(res).await;
        });

        self.current_screen = Screen::AcquisitionRunning;
    }

    fn handle_key_acquisition(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)) {
            self.abort_flag.store(true, Ordering::Relaxed);
            self.notification_msg = Some(("Aborting acquisition...".to_string(), true));
        }
    }

    fn handle_key_report(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Enter || key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
            self.current_screen = Screen::DeviceExplorer;
            self.refresh_devices();
        }
    }

    fn handle_key_converter(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.current_screen = Screen::DeviceExplorer;
            }
            KeyCode::Tab => {
                self.conv_to_e01 = !self.conv_to_e01;
            }
            KeyCode::Enter => {
                let src = PathBuf::from(&self.conv_source_path);
                let out = PathBuf::from(&self.conv_target_dir);
                let to_e01 = self.conv_to_e01;

                if !src.exists() {
                    self.conv_status_msg = format!("File not found: {}", src.display());
                    return;
                }

                self.conv_status_msg = "Converting in background...".to_string();
                let abort = Arc::new(AtomicBool::new(false));

                tokio::spawn(async move {
                    if to_e01 {
                        let _ = FormatConverter::raw_to_e01(
                            &src,
                            &out,
                            None,
                            CompressionLevel::Fast,
                            SplitSize::TwoGb,
                            None,
                            Some(abort),
                        )
                        .await;
                    } else {
                        let _ = FormatConverter::e01_to_raw(&src, &out, None, Some(abort)).await;
                    }
                });
            }
            _ => {
                edit_text(&mut self.conv_source_path, &mut self.conv_cursor_pos, key);
            }
        }
    }

    pub fn tick(&mut self) {
        // Poll for progress updates
        if let Some(ref mut rx) = self.progress_rx {
            while let Ok(prog) = rx.try_recv() {
                self.telemetry = prog;
            }
        }

        // Poll for final report completion
        if let Some(ref mut rx) = self.report_rx {
            if let Ok(res) = rx.try_recv() {
                match res {
                    Ok(report) => {
                        self.final_report = Some(report);
                        self.current_screen = Screen::ReportSummary;
                    }
                    Err(e) => {
                        self.notification_msg = Some((format!("Acquisition failed: {}", e), true));
                        self.current_screen = Screen::DeviceExplorer;
                    }
                }
                self.report_rx = None;
                self.progress_rx = None;
            }
        }
    }
}

pub fn edit_text(target: &mut String, cursor: &mut usize, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('u') | KeyCode::Char('k') => {
                target.clear();
                *cursor = 0;
                return;
            }
            KeyCode::Char('w') => {
                // Delete backward word
                if *cursor > 0 {
                    let before = &target[..*cursor];
                    let trimmed = before.trim_end();
                    let new_len = trimmed.rfind(|c: char| c.is_whitespace() || c == '/' || c == '_').map(|i| i + 1).unwrap_or(0);
                    target.replace_range(new_len..*cursor, "");
                    *cursor = new_len;
                }
                return;
            }
            KeyCode::Char('a') => {
                *cursor = 0;
                return;
            }
            KeyCode::Char('e') => {
                *cursor = target.len();
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char(c) => {
            if *cursor >= target.len() {
                target.push(c);
                *cursor = target.len();
            } else {
                target.insert(*cursor, c);
                *cursor += 1;
            }
        }
        KeyCode::Backspace => {
            if *cursor > 0 && !target.is_empty() {
                let remove_idx = *cursor - 1;
                if remove_idx < target.len() {
                    target.remove(remove_idx);
                    *cursor -= 1;
                }
            }
        }
        KeyCode::Delete => {
            if *cursor < target.len() {
                target.remove(*cursor);
            }
        }
        KeyCode::Left => {
            *cursor = cursor.saturating_sub(1);
        }
        KeyCode::Right => {
            if *cursor < target.len() {
                *cursor += 1;
            }
        }
        KeyCode::Home => {
            *cursor = 0;
        }
        KeyCode::End => {
            *cursor = target.len();
        }
        _ => {}
    }
}
