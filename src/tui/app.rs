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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConverterField {
    SourcePath,
    Mode,
    TargetDir,
    StartButton,
}

impl ConverterField {
    pub fn all() -> &'static [ConverterField] {
        &[
            ConverterField::SourcePath,
            ConverterField::Mode,
            ConverterField::TargetDir,
            ConverterField::StartButton,
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
    pub conv_active_field: usize,
    pub conv_source_path: String,
    pub conv_cursor_pos: usize,
    pub conv_target_dir: String,
    pub conv_to_e01: bool,
    pub conv_status_msg: String,
    pub conv_rx: Option<mpsc::Receiver<Result<PathBuf, String>>>,

    // Autocomplete State
    pub autocomplete_state: Option<crate::tui::autocomplete::PathAutocompleteState>,

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
            conv_active_field: 0,
            conv_source_path: "".to_string(),
            conv_cursor_pos: 0,
            conv_target_dir: target_dir.to_string_lossy().to_string(),
            conv_to_e01: true,
            conv_status_msg: "Ready to convert images.".to_string(),
            conv_rx: None,
            autocomplete_state: None,
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
                        self.notification_msg =
                            Some(("Device is already unmounted.".to_string(), false));
                    }
                }
            }
            KeyCode::Char('c') | KeyCode::F(7) => {
                self.current_screen = Screen::Converter;
                self.conv_active_field = 0;
                self.conv_cursor_pos = self.conv_source_path.len();
                self.autocomplete_state = None;
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
        self.autocomplete_state = None;
    }

    fn reset_converter_cursor(&mut self) {
        let fields = ConverterField::all();
        let cur_field = fields[self.conv_active_field % fields.len()];
        let len = match cur_field {
            ConverterField::SourcePath => self.conv_source_path.len(),
            ConverterField::TargetDir => self.conv_target_dir.len(),
            _ => 0,
        };
        self.conv_cursor_pos = len;
        self.autocomplete_state = None;
    }

    fn handle_key_unmount_prompt(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                if let Some(dev) = self.selected_device() {
                    match SafetyChecker::unmount_all(&dev.mountpoints) {
                        Ok(()) => {
                            self.notification_msg =
                                Some(("Device successfully unmounted.".to_string(), false));
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

        if key.code != KeyCode::Tab {
            self.autocomplete_state = None;
        }

        match key.code {
            KeyCode::Esc => {
                self.current_screen = Screen::DeviceExplorer;
            }
            KeyCode::Tab => {
                if *cur_field == FormField::TargetDir {
                    self.autocomplete_case_target_dir();
                } else {
                    self.active_field = (self.active_field + 1) % fields.len();
                    self.reset_cursor_to_current_field();
                }
            }
            KeyCode::Down => {
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
            FormField::CaseNumber => edit_text(
                &mut self.case_metadata.case_number,
                &mut self.cursor_pos,
                key,
            ),
            FormField::LocationEa => edit_text(
                &mut self.case_metadata.location_ea,
                &mut self.cursor_pos,
                key,
            ),
            FormField::EvidenceNumber => edit_text(
                &mut self.case_metadata.evidence_number,
                &mut self.cursor_pos,
                key,
            ),
            FormField::Authority => {
                edit_text(&mut self.case_metadata.authority, &mut self.cursor_pos, key)
            }
            FormField::Examiner => {
                edit_text(&mut self.case_metadata.examiner, &mut self.cursor_pos, key)
            }
            FormField::Description => edit_text(
                &mut self.case_metadata.description,
                &mut self.cursor_pos,
                key,
            ),
            FormField::Notes => edit_text(&mut self.case_metadata.notes, &mut self.cursor_pos, key),
            FormField::TargetDir => {
                edit_text(&mut self.target_dir_str, &mut self.cursor_pos, key);
                self.config.output_dir = PathBuf::from(&self.target_dir_str);
            }
            FormField::Format => {
                if key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                    || key.code == KeyCode::Char(' ')
                {
                    self.config.format = match self.config.format {
                        ImageFormat::E01 => ImageFormat::Raw,
                        ImageFormat::Raw => ImageFormat::E01,
                    };
                }
            }
            FormField::SplitSize => {
                if key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                    || key.code == KeyCode::Char(' ')
                {
                    self.config.split_size = match self.config.split_size {
                        SplitSize::TwoGb => SplitSize::FourGb,
                        SplitSize::FourGb => SplitSize::None,
                        SplitSize::None => SplitSize::TwoGb,
                        SplitSize::Custom(_) => SplitSize::TwoGb,
                    };
                }
            }
            FormField::Compression => {
                if key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                    || key.code == KeyCode::Char(' ')
                {
                    self.config.compression = match self.config.compression {
                        CompressionLevel::Fast => CompressionLevel::Best,
                        CompressionLevel::Best => CompressionLevel::None,
                        CompressionLevel::None => CompressionLevel::Fast,
                    };
                }
            }
            FormField::HashMd5 => {
                if key.code == KeyCode::Char(' ')
                    || key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                {
                    self.config.calc_md5 = !self.config.calc_md5;
                }
            }
            FormField::HashSha1 => {
                if key.code == KeyCode::Char(' ')
                    || key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                {
                    self.config.calc_sha1 = !self.config.calc_sha1;
                }
            }
            FormField::HashSha256 => {
                if key.code == KeyCode::Char(' ')
                    || key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                {
                    self.config.calc_sha256 = !self.config.calc_sha256;
                }
            }
            FormField::RescueMode => {
                if key.code == KeyCode::Char(' ')
                    || key.code == KeyCode::Left
                    || key.code == KeyCode::Right
                {
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

        self.config.output_dir = crate::tui::autocomplete::expand_tilde(std::path::Path::new(self.target_dir_str.trim()));
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
                RescueAcquireEngine::run_rescue(
                    dev_clone,
                    case_clone,
                    cfg_clone,
                    prog_tx,
                    abort_flag_clone,
                )
                .await
            } else {
                EwfAcquireEngine::run_acquisition(
                    dev_clone,
                    case_clone,
                    cfg_clone,
                    prog_tx,
                    abort_flag_clone,
                )
                .await
            };

            let _ = rep_tx.send(res).await;
        });

        self.current_screen = Screen::AcquisitionRunning;
    }

    fn handle_key_acquisition(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            self.abort_flag.store(true, Ordering::Relaxed);
            self.notification_msg = Some(("Aborting acquisition...".to_string(), true));
        }
    }

    fn handle_key_report(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Enter || key.code == KeyCode::Esc || key.code == KeyCode::Char('q')
        {
            self.current_screen = Screen::DeviceExplorer;
            self.refresh_devices();
        }
    }

    fn handle_key_converter(&mut self, key: KeyEvent) {
        let fields = ConverterField::all();
        let cur_field = fields[self.conv_active_field % fields.len()];

        if key.code != KeyCode::Tab {
            self.autocomplete_state = None;
        }

        match key.code {
            KeyCode::Esc => {
                self.current_screen = Screen::DeviceExplorer;
            }
            KeyCode::F(5) => {
                self.start_conversion();
            }
            KeyCode::Down => {
                self.conv_active_field = (self.conv_active_field + 1) % fields.len();
                self.reset_converter_cursor();
            }
            KeyCode::Up | KeyCode::BackTab => {
                if self.conv_active_field == 0 {
                    self.conv_active_field = fields.len() - 1;
                } else {
                    self.conv_active_field -= 1;
                }
                self.reset_converter_cursor();
            }
            KeyCode::Tab => {
                match cur_field {
                    ConverterField::SourcePath => {
                        self.autocomplete_conv_source();
                    }
                    ConverterField::TargetDir => {
                        self.autocomplete_conv_target();
                    }
                    ConverterField::Mode => {
                        self.conv_active_field = (self.conv_active_field + 1) % fields.len();
                        self.reset_converter_cursor();
                    }
                    ConverterField::StartButton => {
                        self.conv_active_field = (self.conv_active_field + 1) % fields.len();
                        self.reset_converter_cursor();
                    }
                }
            }
            KeyCode::Enter => {
                match cur_field {
                    ConverterField::StartButton => {
                        self.start_conversion();
                    }
                    ConverterField::Mode => {
                        self.conv_to_e01 = !self.conv_to_e01;
                    }
                    _ => {
                        self.conv_active_field = (self.conv_active_field + 1) % fields.len();
                        self.reset_converter_cursor();
                    }
                }
            }
            _ => {
                match cur_field {
                    ConverterField::SourcePath => {
                        edit_text(&mut self.conv_source_path, &mut self.conv_cursor_pos, key);
                        self.auto_detect_converter_mode();
                    }
                    ConverterField::Mode => {
                        if key.code == KeyCode::Left
                            || key.code == KeyCode::Right
                            || key.code == KeyCode::Char(' ')
                        {
                            self.conv_to_e01 = !self.conv_to_e01;
                        }
                    }
                    ConverterField::TargetDir => {
                        edit_text(&mut self.conv_target_dir, &mut self.conv_cursor_pos, key);
                    }
                    ConverterField::StartButton => {
                        if key.code == KeyCode::Char(' ') {
                            self.start_conversion();
                        }
                    }
                }
            }
        }
    }

    pub fn auto_detect_converter_mode(&mut self) {
        let lower = self.conv_source_path.trim().to_lowercase();
        if lower.ends_with(".e01") {
            self.conv_to_e01 = false;
        } else if lower.ends_with(".raw")
            || lower.ends_with(".dd")
            || lower.ends_with(".img")
            || lower.ends_with(".bin")
        {
            self.conv_to_e01 = true;
        }
    }

    pub fn autocomplete_conv_source(&mut self) {
        use crate::tui::autocomplete::{complete_path, AutocompleteOutcome};
        if let Some(outcome) = complete_path(
            &self.conv_source_path,
            self.conv_cursor_pos,
            false,
            &mut self.autocomplete_state,
        ) {
            match outcome {
                AutocompleteOutcome::SingleMatch { completed, suffix } => {
                    self.conv_source_path = format!("{}{}", completed, suffix);
                    self.conv_cursor_pos = completed.len();
                    self.conv_status_msg = format!("Completed: {}", completed);
                }
                AutocompleteOutcome::PrefixExtended {
                    common_prefix,
                    suffix,
                    total,
                } => {
                    self.conv_source_path = format!("{}{}", common_prefix, suffix);
                    self.conv_cursor_pos = common_prefix.len();
                    self.conv_status_msg =
                        format!("[{} matches] {} (Tab to cycle)", total, common_prefix);
                }
                AutocompleteOutcome::Cycled {
                    candidate,
                    suffix,
                    index,
                    total,
                } => {
                    self.conv_source_path = format!("{}{}", candidate, suffix);
                    self.conv_cursor_pos = candidate.len();
                    self.conv_status_msg =
                        format!("[{}/{}] {} (Tab for next)", index, total, candidate);
                }
                AutocompleteOutcome::NoMatches => {
                    self.conv_status_msg =
                        "No matching files or directories found.".to_string();
                }
            }
            self.auto_detect_converter_mode();
        }
    }

    pub fn autocomplete_conv_target(&mut self) {
        use crate::tui::autocomplete::{complete_path, AutocompleteOutcome};
        if let Some(outcome) = complete_path(
            &self.conv_target_dir,
            self.conv_cursor_pos,
            true,
            &mut self.autocomplete_state,
        ) {
            match outcome {
                AutocompleteOutcome::SingleMatch { completed, suffix } => {
                    self.conv_target_dir = format!("{}{}", completed, suffix);
                    self.conv_cursor_pos = completed.len();
                    self.conv_status_msg = format!("Completed: {}", completed);
                }
                AutocompleteOutcome::PrefixExtended {
                    common_prefix,
                    suffix,
                    total,
                } => {
                    self.conv_target_dir = format!("{}{}", common_prefix, suffix);
                    self.conv_cursor_pos = common_prefix.len();
                    self.conv_status_msg =
                        format!("[{} matches] {} (Tab to cycle)", total, common_prefix);
                }
                AutocompleteOutcome::Cycled {
                    candidate,
                    suffix,
                    index,
                    total,
                } => {
                    self.conv_target_dir = format!("{}{}", candidate, suffix);
                    self.conv_cursor_pos = candidate.len();
                    self.conv_status_msg =
                        format!("[{}/{}] {} (Tab for next)", index, total, candidate);
                }
                AutocompleteOutcome::NoMatches => {
                    self.conv_status_msg = "No matching directories found.".to_string();
                }
            }
        }
    }

    pub fn autocomplete_case_target_dir(&mut self) {
        use crate::tui::autocomplete::{complete_path, AutocompleteOutcome};
        if let Some(outcome) = complete_path(
            &self.target_dir_str,
            self.cursor_pos,
            true,
            &mut self.autocomplete_state,
        ) {
            let (msg, is_err) = match outcome {
                AutocompleteOutcome::SingleMatch { completed, suffix } => {
                    self.target_dir_str = format!("{}{}", completed, suffix);
                    self.cursor_pos = completed.len();
                    self.config.output_dir = crate::tui::autocomplete::expand_tilde(
                        std::path::Path::new(&self.target_dir_str),
                    );
                    (format!("Path completed: {}", completed), false)
                }
                AutocompleteOutcome::PrefixExtended {
                    common_prefix,
                    suffix,
                    total,
                } => {
                    self.target_dir_str = format!("{}{}", common_prefix, suffix);
                    self.cursor_pos = common_prefix.len();
                    self.config.output_dir = crate::tui::autocomplete::expand_tilde(
                        std::path::Path::new(&self.target_dir_str),
                    );
                    (
                        format!("[{} matches] {} (Tab to cycle)", total, common_prefix),
                        false,
                    )
                }
                AutocompleteOutcome::Cycled {
                    candidate,
                    suffix,
                    index,
                    total,
                } => {
                    self.target_dir_str = format!("{}{}", candidate, suffix);
                    self.cursor_pos = candidate.len();
                    self.config.output_dir = crate::tui::autocomplete::expand_tilde(
                        std::path::Path::new(&self.target_dir_str),
                    );
                    (
                        format!("[{}/{}] {} (Tab for next)", index, total, candidate),
                        false,
                    )
                }
                AutocompleteOutcome::NoMatches => {
                    ("No matching directories found.".to_string(), true)
                }
            };
            self.notification_msg = Some((msg, is_err));
        }
    }

    pub fn start_conversion(&mut self) {
        let src_trimmed = self.conv_source_path.trim();
        let out_trimmed = self.conv_target_dir.trim();

        if src_trimmed.is_empty() {
            self.conv_status_msg = "Please specify a source image path.".to_string();
            return;
        }

        let src = crate::tui::autocomplete::expand_tilde(std::path::Path::new(src_trimmed));
        let out = crate::tui::autocomplete::expand_tilde(std::path::Path::new(out_trimmed));
        let to_e01 = self.conv_to_e01;

        if !src.exists() {
            self.conv_status_msg = format!("File not found: {}", src.display());
            return;
        }

        if !out.exists() {
            if let Err(e) = std::fs::create_dir_all(&out) {
                self.conv_status_msg = format!("Failed to create destination dir: {}", e);
                return;
            }
        } else if !out.is_dir() {
            self.conv_status_msg = format!(
                "Destination path is a file, not a directory: {}",
                out.display()
            );
            return;
        }

        if self.conv_rx.is_some() {
            self.conv_status_msg = "A conversion is already in progress...".to_string();
            return;
        }

        self.conv_status_msg = "Converting in background...".to_string();
        let abort = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(1);
        self.conv_rx = Some(rx);

        tokio::spawn(async move {
            let res = if to_e01 {
                FormatConverter::raw_to_e01(
                    &src,
                    &out,
                    None,
                    CompressionLevel::Fast,
                    SplitSize::TwoGb,
                    None,
                    Some(abort),
                )
                .await
            } else {
                FormatConverter::e01_to_raw(&src, &out, None, Some(abort)).await
            };
            let _ = tx.send(res).await;
        });
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

        // Poll for conversion completion
        if let Some(ref mut rx) = self.conv_rx {
            if let Ok(res) = rx.try_recv() {
                match res {
                    Ok(path) => {
                        self.conv_status_msg = format!("Conversion complete: {}", path.display());
                    }
                    Err(e) => {
                        self.conv_status_msg = format!("Conversion failed: {}", e);
                    }
                }
                self.conv_rx = None;
            }
        }
    }
}

pub fn edit_text(target: &mut String, cursor: &mut usize, key: KeyEvent) {
    // Clamp cursor and align to valid character boundary
    if *cursor > target.len() {
        *cursor = target.len();
    }
    while *cursor > 0 && !target.is_char_boundary(*cursor) {
        *cursor -= 1;
    }

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
                    // Skip any trailing delimiters
                    let last_non_delim = before
                        .char_indices()
                        .rfind(|&(_, c)| !c.is_whitespace() && c != '/' && c != '_');

                    if let Some((idx, c)) = last_non_delim {
                        let word_end = idx + c.len_utf8();
                        let before_word = &before[..word_end];
                        let new_len = before_word
                            .char_indices()
                            .filter(|&(_, ch)| ch.is_whitespace() || ch == '/' || ch == '_')
                            .map(|(i, ch)| i + ch.len_utf8())
                            .next_back()
                            .unwrap_or(0);
                        target.replace_range(new_len..*cursor, "");
                        *cursor = new_len;
                    } else {
                        target.replace_range(0..*cursor, "");
                        *cursor = 0;
                    }
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
                *cursor += c.len_utf8();
            }
        }
        KeyCode::Backspace => {
            if *cursor > 0 && !target.is_empty() {
                if let Some((prev_idx, _)) = target[..*cursor].char_indices().next_back() {
                    target.remove(prev_idx);
                    *cursor = prev_idx;
                }
            }
        }
        KeyCode::Delete => {
            if *cursor < target.len() {
                target.remove(*cursor);
            }
        }
        KeyCode::Left => {
            if *cursor > 0 {
                if let Some((prev_idx, _)) = target[..*cursor].char_indices().next_back() {
                    *cursor = prev_idx;
                } else {
                    *cursor = 0;
                }
            }
        }
        KeyCode::Right => {
            if *cursor < target.len() {
                if let Some((next_offset, _)) = target[*cursor..].char_indices().nth(1) {
                    *cursor += next_offset;
                } else {
                    *cursor = target.len();
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn test_edit_text_multibyte_insert_and_cursor() {
        let mut s = String::new();
        let mut cursor = 0;

        // Insert 'ä' (2 bytes)
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('ä')));
        assert_eq!(s, "ä");
        assert_eq!(cursor, 2);

        // Insert '世' (3 bytes)
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('世')));
        assert_eq!(s, "ä世");
        assert_eq!(cursor, 5);

        // Insert '🚀' (4 bytes)
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('🚀')));
        assert_eq!(s, "ä世🚀");
        assert_eq!(cursor, 9);
    }

    #[test]
    fn test_edit_text_multibyte_navigation_and_deletion() {
        let mut s = "ä世🚀".to_string(); // lengths: 2, 3, 4 -> byte offsets: 0, 2, 5, 9
        let mut cursor = 9;

        // Move Left over 🚀
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 5);

        // Move Left over 世
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 2);

        // Move Left over ä
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 0);

        // Move Left at 0 does not underflow
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 0);

        // Move Right over ä
        edit_text(&mut s, &mut cursor, key(KeyCode::Right));
        assert_eq!(cursor, 2);

        // Backspace over ä
        edit_text(&mut s, &mut cursor, key(KeyCode::Backspace));
        assert_eq!(s, "世🚀");
        assert_eq!(cursor, 0);

        // Delete 世
        edit_text(&mut s, &mut cursor, key(KeyCode::Delete));
        assert_eq!(s, "🚀");
        assert_eq!(cursor, 0);
    }

    #[test]
    fn test_edit_text_ctrl_w_multibyte() {
        let mut s = "case_01/prüf_daten/e01".to_string();
        let mut cursor = s.len();

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "case_01/prüf_daten/");
        assert_eq!(cursor, s.len());

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "case_01/prüf_");
        assert_eq!(cursor, s.len());

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "case_01/");
        assert_eq!(cursor, s.len());
    }

    #[test]
    fn test_edit_text_stress_adversarial() {
        let s = "ä世🚀".to_string(); // byte length: 2 + 3 + 4 = 9 bytes

        // Test cursor alignment and navigation from EVERY byte index (including interior invalid indices)
        for invalid_cursor in 0..=s.len() + 3 {
            let mut cur = invalid_cursor;
            let mut s_copy = s.clone();
            edit_text(&mut s_copy, &mut cur, key(KeyCode::Left));
            assert!(
                s_copy.is_char_boundary(cur),
                "Cursor must be on char boundary after Left from {}",
                invalid_cursor
            );

            let mut cur = invalid_cursor;
            let mut s_copy = s.clone();
            edit_text(&mut s_copy, &mut cur, key(KeyCode::Right));
            assert!(
                s_copy.is_char_boundary(cur),
                "Cursor must be on char boundary after Right from {}",
                invalid_cursor
            );

            let mut cur = invalid_cursor;
            let mut s_copy = s.clone();
            edit_text(&mut s_copy, &mut cur, key(KeyCode::Backspace));
            assert!(
                s_copy.is_char_boundary(cur),
                "Cursor must be on char boundary after Backspace from {}",
                invalid_cursor
            );

            let mut cur = invalid_cursor;
            let mut s_copy = s.clone();
            edit_text(&mut s_copy, &mut cur, key(KeyCode::Delete));
            assert!(
                s_copy.is_char_boundary(cur),
                "Cursor must be on char boundary after Delete from {}",
                invalid_cursor
            );

            let mut cur = invalid_cursor;
            let mut s_copy = s.clone();
            edit_text(&mut s_copy, &mut cur, ctrl_key(KeyCode::Char('w')));
            assert!(
                s_copy.is_char_boundary(cur),
                "Cursor must be on char boundary after Ctrl+W from {}",
                invalid_cursor
            );
        }
    }

    #[test]
    fn test_edit_text_insert_at_all_positions() {
        let chars_to_insert = ['a', 'ß', '€', '🔥', '世'];
        for &c in &chars_to_insert {
            let mut s = "123".to_string();
            let mut cur = 0;
            edit_text(&mut s, &mut cur, key(KeyCode::Char(c)));
            assert_eq!(cur, c.len_utf8());
            assert!(s.starts_with(c));

            // Insert in middle
            edit_text(&mut s, &mut cur, key(KeyCode::Char('X')));
            assert!(s.is_char_boundary(cur));

            // Insert at end
            cur = s.len();
            edit_text(&mut s, &mut cur, key(KeyCode::Char(c)));
            assert_eq!(cur, s.len());
            assert!(s.ends_with(c));
        }
    }

    #[test]
    fn test_edit_text_ctrl_w_deep() {
        // Path with mixed unicode and multiple delimiters
        let mut s = "/var/log/ケース_01/データ/image.raw".to_string();
        let mut cursor = s.len();

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "/var/log/ケース_01/データ/");
        assert_eq!(cursor, s.len());

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "/var/log/ケース_01/");
        assert_eq!(cursor, s.len());

        // Underscore is a delimiter, so next Ctrl+W deletes "01/" leaving "/var/log/ケース_"
        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "/var/log/ケース_");
        assert_eq!(cursor, s.len());

        // Next Ctrl+W deletes "ケース_" leaving "/var/log/"
        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "/var/log/");
        assert_eq!(cursor, s.len());

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "/var/");
        assert_eq!(cursor, s.len());

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "/");
        assert_eq!(cursor, s.len());

        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s, "");
        assert_eq!(cursor, 0);

        // Edge case: string of only delimiters
        let mut s_delim = "/// ___   ///".to_string();
        let mut cur_delim = s_delim.len();
        edit_text(&mut s_delim, &mut cur_delim, ctrl_key(KeyCode::Char('w')));
        assert_eq!(s_delim, "");
        assert_eq!(cur_delim, 0);
    }

    #[test]
    fn test_converter_navigation_and_editing() {
        let mut app = App::new();
        // Switch to Converter screen
        app.handle_key(key(KeyCode::Char('c')));
        assert_eq!(app.current_screen, Screen::Converter);
        assert_eq!(app.conv_active_field, 0); // SourcePath

        // Type source path
        for c in "image.raw".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.conv_source_path, "image.raw");
        assert_eq!(app.conv_to_e01, true); // Auto-detected RAW -> E01

        // Move to Conversion Mode
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.conv_active_field, 1);

        // Toggle mode using Space
        app.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(app.conv_to_e01, false);
        // Toggle mode using Enter
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.conv_to_e01, true);

        // Move to Destination Dir
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.conv_active_field, 2);

        // Clear Destination Dir with Ctrl+U
        app.handle_key(ctrl_key(KeyCode::Char('u')));
        assert_eq!(app.conv_target_dir, "");

        // Type a new Destination Dir
        for c in "/cases/output_dir".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.conv_target_dir, "/cases/output_dir");

        // Move to StartButton
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.conv_active_field, 3);

        // Up arrow moves back to Destination Dir
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.conv_active_field, 2);

        // BackTab moves back to Mode
        app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.conv_active_field, 1);

        // BackTab moves back to SourcePath
        app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.conv_active_field, 0);
    }

    #[test]
    fn test_converter_mode_auto_detection() {
        let mut app = App::new();
        app.conv_source_path = "/tmp/suspect.E01".to_string();
        app.auto_detect_converter_mode();
        assert_eq!(app.conv_to_e01, false);

        app.conv_source_path = "/tmp/suspect.dd".to_string();
        app.auto_detect_converter_mode();
        assert_eq!(app.conv_to_e01, true);

        app.conv_source_path = "/tmp/suspect.img".to_string();
        app.auto_detect_converter_mode();
        assert_eq!(app.conv_to_e01, true);
    }

    #[test]
    fn test_path_autocomplete_in_app() {
        let temp = std::env::temp_dir().join(format!("dfdisk_app_ac_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(temp.join("subdir1")).unwrap();
        std::fs::create_dir_all(temp.join("subdir2")).unwrap();
        std::fs::File::create(temp.join("file.raw")).unwrap();

        let temp_str = temp.to_string_lossy().to_string();

        let mut app = App::new();
        app.current_screen = Screen::Converter;

        // 1. Autocomplete Destination Dir (dirs only)
        app.conv_active_field = 2; // TargetDir
        app.conv_target_dir = format!("{}/sub", temp_str);
        app.conv_cursor_pos = app.conv_target_dir.len();

        // First Tab expands prefix to common prefix
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.conv_target_dir, format!("{}/subdir", temp_str));

        // Next Tab cycles to subdir1/
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.conv_target_dir, format!("{}/subdir1/", temp_str));

        // Next Tab cycles to subdir2/
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.conv_target_dir, format!("{}/subdir2/", temp_str));

        // 2. Autocomplete Source Image Path (files + dirs)
        app.conv_active_field = 0; // SourcePath
        app.conv_source_path = format!("{}/fi", temp_str);
        app.conv_cursor_pos = app.conv_source_path.len();

        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.conv_source_path, format!("{}/file.raw", temp_str));

        let _ = std::fs::remove_dir_all(&temp);
    }
}
