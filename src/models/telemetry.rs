use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionStatus {
    Idle,
    Preparing,
    Imaging,
    Verifying,
    Completed,
    Failed(String),
    Aborted,
}

impl AcquisitionStatus {
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        matches!(
            self,
            AcquisitionStatus::Preparing
                | AcquisitionStatus::Imaging
                | AcquisitionStatus::Verifying
        )
    }

    pub fn display_str(&self) -> &'static str {
        match self {
            AcquisitionStatus::Idle => "IDLE",
            AcquisitionStatus::Preparing => "PREPARING",
            AcquisitionStatus::Imaging => "ACQUIRING",
            AcquisitionStatus::Verifying => "VERIFYING",
            AcquisitionStatus::Completed => "COMPLETED",
            AcquisitionStatus::Failed(_) => "FAILED",
            AcquisitionStatus::Aborted => "ABORTED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressTelemetry {
    pub status: AcquisitionStatus,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub percentage: f64,
    pub speed_bps: f64,
    pub avg_speed_bps: f64,
    pub eta_secs: Option<u64>,
    pub elapsed_secs: u64,
    pub bad_sectors: u64,
    pub compression_ratio: Option<f64>,
    pub current_segment: String,
    pub status_message: String,
    pub log_messages: Vec<String>,
}

impl Default for ProgressTelemetry {
    fn default() -> Self {
        Self {
            status: AcquisitionStatus::Idle,
            bytes_processed: 0,
            total_bytes: 0,
            percentage: 0.0,
            speed_bps: 0.0,
            avg_speed_bps: 0.0,
            eta_secs: None,
            elapsed_secs: 0,
            bad_sectors: 0,
            compression_ratio: None,
            current_segment: String::new(),
            status_message: "Ready to start acquisition".to_string(),
            log_messages: Vec::new(),
        }
    }
}

impl ProgressTelemetry {
    pub fn human_speed(&self) -> String {
        let mbs = self.speed_bps / (1024.0 * 1024.0);
        if mbs >= 1000.0 {
            format!("{:.2} GB/s", mbs / 1024.0)
        } else {
            format!("{:.1} MB/s", mbs)
        }
    }

    pub fn human_avg_speed(&self) -> String {
        let mbs = self.avg_speed_bps / (1024.0 * 1024.0);
        if mbs >= 1000.0 {
            format!("{:.2} GB/s", mbs / 1024.0)
        } else {
            format!("{:.1} MB/s", mbs)
        }
    }

    pub fn human_eta(&self) -> String {
        match self.eta_secs {
            Some(secs) => format_duration(secs),
            None => "--:--:--".to_string(),
        }
    }

    pub fn human_elapsed(&self) -> String {
        format_duration(self.elapsed_secs)
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        let text = msg.into();
        self.status_message = text.clone();
        self.log_messages.push(text);
        if self.log_messages.len() > 200 {
            self.log_messages.remove(0);
        }
    }
}

pub fn format_duration(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}
