//! Progress of a running acquisition, sent from the engine to the UI.
//!
//! Updates are deltas for the log: a producer sends
//! [`ProgressTelemetry::take_update`] (which hands over the log lines added
//! since the previous update) and a consumer merges with
//! [`ProgressTelemetry::apply_update`], so the log accumulates instead of being
//! replaced by each update.

use crate::models::outcome::Outcome;
use serde::{Deserialize, Serialize};

/// Most log lines a consumer keeps.
pub const MAX_LOG_LINES: usize = 1000;

/// State of an acquisition; the running states are its phases in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionStatus {
    Idle,
    /// Validation, identity, safety and destination checks
    Preparing,
    /// Reading the source and writing the image
    Acquiring,
    /// fsync of image and auxiliary files, cache eviction
    Flushing,
    /// Re-reading the written image
    Verifying,
    /// Second read of the source (`--verify-source`)
    SourceReread,
    /// Classification, reports, audit
    Finalizing,
    /// Finished with a report (see `ProgressTelemetry::outcome`)
    Completed,
    /// Ended without a report
    Failed(String),
    Aborted,
}

impl AcquisitionStatus {
    pub fn is_running(&self) -> bool {
        matches!(
            self,
            AcquisitionStatus::Preparing
                | AcquisitionStatus::Acquiring
                | AcquisitionStatus::Flushing
                | AcquisitionStatus::Verifying
                | AcquisitionStatus::SourceReread
                | AcquisitionStatus::Finalizing
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            AcquisitionStatus::Completed
                | AcquisitionStatus::Failed(_)
                | AcquisitionStatus::Aborted
        )
    }

    pub fn display_str(&self) -> &'static str {
        match self {
            AcquisitionStatus::Idle => "IDLE",
            AcquisitionStatus::Preparing => "PREPARING",
            AcquisitionStatus::Acquiring => "ACQUIRING",
            AcquisitionStatus::Flushing => "FLUSHING",
            AcquisitionStatus::Verifying => "VERIFYING",
            AcquisitionStatus::SourceReread => "SOURCE RE-READ",
            AcquisitionStatus::Finalizing => "FINALIZING",
            AcquisitionStatus::Completed => "COMPLETED",
            AcquisitionStatus::Failed(_) => "FAILED",
            AcquisitionStatus::Aborted => "ABORTED",
        }
    }
}

/// Progress of one read pass after the acquisition (image verification or
/// the second source read), kept apart from the acquisition progress.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PhaseProgress {
    pub bytes_done: u64,
    pub total_bytes: u64,
    pub percentage: f64,
    pub speed_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressTelemetry {
    pub status: AcquisitionStatus,
    /// Acquisition pass: bytes of the source processed
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
    /// Producer side: lines not yet sent. Consumer side: the accumulated log.
    pub log_messages: Vec<String>,
    /// Verification or source re-read pass, while one runs
    #[serde(default)]
    pub verify_progress: Option<PhaseProgress>,
    /// Set with `Completed`
    #[serde(default)]
    pub outcome: Option<Outcome>,
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
            verify_progress: None,
            outcome: None,
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

    /// Add a log line (also the current status message).
    pub fn push_log(&mut self, msg: impl Into<String>) {
        let text = msg.into();
        self.status_message = text.clone();
        self.log_messages.push(text);
        if self.log_messages.len() > MAX_LOG_LINES {
            let excess = self.log_messages.len() - MAX_LOG_LINES;
            self.log_messages.drain(..excess);
        }
    }

    /// Producer: an update to send, carrying the log lines added since the
    /// previous update (they are handed over, not repeated).
    pub fn take_update(&mut self) -> ProgressTelemetry {
        let mut update = self.clone();
        update.log_messages = std::mem::take(&mut self.log_messages);
        update
    }

    /// Consumer: take every field of `update` and append its log lines.
    pub fn apply_update(&mut self, update: ProgressTelemetry) {
        let mut log = std::mem::take(&mut self.log_messages);
        log.extend(update.log_messages.iter().cloned());
        if log.len() > MAX_LOG_LINES {
            let excess = log.len() - MAX_LOG_LINES;
            log.drain(..excess);
        }
        *self = ProgressTelemetry {
            log_messages: log,
            ..update
        };
    }
}

pub fn format_duration(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_accumulate_across_updates() {
        let mut producer = ProgressTelemetry::default();
        let mut consumer = ProgressTelemetry::default();

        producer.push_log("first");
        producer.push_log("second");
        consumer.apply_update(producer.take_update());
        // A progress-only update must not wipe the log
        producer.percentage = 50.0;
        consumer.apply_update(producer.take_update());
        // An engine that builds fresh telemetry for progress does not either
        consumer.apply_update(ProgressTelemetry {
            status: AcquisitionStatus::Acquiring,
            percentage: 60.0,
            ..Default::default()
        });
        producer.push_log("third");
        consumer.apply_update(producer.take_update());

        assert_eq!(consumer.log_messages, ["first", "second", "third"]);
        assert_eq!(consumer.status_message, "third");
        assert_eq!(consumer.percentage, 50.0);
        assert!(producer.log_messages.is_empty());
    }

    #[test]
    fn log_is_bounded() {
        let mut consumer = ProgressTelemetry::default();
        for i in 0..(MAX_LOG_LINES + 10) {
            let mut u = ProgressTelemetry::default();
            u.push_log(format!("line {i}"));
            consumer.apply_update(u);
        }
        assert_eq!(consumer.log_messages.len(), MAX_LOG_LINES);
        assert_eq!(consumer.log_messages[0], "line 10");
    }

    #[test]
    fn phases_are_ordered_states() {
        for s in [
            AcquisitionStatus::Preparing,
            AcquisitionStatus::Acquiring,
            AcquisitionStatus::Flushing,
            AcquisitionStatus::Verifying,
            AcquisitionStatus::SourceReread,
            AcquisitionStatus::Finalizing,
        ] {
            assert!(s.is_running(), "{s:?}");
            assert!(!s.is_terminal());
        }
        assert!(AcquisitionStatus::Completed.is_terminal());
        assert!(AcquisitionStatus::Failed("x".into()).is_terminal());
        assert_eq!(
            AcquisitionStatus::SourceReread.display_str(),
            "SOURCE RE-READ"
        );
    }
}
