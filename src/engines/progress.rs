//! Progress of a running acquisition, from the session and its engine to the
//! CLI or TUI ([`ProgressSink`]).
//!
//! The sink never blocks the acquisition: updates are forwarded with
//! `try_send`; when the consumer is slow, the newest state is kept and the
//! log lines accumulate (bounded) until the next update gets through. Warnings
//! go through the sink, never to stderr, because a TUI may own the terminal.
//! The sink is `Clone + Send + Sync`, so engines use it from blocking threads
//! too.

use crate::models::outcome::Outcome;
use crate::models::telemetry::{
    AcquisitionStatus, PhaseProgress, ProgressTelemetry, MAX_LOG_LINES,
};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{SendTimeoutError, TrySendError};

/// How long the final update of a run waits for a full channel.
const FINAL_SEND_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct SinkInner {
    tx: Option<mpsc::Sender<ProgressTelemetry>>,
    /// Current state; `log_messages` holds the lines not delivered yet
    state: ProgressTelemetry,
    /// Every warning, for the report and tests
    warnings: Vec<String>,
}

/// Where a session and its engine send progress (§4). Cheap to clone; clones
/// share the state and the channel.
#[derive(Debug, Clone)]
pub struct ProgressSink {
    inner: Arc<Mutex<SinkInner>>,
}

impl ProgressSink {
    /// A sink forwarding to `tx` (the CLI/TUI receiver).
    pub fn new(tx: mpsc::Sender<ProgressTelemetry>) -> Self {
        Self::with(Some(tx))
    }

    /// A sink without a receiver (tests, headless callers): state and
    /// warnings are kept, nothing is sent.
    pub fn disconnected() -> Self {
        Self::with(None)
    }

    fn with(tx: Option<mpsc::Sender<ProgressTelemetry>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SinkInner {
                tx,
                state: ProgressTelemetry::default(),
                warnings: Vec::new(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SinkInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Deliver the current state if the channel has room; otherwise keep it
    /// (log lines included) for the next attempt.
    fn forward(inner: &mut SinkInner) {
        let Some(tx) = inner.tx.as_ref() else {
            cap_log(&mut inner.state.log_messages);
            return;
        };
        match tx.try_send(inner.state.take_update()) {
            Ok(()) => {}
            Err(TrySendError::Full(update)) => {
                // Put the undelivered lines back in front of any newer ones
                let mut lines = update.log_messages;
                lines.append(&mut inner.state.log_messages);
                cap_log(&mut lines);
                inner.state.log_messages = lines;
            }
            Err(TrySendError::Closed(_)) => {
                inner.tx = None;
            }
        }
    }

    /// Merge an engine's update (produced with
    /// [`ProgressTelemetry::take_update`]: every field, plus the log lines
    /// added since its previous update) and forward it.
    pub fn send(&self, update: ProgressTelemetry) {
        let mut inner = self.lock();
        let mut lines = std::mem::take(&mut inner.state.log_messages);
        lines.extend(update.log_messages.iter().cloned());
        cap_log(&mut lines);
        inner.state = ProgressTelemetry {
            log_messages: lines,
            ..update
        };
        Self::forward(&mut inner);
    }

    /// Edit the current state, then forward it.
    pub fn update(&self, f: impl FnOnce(&mut ProgressTelemetry)) {
        let mut inner = self.lock();
        f(&mut inner.state);
        Self::forward(&mut inner);
    }

    /// Add a log line (also the status message).
    pub fn log(&self, line: impl Into<String>) {
        let line = line.into();
        self.update(|t| t.push_log(line));
    }

    /// A warning the examiner must see: logged as "WARNING: ..." and kept
    /// (see [`warnings`](Self::warnings)).
    pub fn warn(&self, line: impl Into<String>) {
        let line = format!("WARNING: {}", line.into());
        let mut inner = self.lock();
        inner.warnings.push(line.clone());
        inner.state.push_log(line);
        Self::forward(&mut inner);
    }

    /// Enter a phase: status, message (logged), and a fresh phase gauge for
    /// the post-acquisition read passes.
    pub fn phase(&self, status: AcquisitionStatus, message: impl Into<String>) {
        let message = message.into();
        self.update(|t| {
            t.verify_progress = match status {
                AcquisitionStatus::Verifying | AcquisitionStatus::SourceReread => {
                    Some(PhaseProgress::default())
                }
                _ => None,
            };
            t.status = status;
            t.push_log(message);
        });
    }

    /// Progress of the current read pass after the acquisition
    /// (verification or second source read).
    pub fn phase_progress(&self, bytes_done: u64, total_bytes: u64, speed_bps: f64) {
        self.update(|t| {
            let percentage = if total_bytes > 0 {
                (bytes_done as f64 * 100.0 / total_bytes as f64).min(100.0)
            } else {
                100.0
            };
            t.verify_progress = Some(PhaseProgress {
                bytes_done,
                total_bytes,
                percentage,
                speed_bps,
            });
        });
    }

    /// The current state (its log holds only undelivered lines).
    pub fn snapshot(&self) -> ProgressTelemetry {
        self.lock().state.clone()
    }

    /// Every warning sent so far.
    pub fn warnings(&self) -> Vec<String> {
        self.lock().warnings.clone()
    }

    /// The last update of a run (`Completed` with its outcome, `Failed`,
    /// `Aborted`): delivered even when the channel is momentarily full
    /// (waits up to 2 s for room).
    pub async fn finish(
        &self,
        status: AcquisitionStatus,
        outcome: Option<Outcome>,
        message: impl Into<String>,
    ) {
        let (tx, update) = {
            let mut inner = self.lock();
            inner.state.status = status;
            inner.state.outcome = outcome;
            inner.state.verify_progress = None;
            inner.state.push_log(message.into());
            let update = inner.state.take_update();
            (inner.tx.clone(), update)
        };
        if let Some(tx) = tx {
            if let Err(SendTimeoutError::Timeout(update) | SendTimeoutError::Closed(update)) =
                tx.send_timeout(update, FINAL_SEND_TIMEOUT).await
            {
                // Keep the lines for a consumer that reads the state later
                let mut inner = self.lock();
                let mut lines = update.log_messages;
                lines.append(&mut inner.state.log_messages);
                cap_log(&mut lines);
                inner.state.log_messages = lines;
            }
        }
    }

    /// Stop sending (the receiver is going away); the state is still kept.
    pub fn disconnect(&self) {
        self.lock().tx = None;
    }
}

fn cap_log(lines: &mut Vec<String>) {
    if lines.len() > MAX_LOG_LINES {
        let excess = lines.len() - MAX_LOG_LINES;
        lines.drain(..excess);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn updates_never_block_and_lose_no_log_line() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = ProgressSink::new(tx);
        // The first update fills the channel, the next ones are kept back
        sink.log("one");
        sink.log("two");
        sink.update(|t| t.percentage = 50.0);
        let mut consumer = ProgressTelemetry::default();
        consumer.apply_update(rx.recv().await.unwrap());
        assert_eq!(consumer.log_messages, ["one"]);
        // Room again: the next update carries everything held back
        sink.log("three");
        consumer.apply_update(rx.recv().await.unwrap());
        assert_eq!(consumer.log_messages, ["one", "two", "three"]);
        assert_eq!(consumer.percentage, 50.0);
    }

    #[tokio::test]
    async fn engine_updates_merge_and_finish_is_delivered() {
        let (tx, mut rx) = mpsc::channel(4);
        let sink = ProgressSink::new(tx);
        let consumer = tokio::spawn(async move {
            let mut consumer = ProgressTelemetry::default();
            while let Some(u) = rx.recv().await {
                consumer.apply_update(u);
            }
            consumer
        });
        let engine_sink = sink.clone();
        let mut engine = ProgressTelemetry {
            status: AcquisitionStatus::Acquiring,
            total_bytes: 100,
            ..Default::default()
        };
        engine.push_log("engine started");
        engine.bytes_processed = 40;
        std::thread::spawn(move || engine_sink.send(engine.take_update()))
            .join()
            .unwrap();
        sink.warn("audit log not written");
        sink.phase(AcquisitionStatus::Verifying, "verifying");
        sink.phase_progress(50, 100, 1.0);
        sink.finish(
            AcquisitionStatus::Completed,
            Some(Outcome::Verified),
            "done",
        )
        .await;
        drop(sink);
        let consumer = consumer.await.unwrap();
        assert_eq!(consumer.status, AcquisitionStatus::Completed);
        assert_eq!(consumer.outcome, Some(Outcome::Verified));
        assert_eq!(consumer.bytes_processed, 40);
        assert_eq!(
            consumer.log_messages,
            [
                "engine started",
                "WARNING: audit log not written",
                "verifying",
                "done"
            ]
        );
    }

    #[test]
    fn disconnected_sink_keeps_state_and_warnings() {
        let sink = ProgressSink::disconnected();
        sink.warn("x");
        sink.phase(AcquisitionStatus::SourceReread, "second read");
        sink.phase_progress(5, 10, 0.0);
        let s = sink.snapshot();
        assert_eq!(s.status, AcquisitionStatus::SourceReread);
        assert_eq!(s.verify_progress.unwrap().percentage, 50.0);
        assert_eq!(sink.warnings(), ["WARNING: x"]);
        for i in 0..(MAX_LOG_LINES + 10) {
            sink.log(format!("{i}"));
        }
        assert_eq!(sink.snapshot().log_messages.len(), MAX_LOG_LINES);
    }
}
