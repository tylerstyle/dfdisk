//! Terminal output of the CLI.
//!
//! - stdout carries the result: the report text, or with `--json` the JSON
//!   document and nothing else;
//! - human text goes to stdout, or to stderr with `--json`;
//! - progress, warnings and signal messages always go to stderr; progress is
//!   one redrawn line on a terminal and an occasional plain line otherwise;
//! - after SIGHUP (headless, §15) nothing is written to a stream that is a
//!   terminal any more; redirected streams (files, pipes) keep receiving
//!   output, so `dfdisk ... --json > report.json` still gets its report.
//!
//! Write errors are ignored (a closed terminal or pipe must not end an
//! acquisition); nothing here can panic on I/O.

use crate::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use crate::models::text::format_iec;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Sink = Mutex<Box<dyn Write + Send>>;

/// Where the CLI writes.
pub struct Console {
    json: bool,
    headless: Arc<AtomicBool>,
    out_tty: bool,
    err_tty: bool,
    out: Sink,
    err: Sink,
    /// A redrawn progress line is on stderr and must be cleared first
    progress_shown: AtomicBool,
}

/// A writer into a shared buffer (tests).
#[derive(Clone, Default)]
pub struct SharedBuffer(pub Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Console {
    /// stdout and stderr of this process.
    pub fn stdio(json: bool, headless: Arc<AtomicBool>) -> Self {
        Self {
            json,
            headless,
            out_tty: std::io::stdout().is_terminal(),
            err_tty: std::io::stderr().is_terminal(),
            out: Mutex::new(Box::new(std::io::stdout())),
            err: Mutex::new(Box::new(std::io::stderr())),
            progress_shown: AtomicBool::new(false),
        }
    }

    /// Output into two buffers (tests); neither counts as a terminal.
    pub fn capture(json: bool) -> (Self, SharedBuffer, SharedBuffer) {
        let out = SharedBuffer::default();
        let err = SharedBuffer::default();
        (
            Self {
                json,
                headless: Arc::new(AtomicBool::new(false)),
                out_tty: false,
                err_tty: false,
                out: Mutex::new(Box::new(out.clone())),
                err: Mutex::new(Box::new(err.clone())),
                progress_shown: AtomicBool::new(false),
            },
            out,
            err,
        )
    }

    pub fn json(&self) -> bool {
        self.json
    }

    fn suppressed(&self, tty: bool) -> bool {
        tty && self.headless.load(Ordering::SeqCst)
    }

    fn write_to(&self, sink: &Sink, tty: bool, text: &str) {
        if self.suppressed(tty) {
            return;
        }
        let mut w = sink.lock().unwrap_or_else(|e| e.into_inner());
        let _ = w.write_all(text.as_bytes());
        let _ = w.flush();
    }

    /// End a redrawn progress line before other output.
    fn clear_progress(&self) {
        if self.progress_shown.swap(false, Ordering::SeqCst) {
            self.write_to(&self.err, self.err_tty, "\r\x1b[K");
        }
    }

    /// The result on stdout (report text or JSON), always.
    pub fn data(&self, text: &str) {
        self.clear_progress();
        let mut s = text.to_string();
        if !s.ends_with('\n') {
            s.push('\n');
        }
        self.write_to(&self.out, self.out_tty, &s);
    }

    /// Human text: stdout, or stderr with `--json`.
    pub fn say(&self, text: &str) {
        self.clear_progress();
        let line = format!("{text}\n");
        if self.json {
            self.write_to(&self.err, self.err_tty, &line);
        } else {
            self.write_to(&self.out, self.out_tty, &line);
        }
    }

    /// Diagnostics (warnings, signals, phases): stderr.
    pub fn note(&self, text: &str) {
        self.clear_progress();
        self.write_to(&self.err, self.err_tty, &format!("{text}\n"));
    }

    /// A progress line on stderr: redrawn in place on a terminal, a plain
    /// line otherwise.
    pub fn progress(&self, line: &str) {
        if self.err_tty {
            self.write_to(&self.err, self.err_tty, &format!("\r\x1b[K{line}"));
            self.progress_shown.store(true, Ordering::SeqCst);
        } else {
            self.write_to(&self.err, self.err_tty, &format!("{line}\n"));
        }
    }

    /// Finish a redrawn progress line.
    pub fn end_progress(&self) {
        if self.progress_shown.swap(false, Ordering::SeqCst) {
            self.write_to(&self.err, self.err_tty, "\n");
        }
    }

    /// Whether progress is redrawn in place (stderr is a terminal).
    pub fn progress_redraws(&self) -> bool {
        self.err_tty
    }
}

/// Turns progress updates into console lines: warnings always, every log
/// line with `--verbose`, one line per phase change, and a progress line at
/// most every `interval` (250 ms on a terminal, 30 s otherwise).
pub struct ProgressPrinter {
    verbose: bool,
    interval: Duration,
    last: Option<Instant>,
    status: Option<AcquisitionStatus>,
    /// Text of the last phase message printed
    phase_message: String,
}

impl ProgressPrinter {
    pub fn new(console: &Console, verbose: bool) -> Self {
        Self {
            verbose,
            interval: if console.progress_redraws() {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(30)
            },
            last: None,
            status: None,
            phase_message: String::new(),
        }
    }

    /// Handle one update (its `log_messages` are the lines new since the
    /// previous update).
    pub fn update(&mut self, console: &Console, t: &ProgressTelemetry) {
        for line in &t.log_messages {
            if line.starts_with("WARNING") {
                console.note(&format!("[!] {line}"));
            } else if self.verbose {
                console.note(&format!("[*] {line}"));
            }
        }
        if self.status.as_ref() != Some(&t.status) {
            self.status = Some(t.status.clone());
            self.last = None;
            if !t.status.is_terminal() && t.status_message != self.phase_message {
                self.phase_message = t.status_message.clone();
                console.note(&format!(
                    "[*] {}: {}",
                    t.status.display_str(),
                    t.status_message
                ));
            }
        }
        if !t.status.is_running() {
            return;
        }
        let due = self.last.is_none_or(|l| l.elapsed() >= self.interval);
        if due {
            if let Some(line) = progress_line(t) {
                self.last = Some(Instant::now());
                console.progress(&line);
            }
        }
    }

    pub fn finish(&self, console: &Console) {
        console.end_progress();
    }
}

/// One progress line for the current phase, when the phase reports
/// measurable progress (the phase line itself is printed on its change).
pub fn progress_line(t: &ProgressTelemetry) -> Option<String> {
    let speed = |bps: f64| format!("{}/s", format_iec(bps.max(0.0) as u64));
    match (&t.status, &t.verify_progress) {
        (AcquisitionStatus::Verifying | AcquisitionStatus::SourceReread, Some(p))
            if p.total_bytes > 0 || p.bytes_done > 0 =>
        {
            Some(format!(
                "[*] {:<14} {:>5.1}%  {} of {}  {}",
                t.status.display_str(),
                p.percentage,
                format_iec(p.bytes_done),
                format_iec(p.total_bytes),
                speed(p.speed_bps)
            ))
        }
        (AcquisitionStatus::Acquiring, _)
            if t.total_bytes > 0 || t.bytes_processed > 0 || t.percentage > 0.0 =>
        {
            let mut line = format!(
                "[*] {:<14} {:>5.1}%  {} of {}  {}  ETA {}",
                t.status.display_str(),
                t.percentage,
                format_iec(t.bytes_processed),
                format_iec(t.total_bytes),
                speed(t.speed_bps),
                t.human_eta()
            );
            if t.bad_sectors > 0 {
                line.push_str(&format!("  unreadable sectors: {}", t.bad_sectors));
            }
            Some(line)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::telemetry::PhaseProgress;

    #[test]
    fn json_mode_keeps_stdout_for_the_result() {
        let (c, out, err) = Console::capture(true);
        c.say("Source: /dev/sdx");
        c.note("[!] WARNING: x");
        c.progress("[*] ACQUIRING 1%");
        c.data("{\"schema_version\": 2}");
        assert_eq!(out.text(), "{\"schema_version\": 2}\n");
        assert!(err.text().contains("Source: /dev/sdx"));
        assert!(err.text().contains("WARNING: x"));
        assert!(err.text().contains("ACQUIRING 1%\n"));

        let (c, out, err) = Console::capture(false);
        c.say("Source: /dev/sdx");
        c.data("REPORT");
        assert_eq!(out.text(), "Source: /dev/sdx\nREPORT\n");
        assert!(err.text().is_empty());
    }

    #[test]
    fn headless_silences_terminals_only() {
        let headless = Arc::new(AtomicBool::new(true));
        let out = SharedBuffer::default();
        let err = SharedBuffer::default();
        let c = Console {
            json: true,
            headless: headless.clone(),
            out_tty: false,
            err_tty: true,
            out: Mutex::new(Box::new(out.clone())),
            err: Mutex::new(Box::new(err.clone())),
            progress_shown: AtomicBool::new(false),
        };
        c.note("gone");
        c.progress("gone");
        c.data("{}");
        assert_eq!(err.text(), "", "the terminal is gone");
        assert_eq!(
            out.text(),
            "{}\n",
            "a redirected stdout still gets the report"
        );
        headless.store(false, Ordering::SeqCst);
        c.progress("p");
        c.note("n");
        assert_eq!(err.text(), "\r\x1b[Kp\r\x1b[Kn\n");
    }

    #[test]
    fn printer_reports_warnings_phases_and_rate_limited_progress() {
        let (c, _out, err) = Console::capture(false);
        let mut p = ProgressPrinter::new(&c, false);
        let mut t = ProgressTelemetry {
            status: AcquisitionStatus::Acquiring,
            status_message: "Acquiring with RAW".into(),
            percentage: 10.0,
            total_bytes: 1 << 20,
            bytes_processed: 1 << 17,
            log_messages: vec!["engine detail".into(), "WARNING: low space".into()],
            ..Default::default()
        };
        p.update(&c, &t);
        t.log_messages.clear();
        t.percentage = 11.0;
        p.update(&c, &t); // within the interval: no second line
        t.status = AcquisitionStatus::Verifying;
        t.status_message = "Verifying the written image".into();
        t.verify_progress = Some(PhaseProgress {
            bytes_done: 1 << 19,
            total_bytes: 1 << 20,
            percentage: 50.0,
            speed_bps: 1048576.0,
        });
        p.update(&c, &t);
        p.finish(&c);
        let text = err.text();
        assert!(!text.contains("engine detail"), "{text}");
        assert!(text.contains("[!] WARNING: low space"), "{text}");
        assert!(text.contains("ACQUIRING: Acquiring with RAW"), "{text}");
        assert_eq!(text.matches("10.0%").count(), 1, "{text}");
        assert!(!text.contains("11.0%"), "{text}");
        assert!(text.contains("VERIFYING:"), "{text}");
        assert!(text.contains("50.0%"), "{text}");

        let (c, _out, err) = Console::capture(false);
        let mut p = ProgressPrinter::new(&c, true);
        p.update(
            &c,
            &ProgressTelemetry {
                log_messages: vec!["engine detail".into()],
                ..Default::default()
            },
        );
        assert!(err.text().contains("[*] engine detail"));
    }
}
