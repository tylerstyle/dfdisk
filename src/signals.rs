//! Signals and user aborts of a running acquisition (§15, §16), shared by the
//! CLI and the TUI.
//!
//! An [`AbortController`] owns three flags:
//! - **abort** (graceful): engines stop their tool (SIGINT, grace period,
//!   escalation), keep every output, and the session still writes the report
//!   and the audit "finished" record (outcome Aborted, exit 8). Set by the
//!   first SIGINT, by SIGTERM or SIGQUIT (`Ctrl+\` would otherwise end dfdisk
//!   without a report, its tool running on), or by the UI after a y/N
//!   confirmation.
//! - **force**: a second SIGINT; external tools are killed at once
//!   (`engines::process::StopControl::force`). The report is still written.
//! - **headless**: SIGHUP (terminal gone). The acquisition keeps running to
//!   completion and writes its report; the CLI/TUI stop writing to the
//!   terminal.
//!
//! The flags are plain `Arc<AtomicBool>`s so engines poll them cheaply.
//! [`AbortController::install`] turns OS signals into flag changes; the
//! decision itself is [`AbortController::handle`] (pure state machine, unit
//! tested). Note: once tokio listens for a signal, the signal's default action
//! (terminate) stays replaced for the life of the process, so install the
//! listener only around work that reacts to the flags.

use crate::engines::process::StopControl;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The abort and force flags an acquisition, verification or conversion
/// polls. Cheap to clone; clones share the flags.
#[derive(Debug, Clone, Default)]
pub struct StopFlags {
    /// Graceful stop requested
    pub abort: Arc<AtomicBool>,
    /// Immediate stop requested (kill external tools now)
    pub force: Arc<AtomicBool>,
}

impl StopFlags {
    /// Fresh flags, nothing requested.
    pub fn new() -> Self {
        Self::default()
    }

    /// Flags around an existing abort flag (callers that have no force flag).
    pub fn from_abort(abort: Arc<AtomicBool>) -> Self {
        Self {
            abort,
            force: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_aborted(&self) -> bool {
        self.abort.load(Ordering::SeqCst)
    }

    pub fn is_forced(&self) -> bool {
        self.force.load(Ordering::SeqCst)
    }

    /// The flags as the process runner's stop control.
    pub fn stop_control(&self) -> StopControl {
        StopControl::abort(self.abort.clone()).with_force(self.force.clone())
    }
}

/// The signals that change a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalKind {
    /// SIGINT (Ctrl+C)
    Interrupt,
    /// SIGTERM
    Terminate,
    /// SIGHUP (terminal closed)
    Hangup,
    /// SIGQUIT (`Ctrl+\`): handled like SIGTERM
    Quit,
}

impl SignalKind {
    pub fn name(&self) -> &'static str {
        match self {
            SignalKind::Interrupt => "SIGINT",
            SignalKind::Terminate => "SIGTERM",
            SignalKind::Hangup => "SIGHUP",
            SignalKind::Quit => "SIGQUIT",
        }
    }

    fn code(self) -> u8 {
        match self {
            SignalKind::Interrupt => 1,
            SignalKind::Terminate => 2,
            SignalKind::Hangup => 3,
            SignalKind::Quit => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(SignalKind::Interrupt),
            2 => Some(SignalKind::Terminate),
            3 => Some(SignalKind::Hangup),
            4 => Some(SignalKind::Quit),
            _ => None,
        }
    }
}

/// What a signal (or UI request) did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// The graceful abort flag was set (first SIGINT, SIGTERM)
    Abort,
    /// The force flag was set (second SIGINT)
    Force,
    /// Headless mode (SIGHUP): keep running, stop terminal output
    Headless,
    /// Nothing new: the flag was already set
    Unchanged,
}

impl SignalAction {
    /// A one-line message for the examiner (CLI stderr / TUI notification).
    pub fn message(&self, signal: SignalKind) -> String {
        match self {
            SignalAction::Abort => format!(
                "{}: stopping the acquisition gracefully; the outputs and the report are kept (press Ctrl+C again to kill external tools immediately)",
                signal.name()
            ),
            SignalAction::Force => format!(
                "{}: killing external tools immediately; the report is still written",
                signal.name()
            ),
            SignalAction::Headless => format!(
                "{}: the terminal is gone; continuing without terminal output until the report is written",
                signal.name()
            ),
            SignalAction::Unchanged => format!("{}: already handled", signal.name()),
        }
    }
}

/// Abort, force and headless flags of one process, set by signals and by
/// the UI. Clones share the flags.
#[derive(Debug, Clone, Default)]
pub struct AbortController {
    stop: StopFlags,
    headless: Arc<AtomicBool>,
    last_signal: Arc<AtomicU8>,
}

impl AbortController {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abort and force flags to hand to `session::run_with`, verification
    /// and conversion.
    pub fn stop_flags(&self) -> StopFlags {
        self.stop.clone()
    }

    pub fn abort_flag(&self) -> Arc<AtomicBool> {
        self.stop.abort.clone()
    }

    pub fn force_flag(&self) -> Arc<AtomicBool> {
        self.stop.force.clone()
    }

    pub fn headless_flag(&self) -> Arc<AtomicBool> {
        self.headless.clone()
    }

    pub fn is_aborted(&self) -> bool {
        self.stop.is_aborted()
    }

    pub fn is_forced(&self) -> bool {
        self.stop.is_forced()
    }

    /// The terminal is gone: do not write to it.
    pub fn is_headless(&self) -> bool {
        self.headless.load(Ordering::SeqCst)
    }

    /// The last signal received, if any.
    pub fn last_signal(&self) -> Option<SignalKind> {
        SignalKind::from_code(self.last_signal.load(Ordering::SeqCst))
    }

    /// Graceful abort requested by the examiner (after the UI's y/N
    /// confirmation).
    pub fn request_abort(&self) -> SignalAction {
        if self.stop.abort.swap(true, Ordering::SeqCst) {
            SignalAction::Unchanged
        } else {
            SignalAction::Abort
        }
    }

    /// Immediate stop requested by the examiner (implies abort).
    pub fn request_force(&self) -> SignalAction {
        self.stop.abort.store(true, Ordering::SeqCst);
        if self.stop.force.swap(true, Ordering::SeqCst) {
            SignalAction::Unchanged
        } else {
            SignalAction::Force
        }
    }

    /// Apply a signal: SIGINT aborts gracefully, a second SIGINT forces;
    /// SIGTERM and SIGQUIT abort gracefully; SIGHUP switches to headless and
    /// keeps the run going.
    pub fn handle(&self, signal: SignalKind) -> SignalAction {
        self.last_signal.store(signal.code(), Ordering::SeqCst);
        match signal {
            SignalKind::Interrupt => {
                if self.stop.abort.swap(true, Ordering::SeqCst) {
                    self.request_force()
                } else {
                    SignalAction::Abort
                }
            }
            SignalKind::Terminate | SignalKind::Quit => self.request_abort(),
            SignalKind::Hangup => {
                if self.headless.swap(true, Ordering::SeqCst) {
                    SignalAction::Unchanged
                } else {
                    SignalAction::Headless
                }
            }
        }
    }

    /// Clear abort and force for the next run (TUI between acquisitions).
    /// Headless stays: the terminal does not come back.
    pub fn reset(&self) {
        self.stop.abort.store(false, Ordering::SeqCst);
        self.stop.force.store(false, Ordering::SeqCst);
        self.last_signal.store(0, Ordering::SeqCst);
    }

    /// Listen for SIGINT, SIGTERM, SIGHUP and SIGQUIT and apply them with
    /// [`handle`](Self::handle). Every signal and its action is also sent to
    /// the returned listener, so the CLI/TUI can tell the examiner. Must be
    /// called inside a tokio runtime. Dropping the listener stops listening,
    /// but the signals stay caught (see the module docs).
    pub fn install(&self) -> io::Result<SignalListener> {
        use tokio::signal::unix::{signal, SignalKind as Tk};
        let mut int = signal(Tk::interrupt())?;
        let mut term = signal(Tk::terminate())?;
        let mut hup = signal(Tk::hangup())?;
        let mut quit = signal(Tk::quit())?;
        let (tx, rx) = mpsc::unbounded_channel();
        let controller = self.clone();
        let task = tokio::spawn(async move {
            loop {
                let kind = tokio::select! {
                    Some(()) = int.recv() => SignalKind::Interrupt,
                    Some(()) = term.recv() => SignalKind::Terminate,
                    Some(()) = hup.recv() => SignalKind::Hangup,
                    Some(()) = quit.recv() => SignalKind::Quit,
                    else => break,
                };
                let action = controller.handle(kind);
                let _ = tx.send((kind, action));
            }
        });
        Ok(SignalListener { task, events: rx })
    }
}

/// Signal listener of [`AbortController::install`]; stops listening when
/// dropped.
#[derive(Debug)]
pub struct SignalListener {
    task: JoinHandle<()>,
    events: mpsc::UnboundedReceiver<(SignalKind, SignalAction)>,
}

impl SignalListener {
    /// The next signal received and what it did.
    pub async fn recv(&mut self) -> Option<(SignalKind, SignalAction)> {
        self.events.recv().await
    }

    /// A signal received since the last call, without waiting.
    pub fn try_recv(&mut self) -> Option<(SignalKind, SignalAction)> {
        self.events.try_recv().ok()
    }
}

impl Drop for SignalListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_interrupt_aborts_second_forces() {
        let c = AbortController::new();
        assert!(!c.is_aborted() && !c.is_forced() && !c.is_headless());
        assert_eq!(c.handle(SignalKind::Interrupt), SignalAction::Abort);
        assert!(c.is_aborted());
        assert!(!c.is_forced());
        assert_eq!(c.handle(SignalKind::Interrupt), SignalAction::Force);
        assert!(c.is_forced());
        assert_eq!(c.handle(SignalKind::Interrupt), SignalAction::Unchanged);
        assert_eq!(c.last_signal(), Some(SignalKind::Interrupt));
    }

    #[test]
    fn terminate_aborts_gracefully_and_never_forces() {
        let c = AbortController::new();
        assert_eq!(c.handle(SignalKind::Terminate), SignalAction::Abort);
        assert_eq!(c.handle(SignalKind::Terminate), SignalAction::Unchanged);
        assert!(c.is_aborted());
        assert!(!c.is_forced());
        // A SIGINT after SIGTERM escalates
        assert_eq!(c.handle(SignalKind::Interrupt), SignalAction::Force);
    }

    #[test]
    fn quit_aborts_gracefully_like_terminate() {
        let c = AbortController::new();
        assert_eq!(c.handle(SignalKind::Quit), SignalAction::Abort);
        assert!(c.is_aborted() && !c.is_forced() && !c.is_headless());
        assert_eq!(c.handle(SignalKind::Quit), SignalAction::Unchanged);
        assert_eq!(c.last_signal(), Some(SignalKind::Quit));
        assert!(SignalAction::Abort
            .message(SignalKind::Quit)
            .starts_with("SIGQUIT: stopping the acquisition gracefully"));
    }

    #[test]
    fn hangup_keeps_running_headless() {
        let c = AbortController::new();
        assert_eq!(c.handle(SignalKind::Hangup), SignalAction::Headless);
        assert!(c.is_headless());
        assert!(!c.is_aborted());
        assert_eq!(c.handle(SignalKind::Hangup), SignalAction::Unchanged);
        c.reset();
        assert!(c.is_headless(), "the terminal does not come back");
    }

    #[test]
    fn ui_requests_and_shared_flags() {
        let c = AbortController::new();
        let flags = c.stop_flags();
        let clone = c.clone();
        assert_eq!(clone.request_abort(), SignalAction::Abort);
        assert!(flags.is_aborted());
        assert_eq!(c.request_abort(), SignalAction::Unchanged);
        assert_eq!(c.request_force(), SignalAction::Force);
        assert!(flags.is_forced());
        let control = flags.stop_control();
        assert!(control.abort.unwrap().load(Ordering::SeqCst));
        assert!(control.force.unwrap().load(Ordering::SeqCst));
        c.reset();
        assert!(!flags.is_aborted() && !flags.is_forced());
        assert_eq!(c.last_signal(), None);
        assert!(SignalAction::Abort
            .message(SignalKind::Interrupt)
            .contains("Ctrl+C again"));
        let from = StopFlags::from_abort(Arc::new(AtomicBool::new(true)));
        assert!(from.is_aborted() && !from.is_forced());
    }

    #[tokio::test]
    async fn installed_listener_turns_sighup_into_headless() {
        let c = AbortController::new();
        let mut listener = c.install().unwrap();
        // SIGHUP only: SIGINT/SIGTERM would stay caught for the whole test binary
        // SAFETY: sending a signal to our own process
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("signal delivered");
        assert_eq!(got, Some((SignalKind::Hangup, SignalAction::Headless)));
        assert!(c.is_headless());
        assert!(!c.is_aborted());

        // SIGQUIT is caught too: a graceful abort, not the default core dump
        // that would end the process without a report
        // SAFETY: sending a signal to our own process (caught by the listener)
        unsafe { libc::kill(libc::getpid(), libc::SIGQUIT) };
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("signal delivered");
        assert_eq!(got, Some((SignalKind::Quit, SignalAction::Abort)));
        assert!(c.is_aborted());
    }
}
