//! Running a long operation in the CLI: its progress updates are printed,
//! signals are reported as they arrive (the [`AbortController`] already
//! turned them into flags the operation polls), and the operation's result
//! is returned once it ends.
//!
//! [`AbortController`]: crate::signals::AbortController

use crate::cli::console::{Console, ProgressPrinter};
use crate::models::telemetry::ProgressTelemetry;
use crate::signals::{SignalAction, SignalKind, SignalListener};
use std::future::Future;
use tokio::sync::mpsc;

/// What a signal stops (for the message the examiner sees).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Acquisition,
    Conversion,
    Verification,
}

impl Activity {
    pub fn noun(&self) -> &'static str {
        match self {
            Activity::Acquisition => "acquisition",
            Activity::Conversion => "conversion",
            Activity::Verification => "verification",
        }
    }
}

/// The message for a signal and what it did.
pub fn signal_message(kind: SignalKind, action: SignalAction, activity: Activity) -> String {
    if activity == Activity::Acquisition {
        return action.message(kind);
    }
    let what = activity.noun();
    match action {
        SignalAction::Abort => format!(
            "{}: stopping the {what} (press Ctrl+C again to kill external tools immediately)",
            kind.name()
        ),
        SignalAction::Force => format!("{}: killing external tools immediately", kind.name()),
        SignalAction::Headless => format!(
            "{}: the terminal is gone; the {what} continues without terminal output",
            kind.name()
        ),
        SignalAction::Unchanged => format!("{}: already handled", kind.name()),
    }
}

/// The next signal of the listener; never resolves without a listener (or
/// after the listener ended).
pub async fn next_signal(listener: &mut Option<SignalListener>) -> (SignalKind, SignalAction) {
    if let Some(l) = listener.as_mut() {
        if let Some(event) = l.recv().await {
            return event;
        }
    }
    *listener = None;
    std::future::pending().await
}

/// Tell the examiner what a signal did (stderr).
pub fn report_signal(
    console: &Console,
    kind: SignalKind,
    action: SignalAction,
    activity: Activity,
) {
    if action != SignalAction::Unchanged {
        console.note(&format!("[!] {}", signal_message(kind, action, activity)));
    }
}

/// Await `operation` while printing the updates of `rx` and reporting
/// signals. Updates still queued when it ends are printed too.
pub async fn drive<T>(
    operation: impl Future<Output = T>,
    mut rx: mpsc::Receiver<ProgressTelemetry>,
    listener: &mut Option<SignalListener>,
    console: &Console,
    printer: &mut ProgressPrinter,
    activity: Activity,
) -> T {
    tokio::pin!(operation);
    let mut open = true;
    let result = loop {
        tokio::select! {
            result = &mut operation => break result,
            update = rx.recv(), if open => match update {
                Some(update) => printer.update(console, &update),
                None => open = false,
            },
            (kind, action) = next_signal(listener) => report_signal(console, kind, action, activity),
        }
    };
    while let Ok(update) = rx.try_recv() {
        printer.update(console, &update);
    }
    printer.finish(console);
    result
}

/// Await `operation` while reporting signals (no progress channel).
pub async fn with_signals<T>(
    operation: impl Future<Output = T>,
    listener: &mut Option<SignalListener>,
    console: &Console,
    activity: Activity,
) -> T {
    tokio::pin!(operation);
    loop {
        tokio::select! {
            result = &mut operation => break result,
            (kind, action) = next_signal(listener) => report_signal(console, kind, action, activity),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::telemetry::AcquisitionStatus;

    #[tokio::test]
    async fn drive_prints_every_update_and_returns_the_result() {
        let (console, _out, err) = Console::capture(false);
        let mut printer = ProgressPrinter::new(&console, true);
        let (tx, rx) = mpsc::channel(4);
        let op = async move {
            for i in 0..10 {
                let mut t = ProgressTelemetry {
                    status: AcquisitionStatus::Acquiring,
                    ..Default::default()
                };
                t.push_log(format!("line {i}"));
                tx.send(t.take_update()).await.unwrap();
            }
            42
        };
        let mut none = None;
        let r = drive(
            op,
            rx,
            &mut none,
            &console,
            &mut printer,
            Activity::Acquisition,
        )
        .await;
        assert_eq!(r, 42);
        let text = err.text();
        for i in 0..10 {
            assert!(text.contains(&format!("[*] line {i}")), "{text}");
        }
    }

    #[tokio::test]
    async fn without_a_listener_signals_never_fire() {
        let (console, ..) = Console::capture(false);
        let mut none = None;
        assert_eq!(
            with_signals(async { 7 }, &mut none, &console, Activity::Conversion).await,
            7
        );
    }

    #[test]
    fn messages_name_what_is_stopped() {
        let m = signal_message(
            SignalKind::Interrupt,
            SignalAction::Abort,
            Activity::Verification,
        );
        assert!(m.starts_with("SIGINT: stopping the verification"), "{m}");
        let m = signal_message(
            SignalKind::Interrupt,
            SignalAction::Abort,
            Activity::Acquisition,
        );
        assert!(m.contains("outputs and the report are kept"), "{m}");
        let m = signal_message(
            SignalKind::Hangup,
            SignalAction::Headless,
            Activity::Conversion,
        );
        assert!(m.contains("conversion continues"), "{m}");
    }
}
