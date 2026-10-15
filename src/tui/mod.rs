//! The terminal UI (§16): device explorer, case setup, confirmation sheet,
//! acquisition / conversion / verification progress and persistent results.
//!
//! Terminal handling: raw mode and the alternate screen, no mouse capture
//! (text stays selectable for copying hashes), restored on every exit path
//! including a panic of the UI itself (dfdisk then exits 1, after a running
//! job was aborted and has written its report and audit record, and a
//! running unmount has ended: [`finish_background_work`]). A panic in
//! background work (a job, a scan, an unmount) does not end the UI: it
//! becomes that work's failure on screen (a job's FAILED result), and its
//! message is printed once the terminal is restored. Signals (installed once per process): SIGHUP continues
//! headless (nothing more is drawn) until the running job has written its
//! report; SIGTERM / SIGINT / SIGQUIT abort a running job gracefully and quit
//! once its report is written; idle, they quit at once.

pub mod app;
pub mod autocomplete;
pub mod backend;
pub mod confirm;
pub mod devices;
pub mod events;
pub mod form;
pub mod input;
pub mod profile;
pub mod ui;

use crate::signals::{AbortController, SignalListener};
use app::{panic_message, App};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::{AppEvent, EventHandler};
use futures::FutureExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// Redraw and background-poll interval.
const TICK: Duration = Duration::from_millis(50);

/// After a panic of the UI: how long a running job has to end after its
/// graceful abort (its tools' grace periods, the report), then after the
/// forced stop.
const PANIC_ABORT_WAIT: Duration = Duration::from_secs(300);
const PANIC_FORCE_WAIT: Duration = Duration::from_secs(60);

/// Background work that must end before dfdisk exits: a job (acquisition,
/// conversion, verification: its report and audit "finished" record) or an
/// audited unmount (I-N3). Clones share the count; each piece of work holds
/// a [`WorkGuard`] while it runs, also while it unwinds from a panic.
#[derive(Debug, Clone, Default)]
pub struct WorkTracker(Arc<AtomicUsize>);

/// One running piece of work of a [`WorkTracker`].
#[derive(Debug)]
pub struct WorkGuard(Arc<AtomicUsize>);

impl WorkTracker {
    pub fn enter(&self) -> WorkGuard {
        self.0.fetch_add(1, Ordering::SeqCst);
        WorkGuard(self.0.clone())
    }

    pub fn running(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// Wait until no work runs, at most `limit`; whether none runs.
    pub async fn wait_idle(&self, limit: Duration) -> bool {
        let t0 = Instant::now();
        while self.running() > 0 {
            if t0.elapsed() >= limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The UI stopped on a panic while work ran (I-N3): `process::exit` would
/// end the runtime with the job's audit guards (FinishedGuard, the tool's
/// process group, the output guard) never run, an "acquisition_started"
/// without its "finished". A running job is aborted gracefully, as SIGTERM
/// does in the TUI, and awaited with its report (`abort_wait`); one still
/// running is then stopped at once (`force_wait`). An unmount ignores the
/// abort and is awaited to its end and its audit record. Returns what
/// happened, for the terminal.
pub async fn finish_background_work(
    controller: &AbortController,
    work: &WorkTracker,
    abort_wait: Duration,
    force_wait: Duration,
) -> Vec<String> {
    let mut out = Vec::new();
    if work.running() == 0 {
        return out;
    }
    out.push(
        "dfdisk: the terminal UI stopped while a job or an unmount was running: a running job is aborted (its report and audit record are written), an unmount is finished and recorded; waiting for them"
            .to_string(),
    );
    controller.request_abort();
    if work.wait_idle(abort_wait).await {
        out.push("dfdisk: the background work ended; see its report and the audit log".into());
        return out;
    }
    controller.request_force();
    if work.wait_idle(force_wait).await {
        out.push(format!(
            "dfdisk: the background work did not end within {} s of the abort and was stopped at once; see its report and the audit log",
            abort_wait.as_secs()
        ));
    } else {
        out.push(format!(
            "dfdisk: the background work did not end within {} s; dfdisk exits without its report or audit record",
            (abort_wait + force_wait).as_secs()
        ));
    }
    out
}

pub fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// Panics of background threads while the TUI runs, printed after it closed.
static BACKGROUND_PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// What the TUI's panic hook does with a panic on `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicRoute {
    /// The UI thread: the process ends; give the terminal back and print
    RestoreAndPrint,
    /// Background work: the UI keeps running and shows the failure; keep
    /// the message for later (printing now would garble the screen)
    Keep,
}

pub fn panic_route(ui_thread: ThreadId, current: ThreadId) -> PanicRoute {
    if current == ui_thread {
        PanicRoute::RestoreAndPrint
    } else {
        PanicRoute::Keep
    }
}

/// Await the UI; a panic of the UI itself becomes an error (exit 1, not the
/// runtime's 101).
async fn guard_ui<F, T>(ui: F) -> Result<T, Box<dyn std::error::Error>>
where
    F: std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
{
    match std::panic::AssertUnwindSafe(ui).catch_unwind().await {
        Ok(result) => result,
        Err(payload) => Err(format!(
            "internal error: the terminal UI stopped ({})",
            panic_message(payload.as_ref())
        )
        .into()),
    }
}

/// Run the TUI with the process' [`AbortController`] and its one signal
/// listener (installed by `main`; two listeners would apply every signal
/// twice: one SIGINT would count as abort and force). Returns the process
/// exit code: that of a result the examiner did not acknowledge on screen,
/// else 0. `Err` only for a terminal failure outside a running job.
pub async fn run_tui_with(
    controller: AbortController,
    listener: Option<SignalListener>,
) -> Result<i32, Box<dyn std::error::Error>> {
    // A panic of the UI thread ends dfdisk: the terminal is restored first.
    // Background panics are kept and printed once the terminal is back
    let ui_thread = std::thread::current().id();
    let prev_hook = std::sync::Arc::new(std::panic::take_hook());
    let hook_clone = std::sync::Arc::clone(&prev_hook);
    std::panic::set_hook(Box::new(move |panic_info| {
        match panic_route(ui_thread, std::thread::current().id()) {
            PanicRoute::RestoreAndPrint => {
                restore_terminal();
                hook_clone(panic_info);
            }
            PanicRoute::Keep => {
                if let Ok(mut kept) = BACKGROUND_PANICS.lock() {
                    kept.push(panic_info.to_string());
                }
            }
        }
    }));

    let work = WorkTracker::default();
    let res = guard_ui(run_tui_inner(controller.clone(), listener, work.clone())).await;

    restore_terminal();
    if res.is_err() {
        // A panic of the UI: the job's guards run before dfdisk exits
        for line in
            finish_background_work(&controller, &work, PANIC_ABORT_WAIT, PANIC_FORCE_WAIT).await
        {
            eprintln!("{line}");
        }
    }
    let _ = std::panic::take_hook();
    if let Ok(prev_hook) = std::sync::Arc::try_unwrap(prev_hook) {
        std::panic::set_hook(prev_hook);
    }
    let kept: Vec<String> = BACKGROUND_PANICS
        .lock()
        .map(|mut k| std::mem::take(&mut *k))
        .unwrap_or_default();
    for p in kept {
        eprintln!("dfdisk: internal error in background work: {p}");
    }

    // The terminal is ours again: say what was not acknowledged on screen
    let (line, code) = res?;
    if let Some(line) = line {
        eprintln!("{line}");
    }
    Ok(code)
}

/// Runs the UI; returns a line for the terminal when a result was not seen,
/// and the exit code.
async fn run_tui_inner(
    controller: AbortController,
    mut listener: Option<SignalListener>,
    work: WorkTracker,
) -> Result<(Option<String>, i32), Box<dyn std::error::Error>> {
    let mut app = App::with_controller(controller);
    app.work = work;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut events = EventHandler::new();
    let mut events_open = true;
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if !app.headless {
            // A drawing error on a terminal that just went away must not end a
            // running acquisition: its report is written first
            if let Err(e) = terminal.draw(|frame| ui::render(frame, &mut app)) {
                if !app.busy() {
                    return Err(e.into());
                }
                app.headless = true;
                app.quit_after_job = true;
            }
        }
        tokio::select! {
            ev = events.next(), if events_open => match ev {
                Some(AppEvent::Key(key)) => app.handle_key(key),
                Some(AppEvent::Resize(_, _)) => {}
                None => {
                    // The terminal input is gone (hang-up): finish headless
                    events_open = false;
                    app.headless = true;
                    if app.busy() {
                        app.quit_after_job = true;
                    } else {
                        app.should_quit = true;
                    }
                }
            },
            _ = ticker.tick() => app.tick(),
            sig = async {
                match listener.as_mut() {
                    Some(l) => l.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match sig {
                    Some((kind, action)) => app.on_signal(kind, action),
                    None => listener = None,
                }
            }
        }
        if app.should_quit {
            break;
        }
    }
    let code = app.exit_code();
    if app.headless {
        return Ok((None, code));
    }
    let _ = terminal.show_cursor();
    Ok((app.exit_summary(), code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restore_terminal_callable() {
        // Ensure restore_terminal runs safely even if terminal was not in raw mode
        restore_terminal();
    }

    #[test]
    fn only_a_panic_of_the_ui_thread_gives_the_terminal_back() {
        let ui = std::thread::current().id();
        assert_eq!(panic_route(ui, ui), PanicRoute::RestoreAndPrint);
        let worker = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        assert_eq!(panic_route(ui, worker), PanicRoute::Keep);
    }

    /// A job on the runtime holding a guard: it ends `after` the abort (or
    /// only on force), then sets `done`.
    fn job(
        work: &WorkTracker,
        controller: &AbortController,
        on_force_only: bool,
        done: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let guard = work.enter();
        let stop = controller.stop_flags();
        tokio::spawn(async move {
            let _running = guard;
            loop {
                let stopped = if on_force_only {
                    stop.is_forced()
                } else {
                    stop.is_aborted()
                };
                if stopped {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // The report and the audit record
            tokio::time::sleep(Duration::from_millis(50)).await;
            done.store(true, Ordering::SeqCst);
        });
    }

    #[tokio::test]
    async fn a_panic_of_the_ui_waits_for_the_running_job_to_write_its_report() {
        // I-N3: nothing to wait for, nothing said
        let controller = AbortController::new();
        let work = WorkTracker::default();
        let wait = Duration::from_secs(10);
        assert!(finish_background_work(&controller, &work, wait, wait)
            .await
            .is_empty());
        assert!(!controller.is_aborted());

        // A job: aborted gracefully and awaited
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        job(&work, &controller, false, done.clone());
        assert_eq!(work.running(), 1);
        let said = finish_background_work(&controller, &work, wait, wait).await;
        assert!(done.load(Ordering::SeqCst), "the job ended before the exit");
        assert_eq!(work.running(), 0);
        assert!(controller.is_aborted() && !controller.is_forced());
        assert!(said[0].contains("a running job is aborted"), "{said:?}");
        assert!(said[1].contains("ended"), "{said:?}");

        // One that ends only when forced: forced after the abort wait
        let controller = AbortController::new();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        job(&work, &controller, true, done.clone());
        let said =
            finish_background_work(&controller, &work, Duration::from_millis(100), wait).await;
        assert!(done.load(Ordering::SeqCst));
        assert!(controller.is_forced());
        assert!(said[1].contains("stopped at once"), "{said:?}");

        // Work that does not end at all: dfdisk says so and exits
        let stuck = work.enter();
        let said = finish_background_work(
            &AbortController::new(),
            &work,
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .await;
        assert!(said[1].contains("without its report"), "{said:?}");
        drop(stuck);
        assert_eq!(work.running(), 0);
    }

    #[tokio::test]
    async fn a_panic_of_the_ui_is_an_error_not_an_abort() {
        let ok: Result<i32, _> = guard_ui(async { Ok(7) }).await;
        assert_eq!(ok.unwrap(), 7);
        let failed: Result<i32, _> = guard_ui(async {
            if std::hint::black_box(true) {
                panic!("drawing went wrong");
            }
            Ok(0)
        })
        .await;
        let e = failed.unwrap_err().to_string();
        assert!(
            e.starts_with("internal error: the terminal UI stopped"),
            "{e}"
        );
        assert!(e.contains("drawing went wrong"), "{e}");
    }
}
