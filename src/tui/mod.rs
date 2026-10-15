//! The terminal UI (§16): device explorer, case setup, confirmation sheet,
//! acquisition / conversion / verification progress and persistent results.
//!
//! Terminal handling: raw mode and the alternate screen, no mouse capture
//! (text stays selectable for copying hashes), restored on every exit path
//! including a panic of the UI itself (dfdisk then exits 1). A panic in
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
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::Duration;

/// Redraw and background-poll interval.
const TICK: Duration = Duration::from_millis(50);

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

    let res = guard_ui(run_tui_inner(controller, listener)).await;

    restore_terminal();
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
) -> Result<(Option<String>, i32), Box<dyn std::error::Error>> {
    let mut app = App::with_controller(controller);

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
