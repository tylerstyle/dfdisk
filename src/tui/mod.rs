//! The terminal UI (§16): device explorer, case setup, confirmation sheet,
//! acquisition / conversion / verification progress and persistent results.
//!
//! Terminal handling: raw mode and the alternate screen, no mouse capture
//! (text stays selectable for copying hashes), restored on every exit path
//! including panics. Signals (installed once per process): SIGHUP continues
//! headless (nothing more is drawn) until the running job has written its
//! report; SIGTERM / SIGINT abort a running job gracefully and quit once its
//! report is written; idle, they quit at once.

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

use app::App;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::{AppEvent, EventHandler};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

/// Redraw and background-poll interval.
const TICK: Duration = Duration::from_millis(50);

pub fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

pub async fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    // Restore the terminal if a panic occurs
    let prev_hook = std::sync::Arc::new(std::panic::take_hook());
    let hook_clone = std::sync::Arc::clone(&prev_hook);
    std::panic::set_hook(Box::new(move |panic_info| {
        restore_terminal();
        hook_clone(panic_info);
    }));

    let res = run_tui_inner().await;

    restore_terminal();
    let _ = std::panic::take_hook();
    if let Ok(prev_hook) = std::sync::Arc::try_unwrap(prev_hook) {
        std::panic::set_hook(prev_hook);
    }

    // The terminal is ours again: say what was not acknowledged on screen
    if let Some(line) = res? {
        eprintln!("{line}");
    }
    Ok(())
}

/// Runs the UI; returns a line for the terminal when a result was not seen.
async fn run_tui_inner() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut app = App::new();
    // Once per process: tokio keeps the signals caught after a listener drops
    let mut listener = app.controller.install().ok();

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
                if app.job.is_none() {
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
                    if app.job.is_some() {
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
    if app.headless {
        return Ok(None);
    }
    let _ = terminal.show_cursor();
    Ok(app.exit_summary())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restore_terminal_callable() {
        // Ensure restore_terminal runs safely even if terminal was not in raw mode
        restore_terminal();
    }
}
