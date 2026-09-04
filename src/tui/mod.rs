pub mod app;
pub mod autocomplete;
pub mod events;
pub mod ui;

use app::App;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use events::{AppEvent, EventHandler};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

pub fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

pub async fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    // Install custom panic hook to restore terminal if a panic occurs
    let prev_hook = std::panic::take_hook();
    let prev_hook = std::sync::Arc::new(prev_hook);
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

    res
}

async fn run_tui_inner() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let mut events = EventHandler::new(Duration::from_millis(50));

    let res = run_app(&mut terminal, &mut app, &mut events).await;

    let _ = terminal.show_cursor();
    res
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    events: &mut EventHandler,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| ui::render(frame, app))?;

        if let Some(event) = events.next().await {
            match event {
                AppEvent::Key(key) => {
                    app.handle_key(key);
                }
                AppEvent::Tick => {
                    app.tick();
                }
                AppEvent::Resize(_, _) => {}
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
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
