//! Terminal input for the TUI: key presses and resizes from crossterm's event
//! stream, forwarded over a channel. The channel closes when the terminal
//! goes away (end of input or repeated read errors, e.g. after SIGHUP), so
//! the main loop never spins on a dead terminal.

use crossterm::event::{Event as CrosstermEvent, EventStream, KeyEvent, KeyEventKind};
use futures::StreamExt;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Key(KeyEvent),
    Resize(u16, u16),
}

pub struct EventHandler {
    rx: mpsc::Receiver<AppEvent>,
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHandler {
    /// Start reading terminal events (needs a tokio runtime).
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut reader = EventStream::new();
            let mut errors = 0u32;
            while let Some(event) = reader.next().await {
                let forward = match event {
                    Ok(CrosstermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                        Some(AppEvent::Key(key))
                    }
                    Ok(CrosstermEvent::Resize(w, h)) => Some(AppEvent::Resize(w, h)),
                    Ok(_) => None,
                    Err(_) => {
                        errors += 1;
                        if errors >= 10 {
                            break;
                        }
                        continue;
                    }
                };
                errors = 0;
                if let Some(ev) = forward {
                    if tx.send(ev).await.is_err() {
                        break;
                    }
                }
            }
        });
        Self { rx }
    }

    /// The next event; `None` once the terminal input is gone.
    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}
