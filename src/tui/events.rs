use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

#[allow(dead_code)]
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Resize(u16, u16),
}

pub struct EventHandler {
    rx: mpsc::Receiver<AppEvent>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            loop {
                if event::poll(tick_rate).unwrap_or(false) {
                    if let Ok(crossterm_event) = event::read() {
                        match crossterm_event {
                            CrosstermEvent::Key(key) => {
                                let _ = tx.send(AppEvent::Key(key)).await;
                            }
                            CrosstermEvent::Resize(w, h) => {
                                let _ = tx.send(AppEvent::Resize(w, h)).await;
                            }
                            _ => {}
                        }
                    }
                } else {
                    let _ = tx.send(AppEvent::Tick).await;
                }
            }
        });

        Self { rx }
    }

    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}
