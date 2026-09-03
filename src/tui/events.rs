use crossterm::event::{Event as CrosstermEvent, EventStream, KeyEvent, KeyEventKind};
use futures::StreamExt;
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
            let mut reader = EventStream::new();
            let mut interval = tokio::time::interval(tick_rate);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if tx.send(AppEvent::Tick).await.is_err() {
                            break;
                        }
                    }
                    maybe_event = reader.next() => {
                        match maybe_event {
                            Some(Ok(crossterm_event)) => {
                                match crossterm_event {
                                    CrosstermEvent::Key(key)
                                        if key.kind == KeyEventKind::Press
                                            && tx.send(AppEvent::Key(key)).await.is_err() =>
                                    {
                                        break;
                                    }
                                    CrosstermEvent::Resize(w, h)
                                        if tx.send(AppEvent::Resize(w, h)).await.is_err() =>
                                    {
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            Some(Err(_)) => {}
                            None => break,
                        }
                    }
                }
            }
        });

        Self { rx }
    }

    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}
