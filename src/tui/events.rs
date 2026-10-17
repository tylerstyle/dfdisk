//! Terminal input for the TUI: key presses and resizes, read on a thread of
//! its own and forwarded over a channel. The channel closes when the terminal
//! goes away (hang-up or a read error), so the main loop finishes headless.
//!
//! crossterm 0.29 never returns from a read on a hung-up terminal: its event
//! source only leaves its read loop on WouldBlock, and a dead tty answers
//! EOF or EIO, so it spins at full CPU (with its `EventStream` too, for the
//! rest of a headless acquisition). The reader therefore polls the terminal
//! itself and asks crossterm only once input is waiting.

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use std::fs::File;
use std::io::IsTerminal;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Key(KeyEvent),
    Resize(u16, u16),
}

/// How long the reader waits for input before it checks that the UI still
/// listens.
const POLL: Duration = Duration::from_millis(100);

pub struct EventHandler {
    rx: mpsc::Receiver<AppEvent>,
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHandler {
    /// Start reading terminal events.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(100);
        std::thread::Builder::new()
            .name("dfdisk-input".into())
            .spawn(move || read_events(&tx))
            .expect("start the terminal input thread");
        Self { rx }
    }

    /// The next event; `None` once the terminal input is gone.
    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}

/// Read until the terminal goes away or the UI stops listening. Returning
/// drops `tx`, which closes the channel.
fn read_events(tx: &mpsc::Sender<AppEvent>) {
    // crossterm reads stdin when it is a terminal, else /dev/tty: watch the
    // same terminal
    let tty = (!std::io::stdin().is_terminal())
        .then(|| File::open("/dev/tty").ok())
        .flatten();
    let fd = tty.as_ref().map_or(libc::STDIN_FILENO, |f| f.as_raw_fd());
    loop {
        match poll_fd(fd, POLL) {
            Polled::Hangup => return,
            Polled::Timeout | Polled::Interrupted => {}
            // A hang-up between this poll and crossterm's read is the one
            // window left in which crossterm can still spin
            Polled::Ready => loop {
                match event::poll(Duration::ZERO) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return,
                }
                let forward = match event::read() {
                    Ok(CrosstermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                        Some(AppEvent::Key(key))
                    }
                    Ok(CrosstermEvent::Resize(w, h)) => Some(AppEvent::Resize(w, h)),
                    Ok(_) => None,
                    Err(_) => return,
                };
                if let Some(ev) = forward {
                    if tx.blocking_send(ev).is_err() {
                        return;
                    }
                }
            },
        }
        if tx.is_closed() {
            return;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polled {
    Ready,
    Timeout,
    Interrupted,
    /// The terminal hung up or the descriptor is no longer usable
    Hangup,
}

/// Wait up to `timeout` for input on `fd`.
fn poll_fd(fd: RawFd, timeout: Duration) -> Polled {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    // SAFETY: one valid pollfd, and the count says one
    let n = unsafe { libc::poll(&mut pfd, 1, ms) };
    if n < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            Polled::Interrupted
        } else {
            Polled::Hangup
        };
    }
    if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        Polled::Hangup
    } else if pfd.revents & libc::POLLIN != 0 {
        Polled::Ready
    } else {
        Polled::Timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: fds has room for the two descriptors pipe() writes
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors are new and owned only here
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn a_pipe_is_ready_waits_or_hangs_up() {
        let (r, w) = pipe();
        let short = Duration::from_millis(10);
        assert_eq!(poll_fd(r.as_raw_fd(), short), Polled::Timeout);
        // SAFETY: writing one byte from a valid buffer to an open pipe
        assert_eq!(
            unsafe { libc::write(w.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        assert_eq!(poll_fd(r.as_raw_fd(), short), Polled::Ready);
        let mut buf = [0u8; 1];
        // SAFETY: reading one byte into a valid buffer
        assert_eq!(
            unsafe { libc::read(r.as_raw_fd(), buf.as_mut_ptr().cast(), 1) },
            1
        );
        drop(w);
        assert_eq!(poll_fd(r.as_raw_fd(), short), Polled::Hangup);
    }

    /// The real case: the terminal emulator (the pty master) goes away
    #[test]
    fn a_terminal_whose_other_end_closed_hangs_up() {
        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty writes two descriptors; name, termios and winsize
        // may be null
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if rc != 0 {
            eprintln!(
                "skipped: no pseudo-terminal here ({})",
                std::io::Error::last_os_error()
            );
            return;
        }
        // SAFETY: both descriptors are new and owned only here
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let short = Duration::from_millis(10);
        assert_eq!(poll_fd(slave.as_raw_fd(), short), Polled::Timeout);
        drop(master);
        assert_eq!(poll_fd(slave.as_raw_fd(), short), Polled::Hangup);
    }
}
