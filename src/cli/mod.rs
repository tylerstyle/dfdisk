//! The command line (§15). [`run_command`] runs one command and returns the
//! process exit code (§2); errors are printed here, once, with their kind.

pub mod acquire;
pub mod args;
pub mod console;
pub mod drive;
pub mod handlers;
pub mod resolve;
pub mod size;

#[cfg(test)]
mod tests;

pub use acquire::{handle_acquire, handle_check};
pub use args::{Cli, Commands};
pub use handlers::{handle_convert, handle_list, handle_unmount, handle_verify};

use crate::engines::AcquisitionError;
use crate::signals::{AbortController, SignalListener};
use console::Console;
use std::future::Future;

/// Run one command (not the TUI) and return its exit code. Acquire, check,
/// unmount, verify and convert listen for SIGINT/SIGTERM/SIGQUIT/SIGHUP (once
/// per process, §15); list keeps the default signal behaviour.
pub async fn run_command(command: Commands) -> i32 {
    let controller = AbortController::new();
    let console = Console::stdio(command.json(), controller.headless_flag());
    let result = dispatch(command, &controller, &console).await;
    finish(&console, result)
}

async fn dispatch(
    command: Commands,
    controller: &AbortController,
    console: &Console,
) -> Result<i32, AcquisitionError> {
    let mut listener = if listens(&command) {
        Some(controller.install().map_err(|e| {
            AcquisitionError::failed(format!("cannot install the signal handlers: {e}"))
        })?)
    } else {
        None
    };
    match command {
        Commands::Tui => Err(AcquisitionError::usage(
            "the terminal UI is started by main, not by run_command",
        )),
        Commands::List(args) => handle_list(args, console).await,
        Commands::Acquire(args) => handle_acquire(args, controller, &mut listener, console).await,
        Commands::Check(args) => handle_check(args, &mut listener, console).await,
        Commands::Unmount(args) => {
            unmount_to_the_end(handle_unmount(args, console), &mut listener, console).await
        }
        Commands::Verify(args) => handle_verify(args, controller, &mut listener, console).await,
        Commands::Convert(args) => handle_convert(args, controller, &mut listener, console).await,
    }
}

/// Commands that listen for signals (the rest keep the default behaviour).
fn listens(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Acquire(_)
            | Commands::Check(_)
            | Commands::Unmount(_)
            | Commands::Verify(_)
            | Commands::Convert(_)
    )
}

/// Await an unmount to its end whatever signal arrives (each is reported):
/// cut short, umount would still have run but its audit record and the check
/// that nothing stayed mounted would not (safety L2).
async fn unmount_to_the_end<T>(
    work: impl Future<Output = T>,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> T {
    tokio::pin!(work);
    loop {
        tokio::select! {
            result = &mut work => break result,
            (kind, _) = drive::next_signal(listener) => console.note(&format!(
                "[!] {}: the unmount in progress is finished, checked and recorded in the audit log before dfdisk exits",
                kind.name()
            )),
        }
    }
}

/// The exit code of a command's result; an error is printed once (stderr,
/// and as `{"error": ..}` on stdout with `--json`).
pub fn finish(console: &Console, result: Result<i32, AcquisitionError>) -> i32 {
    match result {
        Ok(code) => code,
        Err(e) => {
            console.end_progress();
            if console.json() {
                console.data(
                    &serde_json::to_string_pretty(&acquire::error_json(&e)).unwrap_or_default(),
                );
            }
            console.note(&format!("Error ({}): {e}", e.kind.label()));
            e.exit_code()
        }
    }
}

#[cfg(test)]
mod unmount_signal_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unmount_listens_for_signals() {
        let unmount = Commands::Unmount(args::UnmountArgs {
            device: "/dev/sdx".into(),
            json: false,
        });
        assert!(listens(&unmount));
        assert!(!listens(&Commands::Tui));
    }

    #[tokio::test]
    async fn an_unmount_runs_to_its_end_whatever_signal_arrives() {
        let controller = AbortController::new();
        let mut listener = Some(controller.install().unwrap());
        let (console, _out, err) = Console::capture(false);
        // SIGHUP only: SIGINT/SIGTERM would stay caught for the whole test
        // binary (the listener above catches this one)
        let signal = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // SAFETY: sending a signal to our own process
            unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        };
        let unmount = async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            "recorded"
        };
        let (result, ()) =
            tokio::join!(unmount_to_the_end(unmount, &mut listener, &console), signal);
        assert_eq!(result, "recorded");
        assert!(
            err.text().contains(
                "SIGHUP: the unmount in progress is finished, checked and recorded in the audit log"
            ),
            "{}",
            err.text()
        );
    }
}
