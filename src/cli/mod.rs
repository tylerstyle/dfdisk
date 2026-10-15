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
use crate::signals::AbortController;
use console::Console;

/// Run one command (not the TUI) and return its exit code. Acquire, check,
/// verify and convert listen for SIGINT/SIGTERM/SIGHUP (once per process,
/// §15); list and unmount keep the default signal behaviour.
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
    let listen = matches!(
        command,
        Commands::Acquire(_) | Commands::Check(_) | Commands::Verify(_) | Commands::Convert(_)
    );
    let mut listener = if listen {
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
        Commands::Unmount(args) => handle_unmount(args, console).await,
        Commands::Verify(args) => handle_verify(args, controller, &mut listener, console).await,
        Commands::Convert(args) => handle_convert(args, controller, &mut listener, console).await,
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
