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

/// `schema_version` of the JSON documents the CLI prints besides the
/// reports: `check --json`, `verify --json`, `unmount --json`, the error
/// object and the `acquire --rescue-to-e01 --json` document
/// (docs/report-format.md, "Other JSON output").
pub const CLI_JSON_SCHEMA_VERSION: u32 = 1;

/// `value` (an object) with `schema_version` set to
/// [`CLI_JSON_SCHEMA_VERSION`].
pub fn with_schema_version(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(map) = value.as_object_mut() {
        map.insert(
            "schema_version".into(),
            serde_json::json!(CLI_JSON_SCHEMA_VERSION),
        );
    }
    value
}

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

/// Run `run` (a command or the TUI) and turn a panic into exit code 1
/// (internal error) with a message on stderr, instead of Rust's 101 (T6).
/// The panic hook has already printed where it happened; unwinding has run
/// the audit guards ("acquisition_finished" with exit code 1) and the TUI's
/// hook has restored the terminal.
pub async fn exit_code_or_internal_error<F>(run: F) -> i32
where
    F: std::future::Future<Output = i32>,
{
    use futures::FutureExt;
    match std::panic::AssertUnwindSafe(run).catch_unwind().await {
        Ok(code) => code,
        Err(payload) => {
            let what = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "no message".to_string());
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "Error (INTERNAL ERROR): dfdisk stopped on an internal error (panic: {}). This is a bug; please report it.",
                crate::models::text::sanitize_line(&what)
            );
            crate::models::outcome::exit_code::INTERNAL_ERROR
        }
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

/// Whether the command line asks for JSON output (I-J1), read without the
/// parser (for an argument error, which the parser could not turn into a
/// command): `--json` before a `--`, or for `list` its short `-j`, also in a
/// group of short flags.
pub fn wants_json(args: &[std::ffi::OsString]) -> bool {
    let args: Vec<String> = args
        .iter()
        .skip(1)
        .take_while(|a| a.as_os_str() != "--")
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let list = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
        == Some("list");
    args.iter().any(|a| {
        a == "--json"
            || (list
                && a.len() > 1
                && a.starts_with('-')
                && !a.starts_with("--")
                && a[1..].chars().all(|c| c.is_ascii_alphabetic())
                && a.contains('j'))
    })
}

/// The JSON error document of an argument error (`kind` usage, exit code 2)
/// for a command line that asked for JSON: every command prints one JSON
/// document with `--json`, an argument error included.
pub fn usage_error_document(args: &[std::ffi::OsString], message: &str) -> Option<String> {
    if !wants_json(args) {
        return None;
    }
    let message = message.trim();
    let message = message.strip_prefix("error: ").unwrap_or(message);
    let e = AcquisitionError::usage(crate::models::text::sanitize_line(message));
    serde_json::to_string_pretty(&acquire::error_json(&e)).ok()
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
