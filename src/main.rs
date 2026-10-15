use clap::Parser;
use dfdisk::cli::{exit_code_or_internal_error, run_command, Cli, Commands};
use dfdisk::models::outcome::exit_code;
use dfdisk::signals::AbortController;
use dfdisk::tui;
use std::io::Write;

/// The process exit code comes from here, and only from here (§2): 0
/// verified, 1 internal error, 2 usage, 3 refused, 4 failed, 5 mismatch, 6
/// incomplete, 7 completed with read errors, 8 aborted, 9 complete but
/// unverified. Argument errors are usage errors (2); `--help`/`--version`
/// exit 0; a panic is an internal error (1), not Rust's 101.
#[tokio::main]
async fn main() {
    let code = match Cli::try_parse() {
        Err(e) => {
            let _ = e.print();
            if e.use_stderr() {
                exit_code::USAGE
            } else {
                exit_code::VERIFIED
            }
        }
        Ok(cli) => {
            exit_code_or_internal_error(async move {
                match cli.command {
                    Some(Commands::Tui) | None => run_tui().await,
                    Some(command) => run_command(command).await,
                }
            })
            .await
        }
    };
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code);
}

/// The TUI with this process' abort controller and its one signal listener
/// (installed once per process, §15/§16). Exit code: that of a result the
/// examiner did not acknowledge on screen, else 0; 4 when the signal
/// handlers cannot be installed (a SIGTERM would then end a run without its
/// report), 1 for a terminal failure.
async fn run_tui() -> i32 {
    let controller = AbortController::new();
    let listener = match controller.install() {
        Ok(listener) => listener,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "Error (FAILED): cannot install the signal handlers: {e}"
            );
            return exit_code::FAILED;
        }
    };
    match tui::run_tui_with(controller, Some(listener)).await {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "Error: {e}");
            exit_code::INTERNAL_ERROR
        }
    }
}
