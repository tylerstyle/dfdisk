use clap::Parser;
use dfdisk::cli::{run_command, Cli, Commands};
use dfdisk::models::outcome::exit_code;
use dfdisk::tui;
use std::io::Write;

/// The process exit code comes from here, and only from here (§2): 0
/// verified, 1 internal error, 2 usage, 3 refused, 4 failed, 5 mismatch, 6
/// incomplete, 7 completed with read errors, 8 aborted, 9 complete but
/// unverified. Argument errors are usage errors (2); `--help`/`--version`
/// exit 0.
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
        Ok(cli) => match cli.command {
            Some(Commands::Tui) | None => match tui::run_tui().await {
                Ok(()) => exit_code::VERIFIED,
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "Error: {e}");
                    exit_code::INTERNAL_ERROR
                }
            },
            Some(command) => run_command(command).await,
        },
    };
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code);
}
