use clap::Parser;
use dfdisk::cli::{handle_acquire, handle_convert, handle_list, handle_verify, Cli, Commands};
use dfdisk::models::outcome::exit_code;
use dfdisk::tui;
use std::io::Write;

/// Exit codes (§2): 0 verified, 1 internal error, 2 usage, 3 refused,
/// 4 failed, 5 mismatch, 6 incomplete, 7 completed with read errors,
/// 8 aborted, 9 complete but unverified. Clap exits with 2 on its own usage
/// errors.
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Tui) | None => match tui::run_tui().await {
            Ok(()) => Ok(exit_code::VERIFIED),
            Err(e) => {
                eprintln!("Error: {e}");
                Ok(exit_code::INTERNAL_ERROR)
            }
        },
        Some(Commands::List(args)) => handle_list(args).await,
        Some(Commands::Acquire(args)) => handle_acquire(args).await,
        Some(Commands::Convert(args)) => handle_convert(args).await,
        Some(Commands::Verify(args)) => handle_verify(args).await,
    };

    // Errors are printed once, here
    let code = match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error ({}): {e}", e.kind.label());
            e.exit_code()
        }
    };
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code);
}
