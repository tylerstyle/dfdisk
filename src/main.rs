mod cli;
mod discovery;
mod engines;
mod models;
mod tui;

use clap::Parser;
use cli::{handle_acquire, handle_convert, handle_list, handle_verify, Cli, Commands};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Tui) | None => {
            // Default behavior: launch interactive TUI
            tui::run_tui().await?;
        }
        Some(Commands::List(args)) => {
            handle_list(args).await?;
        }
        Some(Commands::Acquire(args)) => {
            handle_acquire(args).await?;
        }
        Some(Commands::Convert(args)) => {
            handle_convert(args).await?;
        }
        Some(Commands::Verify(args)) => {
            handle_verify(args).await?;
        }
    }

    Ok(())
}
