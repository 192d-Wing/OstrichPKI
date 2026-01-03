//! OstrichPKI Command Line Interface
//!
//! Administrative CLI tool for managing OstrichPKI services

mod ca;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ostrich-cli")]
#[command(about = "OstrichPKI administrative command-line interface", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Certificate Authority operations
    #[command(subcommand)]
    Ca(ca::CaCommands),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ca(cmd) => ca::handle_command(cmd).await?,
    }

    Ok(())
}
