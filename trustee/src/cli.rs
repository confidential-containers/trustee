use anyhow::Result;
use clap::{error::Error, Parser};

/// Enum to represent different subcommands.
#[derive(Debug, Parser)]
enum Commands {}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub fn cli_default() -> Result<(), Error> {
    let cli = Cli::try_parse()?;

    Ok(())
}
