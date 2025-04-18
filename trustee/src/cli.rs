use anyhow::Result;
use clap::{error::Error, Parser};
use openssl::pkey::PKey;

fn trustee_keygen(path: Option<String>) -> Result<()> {
    let private = PKey::generate_ed25519()?;
    let public = private.public_key_to_pem()?;

    if let Some(path) = path {
        std::fs::write(&path, private.private_key_to_pem_pkcs8()?)?;
        let public_path = format!("{path}.pub");
        std::fs::write(&public_path, public)?;
    }

    Ok(())
}

/// Enum to represent different subcommands.
#[derive(Debug, Parser)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Output file for the private key
        #[arg(long = "out")]
        out: Option<String>,
    },
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub fn cli_default() -> Result<(), Error> {
    let cli = Cli::try_parse()?;

    match cli.command {
        Commands::Keygen { out } => trustee_keygen(out).unwrap(),
    };

    Ok(())
}
