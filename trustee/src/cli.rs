use std::path::Path;

use anyhow::Result;
use clap::{error::Error, Parser};
use openssl::pkey::PKey;
use tokio;

use kbs::{ApiServer, KbsConfig};

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

async fn trustee_run(config_file: &str) -> Result<()> {
    let kbs_config = KbsConfig::try_from(Path::new(config_file))?;
    let api_server = ApiServer::new(kbs_config).await?;
    // TODO initialize the components separately
    // and spawn each one within try_join
    tokio::try_join!(api_server.server()?)?;
    Ok(())
}

#[derive(Debug, Parser)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Output file for the private key
        #[arg(long = "out")]
        out: Option<String>,
    },
    /// Launch Trustee
    Run {
        /// Configuration file
        #[arg(long = "config")]
        config_file: String,
    },
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub async fn cli_default() -> Result<(), Error> {
    let cli = Cli::try_parse()?;

    match cli.command {
        Commands::Keygen { out } => trustee_keygen(out).unwrap(),
        Commands::Run { config_file } => trustee_run(&config_file).await.unwrap(),
    };

    Ok(())
}
