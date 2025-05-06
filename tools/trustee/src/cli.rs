use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{error::Error, Parser};
use dirs::home_dir;
use log::info;

use crate::keys_certs::new_auth_key_pair;

fn trustee_keygen(trustee_home_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let (private, public) = new_auth_key_pair(trustee_home_dir)?;
    info!("Wrote new private key: {:?}", private);
    info!("Wrote new public key: {:?}", public);
    Ok((private, public))
}

#[derive(Debug, Parser)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Output file for the private key
        #[arg(short = 'f')]
        output_file: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Path to the directory for storing config and data
    #[arg(long, value_name = "PATH", env = "TRUSTEE_HOME")]
    home: Option<PathBuf>,
}

pub async fn cli_default() -> Result<(), Error> {
    let cli = Cli::try_parse()?;

    let trustee_home_dir = cli.home.unwrap_or_else(|| {
        if Uid::effective().is_root() {
            "/opt/confidential-containers".into()
        } else {
            home_dir().unwrap_or_default().join(".trustee")
        }
    });

    if !trustee_home_dir.exists() {
        std::fs::create_dir_all(&trustee_home_dir)?;
    }

    match cli.command {
        Commands::Keygen { output_file: out } => {
            let out = out.unwrap_or_else(|| trustee_home_dir.join("key"));
            trustee_keygen(&out).unwrap();
        }
    };

    Ok(())
}
