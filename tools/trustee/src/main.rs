use anyhow::Result;
use clap::Parser;
use nix::unistd::Uid;
use openssl::pkey::{PKey, Private};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use dirs::home_dir;
mod keygen;
mod run;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Path to the directory for storing config and data
    #[arg(long, global = true, value_name = "PATH", env = "TRUSTEE_HOME", default_value = default_home())]
    home: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) enum Commands {
    /// Generate a new key pair (Ed25519)
    Keygen {
        /// Output file for the private key
        #[arg(short = 'f')]
        output_file: Option<PathBuf>,
    },
    /// Launch Trustee. Uses a self-signed HTTPS certificate with a RSA 2048 key by default
    Run {
        /// Configuration file
        #[arg(long)]
        config_file: Option<PathBuf>,
        /// Use built-in policy to allow all (development only).
        /// If neither this nor a policy file is provided, the default policy is to deny all.
        #[arg(long)]
        allow_all: bool,
    },
}

/// default_home calculates a default home folder for trustee according to the current user.
///
/// - `$HOME/.trustee` for all users other than root.
/// - `/opt/confidential-containers/` remains the base path when running as root.
///
/// This enables running the CLI as any user who can't write `/opt/confidential-containers/`.
fn default_home() -> OsString {
    if Uid::effective().is_root() {
        "/opt/confidential-containers".into()
    } else {
        home_dir()
            .unwrap_or_default()
            .join(".trustee")
            .into_os_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.home)?;

    match cli.command {
        Commands::Keygen { output_file } => {
            let out = output_file.unwrap_or_else(|| cli.home.join("key"));
            keygen::trustee_keygen(&out)
        }
        Commands::Run {
            config_file,
            allow_all,
        } => run::trustee_run(&cli.home, config_file, allow_all).await,
    }
}

/// Write a key to separate files: one for private, one for public.
///
/// Error if the file already exists.
fn write_pem(private_path: &Path, public_path: &Path, private_key: &PKey<Private>) -> Result<()> {
    // Write the private key.
    write_private(private_path, private_key)?;

    // Write the public key.
    File::create_new(public_path)?.write_all(&private_key.public_key_to_pem()?)?;

    Ok(())
}

/// Write the private key to a file private to the owner.
fn write_private(path: &Path, key: &PKey<Private>) -> Result<()> {
    let mut f = File::create_new(path)?;
    #[cfg(unix)]
    f.set_permissions(PermissionsExt::from_mode(0o600))?;
    f.write_all(&key.private_key_to_pem_pkcs8()?)?;
    Ok(())
}

/// Generate a new key for authentication and write to the given file paths.
pub(crate) fn write_new_auth_key_pair(private_path: &Path, public_path: &Path) -> Result<()> {
    let private_key = PKey::generate_ed25519()?;
    write_pem(&private_path, &public_path, &private_key)
}
