use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use dirs::home_dir;
use log::{debug, info, warn};
use nix::unistd::Uid;

use crate::keys_certs::{
    ensure_auth_key_pair, ensure_https_cert, ensure_https_key_pair, write_new_auth_key_pair,
};
use kbs::attestation::config::AttestationServiceConfig::CoCoASBuiltIn;
use kbs::{ApiServer, KbsConfig};

fn trustee_keygen(private_path: &Path) -> Result<()> {
    let public_path = private_path.with_extension("pub");
    write_new_auth_key_pair(&private_path, &public_path)?;
    info!("Wrote new private key: {:?}", private_path);
    info!("Wrote new public key: {:?}", public_path);
    Ok(())
}

fn replace_base_dir(path: &Path, new_base: &Path) -> PathBuf {
    let old_base = "/opt/confidential-containers/";
    let suffix = if path.starts_with(old_base) {
        path.strip_prefix(old_base).unwrap()
    } else {
        path
    };
    new_base.join(suffix)
}

fn get_config(
    config_file: Option<PathBuf>,
    allow_all: bool,
    trustee_home_dir: &Path,
) -> Result<KbsConfig> {
    let mut config = config_file
        .map(|config_file| KbsConfig::try_from(config_file.as_path()).unwrap())
        .unwrap_or_default();

    config.policy_engine.policy_path =
        replace_base_dir(config.policy_engine.policy_path.as_path(), trustee_home_dir);

    match &mut config.attestation_service.attestation_service {
        CoCoASBuiltIn(as_config) => {
            as_config.work_dir = replace_base_dir(as_config.work_dir.as_path(), trustee_home_dir);
            
            // Handle RVPS config paths
            if let attestation_service::rvps::RvpsConfig::BuiltIn(rvps_config) = &mut as_config.rvps_config {
                if let reference_value_provider_service::storage::ReferenceValueStorageConfig::LocalFs(local_fs_config) = &mut rvps_config.storage {
                    local_fs_config.file_path = replace_base_dir(Path::new(&local_fs_config.file_path), trustee_home_dir).to_string_lossy().into_owned();
                }
            }

            // Handle attestation token broker paths
            if let attestation_service::token::AttestationTokenConfig::Ear(ear_config) = &mut as_config.attestation_token_broker {
                ear_config.policy_dir = replace_base_dir(Path::new(&ear_config.policy_dir), trustee_home_dir).to_string_lossy().into_owned();
            }
        }
        _ => {}
    }

    if config.admin.auth_public_key.is_none() {
        let (_, public_path) = ensure_auth_key_pair(trustee_home_dir)?;

        config.admin.auth_public_key = Some(public_path);
    }

    if !config.http_server.insecure_http {
        if config.http_server.private_key.is_none() {
            let (private_path, _) = ensure_https_key_pair(trustee_home_dir)?;

            config.http_server.private_key = Some(private_path);
        }

        if config.http_server.certificate.is_none() {
            let private_key = config.http_server.private_key.as_ref().unwrap();
            config.http_server.certificate =
                Some(ensure_https_cert(trustee_home_dir, private_key)?);
        }
    }

    if allow_all {
        warn!("Using policy allow_all. This is for development only.");
        config.policy_engine.policy_path = trustee_home_dir.join("allow_all.rego");
        std::fs::write(
            &config.policy_engine.policy_path,
            include_bytes!("../../../kbs/sample_policies/allow_all.rego"),
        )?;
    } else if !config.policy_engine.policy_path.exists() {
        config.policy_engine.policy_path = trustee_home_dir.join("deny_all.rego");
        std::fs::write(
            &config.policy_engine.policy_path,
            include_bytes!("../../../kbs/sample_policies/deny_all.rego"),
        )?;
    }

    debug!("Config: {:?}", config);
    Ok(config)
}

async fn trustee_run(config: KbsConfig) -> Result<()> {
    let api_server = ApiServer::new(config).await?;
    api_server.server()?.await?;
    Ok(())
}

#[derive(Debug, Parser)]
pub(crate) enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Output file for the private key
        #[arg(short = 'f')]
        output_file: Option<PathBuf>,
    },
    /// Launch Trustee
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

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Path to the directory for storing config and data
    #[arg(long, value_name = "PATH", env = "TRUSTEE_HOME")]
    home: Option<PathBuf>,
}

pub async fn cli_default() -> Result<()> {
    let cli = Cli::parse();

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
            trustee_keygen(&out)?;
        }
        Commands::Run {
            config_file,
            allow_all,
        } => {
            let config = get_config(config_file, allow_all, &trustee_home_dir)?;
            trustee_run(config).await?;
        }
    };

    Ok(())
}
