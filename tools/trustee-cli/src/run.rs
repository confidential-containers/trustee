use anyhow::Result;
use kbs::attestation::config::AttestationServiceConfig::CoCoASBuiltIn;
use kbs::plugins::PluginsConfig::ResourceStorage;
use kbs::plugins::RepositoryConfig::LocalFs;
use kbs::{ApiServer, KbsConfig};
use log::{debug, info, warn};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{write_new_auth_key_pair, write_pem};

pub(crate) async fn trustee_run(
    trustee_home_dir: &Path,
    config_file: Option<PathBuf>,
    allow_all: bool,
) -> Result<()> {
    let config = get_config(config_file, allow_all, trustee_home_dir)?;
    let api_server = ApiServer::new(config).await?;
    // Start the kbs::ApiServer in the foreground.
    api_server.server()?.await?;
    Ok(())
}

/// get_config initializes a KbsConfig from the CLI arguments and environment.
fn get_config(
    config_file: Option<PathBuf>,
    allow_all: bool,
    trustee_home_dir: &Path,
) -> Result<KbsConfig> {
    let mut config = if let Some(path) = config_file {
        KbsConfig::try_from(path.as_path())?
    } else {
        KbsConfig::default()
    };

    // Set home dir for policy engine
    config.policy_engine.policy_path =
        replace_base_dir(config.policy_engine.policy_path.as_path(), trustee_home_dir);

    // Set home dir for plugins
    config.plugins.iter_mut().for_each(|plugins_config| {
        if let ResourceStorage(LocalFs(repo_desc)) = plugins_config {
            repo_desc.dir_path = replace_base_dir(Path::new(&repo_desc.dir_path), trustee_home_dir)
                .to_string_lossy()
                .into();
        }
    });

    // Set home dir for CoCoASBuiltIn attestation service
    if let CoCoASBuiltIn(as_config) = &mut config.attestation_service.attestation_service {
        as_config.work_dir = replace_base_dir(as_config.work_dir.as_path(), trustee_home_dir);

        // Handle RVPS config paths
        if let attestation_service::rvps::RvpsConfig::BuiltIn(rvps_config) =
            &mut as_config.rvps_config
        {
            if let reference_value_provider_service::storage::ReferenceValueStorageConfig::LocalFs(
                local_fs_config,
            ) = &mut rvps_config.storage
            {
                local_fs_config.file_path =
                    replace_base_dir(Path::new(&local_fs_config.file_path), trustee_home_dir)
                        .to_string_lossy()
                        .into_owned();
            }
        }

        // Handle attestation token broker paths

        as_config.attestation_token_broker.policy_dir = replace_base_dir(
            Path::new(&as_config.attestation_token_broker.policy_dir),
            trustee_home_dir,
        )
        .to_string_lossy()
        .into_owned();
    }

    // Automatically create a key pair and use it for admin authentication if it doesn't exist in the configuration.
    if config.admin.auth_public_key.is_none() {
        let (_, public_path) = ensure_auth_key_pair(trustee_home_dir)?;

        config.admin.auth_public_key = Some(public_path);
    }

    // Generate and use a self-signed certificate if there is none configured.
    // Intended to discourage using the service in the clear.
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

    // Set the policy path.
    if allow_all {
        warn!("Using policy allow_all. This is for development only.");
        config.policy_engine.policy_path = trustee_home_dir.join("allow_all.rego");
        std::fs::write(
            &config.policy_engine.policy_path,
            include_bytes!("../../../kbs/sample_policies/allow_all.rego"),
        )?;
    } else if !config.policy_engine.policy_path.exists() {
        // Default to the deny_all policy if there is none configured.
        // Intended to ease the deployment process as it allows to have
        // a service up and running and complete the configuration gradually.
        info!("Using policy deny_all. You may want to configure a less restrictive policy for a functional setup.");
        config.policy_engine.policy_path = trustee_home_dir.join("deny_all.rego");
        std::fs::write(
            &config.policy_engine.policy_path,
            include_bytes!("../../../kbs/sample_policies/deny_all.rego"),
        )?;
    }

    debug!("Config: {:?}", config);
    Ok(config)
}

/// Ensure a key pair for authentication exists in the given home directory.
///
/// Create the key files if they don't exist.
/// Return the path to the private and public keys.
fn ensure_auth_key_pair(home_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let (private_path, public_path) = get_key_paths(home_dir, "auth_key");

    if !private_path.try_exists()? {
        write_new_auth_key_pair(&private_path, &public_path)?;
    }

    Ok((private_path, public_path))
}

/// replace_base_dir replaces the leading `/opt/confidential-containers/` in the path with a new base path.
///
/// This behavior is a compromise to set the base directory at runtime and workaround the hardcoded paths all around the codebase.
/// replace_base_dir will become obsolete when it's possible to set the base directory at runtime project-wide.
fn replace_base_dir(path: &Path, new_base: &Path) -> PathBuf {
    let old_base = "/opt/confidential-containers/";
    if let Ok(suffix) = path.strip_prefix(old_base) {
        new_base.join(suffix)
    } else if path.starts_with("/") {
        path.to_path_buf()
    } else {
        new_base.join(path)
    }
}

/// Ensure a key pair for HTTPS exists in the given home directory.
///
/// Create the key files if they don't exist.
/// Return the path to the private and public keys.
fn ensure_https_key_pair(home_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let (private_path, public_path) = get_key_paths(home_dir, "https_key");

    if !private_path.try_exists()? {
        let rsa = Rsa::generate(2048)?;
        let private_key = PKey::from_rsa(rsa)?;

        write_pem(&private_path, &public_path, &private_key)?;
    }

    Ok((private_path, public_path))
}

fn get_key_paths(base_dir: &Path, key_name: &str) -> (PathBuf, PathBuf) {
    let private_path = base_dir.join(key_name);
    let public_path = private_path.with_extension("pub");
    (private_path, public_path)
}

/// Ensure a HTTPS certificate exists in the given home directory.
///
/// Create a self-signed certificate if it doesn't exist.
///
/// Returns the path to the certificate.
fn ensure_https_cert(home_dir: &Path, private_path: &Path) -> Result<PathBuf> {
    let certificate_path = home_dir.join("https_cert.pem");

    if !certificate_path.try_exists()? {
        write_new_https_cert(&certificate_path, private_path)?;
    }

    Ok(certificate_path)
}

/// Generate a new certificate for HTTPS and write it to the given path.
///
/// Use the given private key to sign the certificate.
fn write_new_https_cert(certificate_path: &Path, private_path: &Path) -> Result<()> {
    // Load the private key from the provided path
    let private_key = {
        let private_key_data = std::fs::read(private_path)?;
        PKey::private_key_from_pem(&private_key_data)?
    };

    let name = {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", "localhost")?;
        name_builder.build()
    };

    // Create a self-signed certificate
    let certificate = {
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(name.as_ref())?;
        builder.set_issuer_name(name.as_ref())?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
        builder.set_pubkey(private_key.as_ref())?;
        builder.set_serial_number(
            openssl::asn1::Asn1Integer::from_bn(openssl::bn::BigNum::from_u32(1)?.as_ref())?
                .as_ref(),
        )?;
        builder.sign(private_key.as_ref(), MessageDigest::sha256())?;
        builder.build()
    };

    // Write certificate to file
    File::create_new(certificate_path)?.write_all(&certificate.to_pem()?)?;

    Ok(())
}
