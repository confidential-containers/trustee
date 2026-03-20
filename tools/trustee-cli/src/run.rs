use anyhow::Result;
use core::net::SocketAddr;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use kbs::admin::{authorization::AuthorizerType, token_verifier::TokenVerifierType, AdminConfig};
use kbs::plugins::PluginsConfig;
use kbs::plugins::RepositoryConfig;
use kbs::{ApiServer, KbsConfig};
use openssl::asn1::Asn1Time;
use openssl::bn::MsbOption;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509NameBuilder, X509};
use serde::Serialize;
use std::fs::write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::write_pem;

pub(crate) async fn trustee_run(
    trustee_home_dir: &Path,
    config_file: Option<PathBuf>,
    allow_all: bool,
) -> Result<()> {
    let config = get_config(config_file, trustee_home_dir)?;
    if let Err(e) = maybe_generate_admin_token(&config.admin, trustee_home_dir) {
        warn!("Failed to generate admin token automatically: {e}");
    }
    let api_server = ApiServer::new(config).await?;

    // Start the kbs::ApiServer in the foreground.
    // Set the policy path.
    if allow_all {
        warn!("Using policy allow_all. This is for development only.");
        api_server
            .policy_engine
            .set_policy(
                "resource-policy",
                include_str!("../../../kbs/sample_policies/allow_all.rego"),
                true,
            )
            .await?;
    }

    api_server.server()?.await?;
    Ok(())
}

/// get_config initializes a KbsConfig from the CLI arguments and environment.
fn get_config(config_file: Option<PathBuf>, trustee_home_dir: &Path) -> Result<KbsConfig> {
    let mut config = if let Some(path) = config_file {
        KbsConfig::try_from(path.as_path())?
    } else {
        KbsConfig::default()
    };

    if config.plugins.is_empty() {
        config
            .plugins
            .push(PluginsConfig::ResourceStorage(RepositoryConfig::default()));
    }

    config
        .storage_backend
        .backends
        .replace_base_dir(trustee_home_dir);

    // Generate and use a self-signed certificate if there is none configured.
    // Intended to discourage using the service in the clear.
    if !config.http_server.insecure_http {
        if config.http_server.private_key.is_none() {
            let (private_path, _) = ensure_https_key_pair(trustee_home_dir)?;

            config.http_server.private_key = Some(private_path);
        }

        if config.http_server.certificate.is_none() {
            let private_key = {
                let private_key_data = std::fs::read(
                    config
                        .http_server
                        .private_key
                        .as_ref()
                        .expect("private_key should be already set in config"),
                )?;
                PKey::private_key_from_pem(&private_key_data)?
            };

            let cert = build_x509(&config.http_server.sockets, private_key)?;
            let cert_path = trustee_home_dir.join("https_cert_cache.pem");
            write(&cert_path, &cert.to_pem()?)?;

            config.http_server.certificate = Some(cert_path);
        }
    }

    debug!("Config: {:?}", config);
    Ok(config)
}

#[derive(Serialize)]
struct AdminClaims {
    issuer: String,
    subject: String,
    audiences: Vec<String>,
    iat: u64,
    exp: u64,
}

fn maybe_generate_admin_token(admin: &AdminConfig, trustee_home_dir: &Path) -> Result<()> {
    let (token_verifier, authorizer) = match admin {
        AdminConfig::TokenAuthorization {
            token_verifier,
            authorizer,
        } => (token_verifier, authorizer),
        _ => return Ok(()),
    };

    let (issuer, public_key_uri): (String, PathBuf) = match token_verifier {
        TokenVerifierType::BearerJwt(config) => {
            let Some(idp) = config.idps.first() else {
                return Ok(());
            };
            let Some(public_key_uri) = idp.public_key_uri.clone() else {
                return Ok(());
            };
            (idp.issuer.clone(), PathBuf::from(public_key_uri))
        }
    };

    let audience = match authorizer {
        AuthorizerType::RegexAcl(_) => issuer.clone(),
    };

    let signing_key_path = infer_signing_key_path(&public_key_uri)
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No matching private key found for admin signer public key {}",
                public_key_uri.display()
            )
        })?;

    let private_key_pem = std::fs::read(&signing_key_path)?;
    let (encoding_key, alg) = if let Ok(key) = EncodingKey::from_ec_pem(&private_key_pem) {
        (key, Algorithm::ES256)
    } else if let Ok(key) = EncodingKey::from_rsa_pem(&private_key_pem) {
        (key, Algorithm::RS256)
    } else {
        (
            EncodingKey::from_ed_pem(&private_key_pem)?,
            Algorithm::EdDSA,
        )
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // Long-lived developer token. Do not use this pattern in production.
    let exp = now + Duration::from_secs(60 * 60 * 24 * 365 * 10).as_secs();
    let claims = AdminClaims {
        issuer,
        subject: String::new(),
        audiences: vec![audience],
        iat: now,
        exp,
    };

    let token = encode(&Header::new(alg), &claims, &encoding_key)?;
    let token_path = trustee_home_dir.join("admin-token");
    std::fs::write(&token_path, format!("{token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!(
        "Generated admin token at {}. You can use it with `kbs-client config --admin-token-file {}`.",
        token_path.display(),
        token_path.display()
    );
    Ok(())
}

fn infer_signing_key_path(public_key_path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // common: foo.pub -> foo
    if public_key_path.extension().and_then(|e| e.to_str()) == Some("pub") {
        candidates.push(public_key_path.with_extension(""));
    }
    // docker-compose convention: public.pub -> private.key
    if public_key_path.file_name().and_then(|n| n.to_str()) == Some("public.pub") {
        candidates.push(public_key_path.with_file_name("private.key"));
    }
    // fallback: same directory auth_key/private.key
    if let Some(parent) = public_key_path.parent() {
        candidates.push(parent.join("auth_key"));
        candidates.push(parent.join("private.key"));
    }

    candidates
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

fn build_x509(sockets: &[SocketAddr], private_key: PKey<Private>) -> Result<X509> {
    let name = {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", "localhost")?;
        name_builder.build()
    };

    let mut san_builder = SubjectAlternativeName::new();
    san_builder.dns("localhost");
    san_builder.dns("localhost.localdomain");
    for socket in sockets {
        san_builder.ip(socket.ip().to_string().as_str());
    }

    let serial = {
        let mut bn = openssl::bn::BigNum::new()?;
        bn.rand(128, MsbOption::ONE, false)?;
        openssl::asn1::Asn1Integer::from_bn(bn.as_ref())?
    };

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(name.as_ref())?;
    builder.set_issuer_name(name.as_ref())?;
    builder.append_extension(san_builder.build(&builder.x509v3_context(None, None))?)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.set_pubkey(private_key.as_ref())?;
    builder.set_serial_number(serial.as_ref())?;
    builder.sign(private_key.as_ref(), MessageDigest::sha256())?;
    Ok(builder.build())
}
