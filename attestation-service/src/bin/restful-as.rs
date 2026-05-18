use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_cors::Cors;
use actix_web::{http::header, web, App, HttpServer};
use anyhow::Result;
use attestation_service::{config::Config, config::ConfigError, AttestationService, ServiceError};
use clap::{arg, command, Parser};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
};
use shadow_rs::shadow;
use strum::{AsRefStr, EnumString};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

use crate::restful::{attestation, get_challenge, get_policies, set_policy};

mod restful;

shadow!(build);

/// RESTful-AS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a CoCo-AS config file.
    #[arg(short, long)]
    pub config_file: Option<String>,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    #[arg(short, long)]
    pub socket: SocketAddr,

    /// Path to the TLS certificate file (PEM). Both certificate and private
    /// key must be provided to enable HTTPS.
    #[arg(short = 't', long = "tls-cert", alias = "https-pubkey-cert")]
    pub tls_cert: Option<PathBuf>,

    /// Path to the TLS private key file (PEM). Both certificate and private
    /// key must be provided to enable HTTPS.
    #[arg(short = 'k', long = "tls-key", alias = "https-prikey")]
    pub tls_key: Option<PathBuf>,

    /// Allowed origin for CORS access (e.g., "http://localhost:3000")
    /// Can be specified multiple times or comma-separated
    #[arg(short = 'r', long = "allowed_origin", value_delimiter = ',', num_args = 1..)]
    pub allowed_origin: Vec<String>,

    /// Require post-quantum cryptography for TLS.
    /// When true, the server refuses to start if no PQC hybrid groups
    /// are supported by the OpenSSL build, and only PQC hybrid groups
    /// are offered — clients without PQC support cannot connect.
    #[arg(long)]
    pub require_pqc: bool,
}

#[derive(EnumString, AsRefStr)]
#[strum(serialize_all = "lowercase")]
enum WebApi {
    #[strum(serialize = "/attestation")]
    Attestation,

    #[strum(serialize = "/policy")]
    Policy,

    #[strum(serialize = "/challenge")]
    Challenge,
}

#[derive(Error, Debug)]
pub enum RestfulError {
    #[error("Creating service failed: {0}")]
    Service(#[from] ServiceError),
    #[error("Failed to read AS config file: {0}")]
    Config(#[from] ConfigError),
    #[error("Openssl errorstack: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("failed to read HTTPS private key: {0}")]
    ReadHttpsKey(#[source] std::io::Error),
    #[error("failed to get HTTPS private key from pem: {0}")]
    ReadHttpsKeyFromPem(#[source] openssl::error::ErrorStack),
    #[error("set private key failed: {0}")]
    SetPrivateKey(#[source] openssl::error::ErrorStack),
    #[error("set HTTPS public key cert: {0}")]
    SetHttpsCert(#[source] openssl::error::ErrorStack),
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

fn configure_cors(allowed_origin: &[String]) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["POST", "GET", "OPTIONS"])
        .allowed_headers(vec![header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(86400);

    // Parse origin
    if !allowed_origin.is_empty() {
        let origins: Vec<String> = allowed_origin
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        for ori in &origins {
            if ori.starts_with("http://") || ori.starts_with("https://") {
                info!("Allowed CORS origin: {ori:?}");
                cors = cors.allowed_origin(ori.as_str());
            } else {
                error!("Invalid CORS origin format: '{ori}'. Must start with http:// or https://");
            }
        }
    };

    cors
}

#[actix_web::main]
async fn main() -> Result<(), RestfulError> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("warn,attestation_service=info,restful_as=info"),
    };

    let version = format!(
        r"
 ________  ________  ________  ________  ________  ________      
|\   ____\|\   __  \|\   ____\|\   __  \|\   __  \|\   ____\     
\ \  \___|\ \  \|\  \ \  \___|\ \  \|\  \ \  \|\  \ \  \___|_    
 \ \  \    \ \  \\\  \ \  \    \ \  \\\  \ \   __  \ \_____  \   
  \ \  \____\ \  \\\  \ \  \____\ \  \\\  \ \  \ \  \|____|\  \  
   \ \_______\ \_______\ \_______\ \_______\ \__\ \__\____\_\  \ 
    \|_______|\|_______|\|_______|\|_______|\|__|\|__|\_________\
                                                     \|_________|
                                                                                    
version: v{}
commit: {}
buildtime: {}
loglevel: {env_filter}
",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME,
    );

    Subscriber::builder().with_env_filter(env_filter).init();

    info!("Welcome to Confidential Containers Attestation Service (RESTful version)!\n\n{version}");
    let cli = Cli::parse();

    // Install aws-lc-rs as the rustls crypto provider so PQC hybrid groups
    // are available for any TLS connection in this process.
    // install_default() is idempotent via .ok().
    #[cfg(feature = "rvps-grpc")]
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let config = match cli.config_file {
        Some(path) => {
            info!("Using config file {path}");
            Config::try_from(Path::new(&path))?
        }
        None => {
            info!("No confile path provided, use default one.");
            Config::default()
        }
    };
    debug!("Attestation Service config: {config:#?}");
    let attestation_service = AttestationService::new(config).await?;

    let allowed_origin = cli.allowed_origin.clone();

    let attestation_service = web::Data::new(Arc::new(RwLock::new(attestation_service)));
    let server = HttpServer::new(move || {
        App::new()
            .wrap(configure_cors(&allowed_origin))
            .service(web::resource(WebApi::Attestation.as_ref()).route(web::post().to(attestation)))
            .service(
                web::resource(WebApi::Policy.as_ref())
                    .route(web::post().to(set_policy))
                    .route(web::get().to(get_policies)),
            )
            .service(web::resource(WebApi::Challenge.as_ref()).route(web::post().to(get_challenge)))
            .app_data(web::Data::clone(&attestation_service))
    });

    let server = match (cli.tls_key, cli.tls_cert) {
        (Some(tls_key), Some(tls_cert)) => {
            let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

            let prikey = tokio::fs::read(&tls_key)
                .await
                .map_err(RestfulError::ReadHttpsKey)?;
            let prikey =
                PKey::private_key_from_pem(&prikey).map_err(RestfulError::ReadHttpsKeyFromPem)?;

            builder
                .set_private_key(&prikey)
                .map_err(RestfulError::SetPrivateKey)?;
            builder
                .set_certificate_chain_file(&tls_cert)
                .map_err(RestfulError::SetHttpsCert)?;

            let pqc_result = tls_config::configure_pqc_groups(&mut builder, cli.require_pqc)
                .map_err(|e| RestfulError::Anyhow(e.into()))?;
            info!("AS REST TLS groups: {}", pqc_result.groups_list);

            info!("starting HTTPS server at https://{}", cli.socket);
            server.bind_openssl(cli.socket, builder)?.run()
        }
        (None, None) => {
            if cli.require_pqc {
                return Err(RestfulError::Anyhow(anyhow::anyhow!(
                    "--require-pqc requires TLS: provide both --tls-cert and --tls-key"
                )));
            }
            info!("starting HTTP server at http://{}", cli.socket);
            server
                .bind((cli.socket.ip().to_string(), cli.socket.port()))?
                .run()
        }
        _ => {
            return Err(RestfulError::Anyhow(anyhow::anyhow!(
                "--tls-cert and --tls-key must be provided together"
            )));
        }
    };

    server.await?;
    Ok(())
}
