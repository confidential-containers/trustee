use anyhow::{Context, Result};
use clap::Parser;
use shadow_rs::shadow;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

use reference_value_provider_service::config::Config;
use reference_value_provider_service::server;

shadow!(build);

const DEFAULT_CONFIG_PATH: &str = "/etc/rvps.json";
const DEFAULT_ADDRESS: &str = "127.0.0.1:50003";

/// RVPS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the configuration file of RVPS
    ///
    /// `--config /etc/rvps.toml`
    #[arg(short = 'c', long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    /// The address that the RVPS server will listen on.
    /// The default is 127.0.0.1:50003
    ///
    /// `--address 127.0.0.1:55554`
    #[arg(short = 'a', long, default_value = DEFAULT_ADDRESS)]
    pub address: String,

    /// Path to the TLS certificate file (PEM) for the gRPC listener.
    /// When provided, --tls-key must also be given.
    /// If omitted, the server starts without TLS (default behavior).
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Path to the TLS private key file (PEM) for the gRPC listener.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("info"),
    };
    Subscriber::builder().with_env_filter(env_filter).init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    info!("CoCo RVPS: {version}");

    let cli = Cli::parse();
    let config = Config::from_file(&cli.config).unwrap_or_else(|e| {
        warn!(
            "fail to read config from {}. Error: {e:?}. Using default configuration.",
            cli.config
        );
        Config::default()
    });

    info!("Listen socket: {}", &cli.address);

    // Install aws-lc-rs as the rustls crypto provider so PQC hybrid groups
    // (X25519MLKEM768 etc.) are available for any TLS connection in this process.
    // install_default() is idempotent via .ok().
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let socket = cli.address.parse().context("parse socket addr failed")?;

    server::start(socket, config, cli.tls_cert, cli.tls_key).await
}
