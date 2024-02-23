use anyhow::{Context, Result};
use clap::Parser;
use log::{info, warn};
use server::config::Config;
use shadow_rs::shadow;

pub mod rvps_api {
    tonic::include_proto!("reference");
}

shadow!(build);

mod server;

const DEFAULT_CONFIG_PATH: &str = "/etc/rvps.json";

/// RVPS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the configuration file of RVPS
    ///
    /// `--config /etc/rvps.toml`
    #[arg(short = 'c', long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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

    info!("Listen socket: {}", config.address);

    let socket = config.address.parse().context("parse socket addr failed")?;

    server::start(socket, config.into()).await
}
