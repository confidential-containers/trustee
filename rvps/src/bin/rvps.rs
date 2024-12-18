use anyhow::{Context, Result};
use clap::Parser;
use log::{info, warn};
use shadow_rs::shadow;

pub mod rvps_api {
    tonic::include_proto!("reference");
}

use reference_value_provider_service::config::Config;

shadow!(build);

mod server;

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

    info!("Listen socket: {}", &cli.address);

    let socket = cli.address.parse().context("parse socket addr failed")?;

    server::start(socket, config).await
}
