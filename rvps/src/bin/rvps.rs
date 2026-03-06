use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use shadow_rs::shadow;
use tracing::info;
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
    #[command(subcommand)]
    pub command: Option<Commands>,

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

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print an example RVPS configuration file to stdout.
    ///
    /// The output includes comments explaining what each field does.
    PrintExampleConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        match command {
            Commands::PrintExampleConfig => {
                print!("{}", Config::example_config_toml());
                return Ok(());
            }
        }
    }

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

    let config = Config::from_file(&cli.config)?;

    info!("Listen socket: {}", &cli.address);

    let socket = cli.address.parse().context("parse socket addr failed")?;

    server::start(socket, config).await
}
