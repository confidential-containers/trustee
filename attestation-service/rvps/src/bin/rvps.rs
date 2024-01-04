use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use shadow_rs::shadow;

pub mod rvps_api {
    tonic::include_proto!("reference");
}

shadow!(build);

mod server;

const DEFAULT_ADDR: &str = "127.0.0.1:50003";
const DEFAULT_STORAGE: &str = "LocalFs";

/// RVPS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Underlying storage engine that RVPS uses.
    #[arg(short = 'c', long, default_value = DEFAULT_STORAGE)]
    pub storage: String,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:50003.
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    pub socket: String,
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

    info!("Listen socket: {}", cli.socket);

    let socket = cli.socket.parse().context("parse socket addr failed")?;
    server::start(socket, &cli.storage).await
}
