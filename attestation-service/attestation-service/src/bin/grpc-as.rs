use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;
use log::info;
use shadow_rs::shadow;

pub mod as_api {
    tonic::include_proto!("attestation");
}

pub mod rvps_api {
    tonic::include_proto!("reference");
}

shadow!(build);

mod grpc;

/// gRPC CoCo-AS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a CoCo-AS config file.
    #[arg(short, long)]
    pub config_file: Option<String>,

    /// Socket that the server will listen on to accept requests.
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    pub socket: SocketAddr,
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

    info!("CoCo AS: {version}");

    let cli = Cli::parse();

    let server = grpc::start(cli.socket, cli.config_file);
    tokio::try_join!(server)?;

    Ok(())
}
