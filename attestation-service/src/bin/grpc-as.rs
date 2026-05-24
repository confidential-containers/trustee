use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use shadow_rs::shadow;
use tracing::info;
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

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
        None => EnvFilter::new("warn,attestation_service=info,grpc_as=info"),
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

    info!("Welcome to Confidential Containers Attestation Service (gRPC version)!\n{version}");

    let cli = Cli::parse();

    // Install aws-lc-rs as the rustls crypto provider so PQC hybrid groups
    // (X25519MLKEM768 etc.) are available for any TLS connection in this process.
    // install_default() is idempotent via .ok().
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let server = grpc::start(cli.socket, cli.config_file, cli.tls_cert, cli.tls_key);
    tokio::try_join!(server)?;

    Ok(())
}
