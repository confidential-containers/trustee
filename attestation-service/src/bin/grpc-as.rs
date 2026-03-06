use std::net::SocketAddr;

use anyhow::Result;
use clap::{Parser, Subcommand};
use shadow_rs::shadow;
use tracing::info;
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

use attestation_service::config::Config as AsConfig;

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
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to a CoCo-AS config file.
    #[arg(short, long)]
    pub config_file: Option<String>,

    /// Socket that the server will listen on to accept requests.
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    pub socket: SocketAddr,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print an example Attestation Service configuration file to stdout.
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
                print!("{}", AsConfig::example_config_toml());
                return Ok(());
            }
        }
    }

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

    let server = grpc::start(cli.socket, cli.config_file);
    tokio::try_join!(server)?;

    Ok(())
}
