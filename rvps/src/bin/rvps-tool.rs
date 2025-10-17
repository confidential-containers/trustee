//! This tool is to connect the RVPS

use anyhow::*;
use clap::{Args, Parser};
use log::info;
use shadow_rs::shadow;

use reference_value_provider_service::client;

shadow!(build);

/// Default address of RVPS
const DEFAULT_ADDR: &str = "http://127.0.0.1:50003";

async fn register(addr: &str, provenance_path: &str) -> Result<()> {
    let message = std::fs::read_to_string(provenance_path).context("read provenance")?;

    client::register(addr.to_string(), message).await?;
    info!("Register provenance succeeded.");

    Ok(())
}

async fn query(addr: String, reference_value_id: String) -> Result<()> {
    let rvs = client::query(addr, reference_value_id).await?;
    match rvs {
        Some(rvs) => info!("Get reference values succeeded:\n {rvs}"),
        None => info!("No reference values found for the given id"),
    }
    Ok(())
}

/// RVPS command-line arguments.
#[derive(Parser)]
#[command(name = "rvps-tool")]
#[command(bin_name = "rvps-tool")]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Register reference values
    Register(RegisterArgs),

    /// Query reference values
    Query(QueryArgs),
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct RegisterArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,

    /// The path to the provenance json file
    #[arg(short, long)]
    path: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct QueryArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,

    /// The id of the reference value
    #[arg(short, long)]
    reference_value_id: String,
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

    info!("CoCo RVPS Client tool: {version}");

    let cli = Cli::parse();

    match cli {
        Cli::Register(para) => register(&para.addr, &para.path).await,
        Cli::Query(para) => query(para.addr, para.reference_value_id).await,
    }
}
