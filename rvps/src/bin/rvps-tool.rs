//! This tool is to connect the RVPS

use anyhow::*;
use clap::{Args, Parser};
use shadow_rs::shadow;
use tracing::info;
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

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

async fn list(addr: String) -> Result<()> {
    let ids = client::list(addr).await?;
    if ids.is_empty() {
        info!("No reference values registered.");
    } else {
        info!("Registered reference value IDs:\n{}", ids.join("\n"));
    }
    Ok(())
}

async fn delete(addr: String, reference_value_id: String) -> Result<()> {
    let deleted = client::delete(addr, reference_value_id.clone()).await?;
    if deleted {
        info!("Deleted reference value '{reference_value_id}'.");
    } else {
        info!("No reference value found for id '{reference_value_id}'.");
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

    /// List of all registered reference values
    List(ListArgs),

    /// Delete a reference value
    Delete(DeleteArgs),
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

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct ListArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct DeleteArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,
    /// The id of the reference value to delete
    #[arg(short, long)]
    reference_value_id: String,
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

    info!("CoCo RVPS Client tool: {version}");

    let cli = Cli::parse();

    match cli {
        Cli::Register(para) => register(&para.addr, &para.path).await,
        Cli::Query(para) => query(para.addr, para.reference_value_id).await,
        Cli::List(para) => list(para.addr).await,
        Cli::Delete(para) => delete(para.addr, para.reference_value_id).await,
    }
}
