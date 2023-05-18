//! This tool is to connect the RVPS

use anyhow::*;
use clap::{App, Arg, Command};
use log::info;
use shadow_rs::shadow;

pub mod rvps_api {
    tonic::include_proto!("reference");
}

use crate::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

shadow!(build);

/// Default address of RVPS
const DEFAULT_ADDR: &str = "http://127.0.0.1:50003";

async fn register(addr: &str, provenance_path: &str) -> Result<()> {
    let message = std::fs::read_to_string(provenance_path).context("read provenance")?;
    let mut client = ReferenceValueProviderServiceClient::connect(addr.to_string()).await?;
    let req = tonic::Request::new(ReferenceValueRegisterRequest { message });

    client.register_reference_value(req).await?;

    info!("Register provenance succeeded.");

    Ok(())
}

async fn query(addr: &str, name: &str) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(addr.to_string()).await?;
    let req = tonic::Request::new(ReferenceValueQueryRequest {
        name: name.to_string(),
    });

    let rvs = client
        .query_reference_value(req)
        .await?
        .into_inner()
        .reference_value_results;
    info!("Get reference values succeeded:\n {rvs}");
    Ok(())
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

    let matches = App::new("RVPS-client")
        .version(version.as_str())
        .long_version(version.as_str())
        .author("Confidential-Containers Team")
        .subcommand(
            Command::new("register")
                .about("Register a reference value into the RVPS")
                .arg(
                    Arg::with_name("addr")
                        .long("addr")
                        .value_name("addr")
                        .help("The address of target RVPS")
                        .takes_value(true)
                        .default_value(DEFAULT_ADDR)
                        .required(false),
                )
                .arg(
                    Arg::with_name("path")
                        .long("path")
                        .value_name("path")
                        .help("The path to the provenance json file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("query")
                .about("Query a reference value from the RVPS")
                .arg(
                    Arg::with_name("addr")
                        .long("addr")
                        .value_name("addr")
                        .help("The address of target RVPS")
                        .takes_value(true)
                        .default_value(DEFAULT_ADDR)
                        .required(false),
                )
                .arg(
                    Arg::with_name("name")
                        .long("name")
                        .value_name("name")
                        .help("The name to query reference value")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("register", sub_cmd)) => {
            let addr = sub_cmd.value_of("addr").expect("no rvps addr input");
            let path = sub_cmd.value_of("path").expect("no rv provenance input");
            register(addr, path).await
        }
        Some(("query", sub_cmd)) => {
            let addr = sub_cmd.value_of("addr").expect("no rvps addr input");
            let name = sub_cmd.value_of("name").expect("no artifact name input");
            query(addr, name).await
        }
        _ => bail!("error occurs for subcommand"),
    }
}
