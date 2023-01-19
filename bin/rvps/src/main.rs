use anyhow::{Context, Result};
use attestation_service::rvps::store::StoreType;
use clap::{App, Arg};
use log::info;
use shadow_rs::shadow;

pub mod rvps_api {
    tonic::include_proto!("reference");
}

shadow!(build);

mod server;

const DEFAULT_ADDR: &str = "127.0.0.1:50003";
const DEFAULT_STORAGE: &str = "LocalFs";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    let matches = App::new("reference-value-provider-service")
        .version(version.as_str())
        .long_version(version.as_str())
        .author("Confidential-Containers Team")
        .arg(
            Arg::with_name("socket")
                .long("socket")
                .value_name("SOCKET")
                .help("Socket that the server will listen on to accept requests.")
                .takes_value(true)
                .default_value(DEFAULT_ADDR)
                .required(false),
        )
        .arg(
            Arg::with_name("storage")
                .long("storage type")
                .value_name("STORAGE")
                .help("Underlying storage type used by RVPS.")
                .takes_value(true)
                .default_value(DEFAULT_STORAGE)
                .required(false),
        )
        .get_matches();

    let socket = matches.value_of("socket").expect("socket addr get failed.");
    let storage = matches
        .value_of("storage")
        .expect("storage type get failed.");

    info!("Listen socket: {}", socket);

    let socket = socket.parse().context("parse socket addr failed")?;
    let storage = StoreType::try_from(storage)
        .context("storage type")?
        .to_store()
        .context("create storage failed")?;
    server::start(socket, storage).await
}
