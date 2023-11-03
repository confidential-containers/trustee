use anyhow::Result;
use clap::{App, Arg};
use shadow_rs::shadow;

pub mod as_api {
    tonic::include_proto!("attestation");
}

pub mod rvps_api {
    tonic::include_proto!("reference");
}

shadow!(build);

mod server;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    let matches = App::new("grpc-attestation-service")
        .version(version.as_str())
        .long_version(version.as_str())
        .author("Confidential-Containers Team")
        .arg(
            Arg::with_name("socket")
                .long("socket")
                .value_name("SOCKET")
                .help("Socket that the server will listen on to accept requests.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rvps-addr")
                .long("rvps-address")
                .value_name("rvps-addr")
                .help("Address of Reference Value Provider Service")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .value_name("config")
                .help("File path of AS config (JSON), left blank to use default config")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    let rvps_addr = matches.value_of("rvps-addr");
    let config_path = matches.value_of("config");
    let server = server::start(matches.value_of("socket"), rvps_addr, config_path);
    tokio::try_join!(server)?;

    Ok(())
}
