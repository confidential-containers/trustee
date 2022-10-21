use anyhow::Result;
use clap::{App, Arg};
use shadow_rs::shadow;

pub mod as_api {
    tonic::include_proto!("attestation");
}

#[macro_use]
extern crate log;
shadow!(build);

mod server;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

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
        .get_matches();

    let server = server::start(matches.value_of("socket"));
    tokio::try_join!(server)?;

    Ok(())
}
