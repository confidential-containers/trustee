use anyhow::Result;
use clap::{App, Arg};
use shadow_rs::shadow;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod management_api {
    tonic::include_proto!("management");
}
pub mod attestation_api {
    tonic::include_proto!("attestation");
}
pub mod common {
    tonic::include_proto!("common");
}

#[macro_use]
extern crate log;
shadow!(build);

mod attestation;
mod management;
mod user;

const ATTESTATION_SERVER_WORKDIR: &str = "/opt/attestation-server";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    let matches = App::new("attestation-server")
        .version(version.as_str())
        .long_version(version.as_str())
        .author("Confidential-Containers Team")
        .arg(
            Arg::with_name("attestation-sock")
                .long("attestation-sock")
                .value_name("ATTESTATION_SOCK")
                .help("Socket that the server will listen on to accept attestation requests.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("management-sock")
                .long("management-sock")
                .value_name("MANAGEMENT_SOCK")
                .help("Socket that the server will listen on to accept management requests.")
                .takes_value(true),
        )
        .get_matches();

    // Create a default User.
    let user = Arc::new(RwLock::new(user::User::default()));
    let workdir = Path::new(ATTESTATION_SERVER_WORKDIR).to_owned();

    let attestation_server = attestation::start_service(
        matches.value_of("attestation-sock"),
        user.clone(),
        workdir.clone(),
    );
    let management_server = management::start_service(
        matches.value_of("management-sock"),
        user.clone(),
        workdir.clone(),
    );
    tokio::try_join!(attestation_server, management_server)?;

    Ok(())
}
