// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Confidential Containers Key Broker Service

use anyhow::Result;
use std::path::Path;

use clap::Parser;
use kbs::{
    config::{Cli, KbsConfig},
    ApiServer,
};
use shadow_rs::shadow;
use tracing::{debug, info};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

shadow!(build);

#[actix_web::main]
async fn main() -> Result<()> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("info"),
    };

    let version = format!(
        r"
 ________  ________  ________  ________          ___  __    ________  ________      
|\   ____\|\   __  \|\   ____\|\   __  \        |\  \|\  \ |\   __  \|\   ____\     
\ \  \___|\ \  \|\  \ \  \___|\ \  \|\  \       \ \  \/  /|\ \  \|\ /\ \  \___|_    
 \ \  \    \ \  \\\  \ \  \    \ \  \\\  \       \ \   ___  \ \   __  \ \_____  \   
  \ \  \____\ \  \\\  \ \  \____\ \  \\\  \       \ \  \\ \  \ \  \|\  \|____|\  \  
   \ \_______\ \_______\ \_______\ \_______\       \ \__\\ \__\ \_______\____\_\  \ 
    \|_______|\|_______|\|_______|\|_______|        \|__| \|__|\|_______|\_________\
                                                                        \|_________|                                                                                                                                                                                           
                                                                                    
version: v{}
commit: {}
buildtime: {}
loglevel: {env_filter}
",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    Subscriber::builder().with_env_filter(env_filter).init();
    info!("Welcome to Confidential Containers Key Broker Service!\n\n{version}");

    let cli = Cli::parse();

    info!("Using config file {}", cli.config_file);
    let kbs_config = KbsConfig::try_from(Path::new(&cli.config_file))?;

    debug!("Config (sensitive fields are omitted): {:#?}", kbs_config);

    let api_server = ApiServer::new(kbs_config).await?;

    api_server.serve().await?;
    Ok(())
}
