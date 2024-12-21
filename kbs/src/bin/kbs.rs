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
use log::{debug, info};

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    info!("Using config file {}", cli.config_file);
    let kbs_config = KbsConfig::try_from(Path::new(&cli.config_file))?;

    debug!("Config (sensitive fields are omitted): {:#?}", kbs_config);

    let api_server = ApiServer::new(kbs_config).await?;

    api_server.serve().await?;
    Ok(())
}
