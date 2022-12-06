// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Confidential Containers Key Broker Service

extern crate anyhow;

use anyhow::Result;
use api_server::ApiServer;
use attestation_service::AttestationService;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket address (IP:port) to listen to, e.g. 127.0.0.1:8080.
    /// This can be set multiple times.
    #[arg(required = true, short, long)]
    socket: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    let api_server = ApiServer::new(cli.socket, Arc::new(AttestationService::new()?));
    api_server.serve().await.map_err(anyhow::Error::from)
}
