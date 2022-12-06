// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Confidential Containers Key Broker Service

extern crate anyhow;

use anyhow::Result;
use api_server::ApiServer;
use attestation_service::AttestationService;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let api_server = ApiServer::new(
        vec![SocketAddr::from((
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            8080,
        ))],
        Arc::new(AttestationService::new()?),
    );
    api_server.serve().await.map_err(anyhow::Error::from)
}
