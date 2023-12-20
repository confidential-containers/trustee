// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Confidential Containers Key Broker Service

extern crate anyhow;

use anyhow::{bail, Result};
use std::path::Path;

#[cfg(feature = "as")]
use api_server::attestation::AttestationService;
use api_server::{
    config::{Cli, KbsConfig},
    ApiServer,
};
use clap::Parser;
use log::{debug, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    info!("Using config file {}", cli.config_file);
    let kbs_config = KbsConfig::try_from(Path::new(&cli.config_file))?;

    debug!("Config: {:#?}", kbs_config);

    if !kbs_config.insecure_http
        && (kbs_config.private_key.is_none() || kbs_config.certificate.is_none())
    {
        bail!("Must specify HTTPS private key and certificate when running in secure mode");
    }

    if kbs_config.insecure_api {
        warn!("insecure APIs are enabled");
    }

    #[cfg(feature = "as")]
    let attestation_service = {
        cfg_if::cfg_if! {
            if #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))] {
                AttestationService::new(kbs_config.as_config.unwrap_or_default()).await?
            } else if #[cfg(feature = "coco-as-grpc")] {
                AttestationService::new(kbs_config.grpc_config.unwrap_or_default()).await?
            } else if #[cfg(feature = "intel-trust-authority-as")] {
                AttestationService::new(kbs_config.intel_trust_authority_config)?
            } else {
                compile_error!("Please enable at least one of the following features: `coco-as-builtin`, `coco-as-builtin-no-verifier`, `coco-as-grpc` or `intel-trust-authority-as` to continue.");
            }
        }
    };

    let api_server = ApiServer::new(
        kbs_config.sockets,
        kbs_config.private_key,
        kbs_config.auth_public_key,
        kbs_config.certificate,
        kbs_config.insecure_http,
        #[cfg(feature = "as")]
        attestation_service,
        kbs_config.timeout,
        kbs_config.insecure_api,
        #[cfg(feature = "resource")]
        kbs_config.repository_config.unwrap_or_default(),
        #[cfg(feature = "resource")]
        kbs_config.attestation_token_config,
        #[cfg(feature = "opa")]
        kbs_config.policy_engine_config.unwrap_or_default(),
    )?;

    api_server.serve().await.map_err(anyhow::Error::from)
}
