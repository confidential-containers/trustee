// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A simple KBS client for test.

use anyhow::Result;
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use clap::Parser;

const CC_KBC_NAME: &str = "cc_kbc";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KBS URI e.g https://127.0.0.1:8080
    #[arg(required = true, long)]
    kbs_uri: String,

    /// KBS Resource path, e.g /my_repo/resource_type/123abc
    /// Document: https://github.com/confidential-containers/attestation-agent/blob/main/docs/KBS_URI.md
    #[arg(required = true, long)]
    resource_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    let mut attestation_agent = AttestationAgent::new();

    let resource_byte = attestation_agent
        .download_confidential_resource(CC_KBC_NAME, &cli.resource_path, &cli.kbs_uri)
        .await?;

    println!("Resource: {:?}", &resource_byte);

    Ok(())
}
