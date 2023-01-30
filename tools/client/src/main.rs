// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A simple KBS client for test.

use anyhow::Result;
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const CC_KBC_NAME: &str = "cc_kbc";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KBS URL. e.g: http://127.0.0.1:8080
    #[arg(required = true, long)]
    kbs_url: String,

    /// Resource path. e.g: "my_repo/resource_type/123abc"
    #[arg(required = true, short, long)]
    resource_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ResourceDescription {
    pub name: String,
    pub optional: HashMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    let resource_path: Vec<&str> = cli.resource_path.split('/').collect();

    let mut attestation_agent = AttestationAgent::new();

    let mut resource_desc_map = HashMap::new();
    resource_desc_map.insert("repository".to_string(), resource_path[0].to_string());
    resource_desc_map.insert("type".to_string(), resource_path[1].to_string());
    resource_desc_map.insert("tag".to_string(), resource_path[2].to_string());

    let resource_desc = ResourceDescription {
        name: String::default(),
        optional: resource_desc_map,
    };

    let resource_byte = attestation_agent
        .download_confidential_resource(
            CC_KBC_NAME,
            &cli.kbs_url,
            &serde_json::to_string(&resource_desc)?,
        )
        .await?;

    println!("{}", String::from_utf8(resource_byte)?);

    Ok(())
}
