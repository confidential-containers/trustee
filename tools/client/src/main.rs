// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A simple KBS client for test.

use anyhow::{bail, Result};
use as_types::SetPolicyInput;
use clap::{Args, Parser, Subcommand};
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use kbs_protocol::{KbsProtocolWrapper, KbsRequest};
use std::path::PathBuf;

const KBS_URL_PREFIX: &str = "kbs/v0";

#[derive(Parser)]
#[clap(name = "KBS client")]
#[clap(author, version, about = "A command line client tool for KBS APIs.", long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// The KBS server host URL.
    #[clap(long, value_parser, default_value_t = String::from("http://127.0.0.1:8080"))]
    url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Set and Config KBS
    #[clap(arg_required_else_help = true)]
    Config(Config),

    /// Get confidential resource
    #[clap(arg_required_else_help = true)]
    GetResource {
        /// KBS Resource path, e.g my_repo/resource_type/123abc
        /// Document: https://github.com/confidential-containers/attestation-agent/blob/main/docs/KBS_URI.md
        #[clap(long, value_parser)]
        path: String,
    },

    /// Attestation and get attestation results token
    Attest,
}

#[derive(Args)]
struct Config {
    #[clap(subcommand)]
    command: ConfigCommands,

    /// PEM file path of private key used to authenticate the resource registration endpoint token (JWT)
    /// to Key Broker Service. This key can sign legal JWTs.
    /// This client tool only support ED22519 key now.
    #[clap(long, value_parser)]
    auth_private_key: PathBuf,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Set attestation verification policy
    SetAttestationPolicy {
        /// Policy format type, e.g "rego"
        #[clap(long, value_parser)]
        r#type: String,

        /// Policy ID, e.g "default"
        #[clap(long, value_parser)]
        id: String,

        /// Policy file path
        #[clap(long, value_parser)]
        policy_file: PathBuf,
    },

    /// Set confidential resource
    SetResource {
        /// KBS Resource path, e.g my_repo/resource_type/123abc
        /// Document: https://github.com/confidential-containers/attestation-agent/blob/main/docs/KBS_URI.md
        #[clap(long, value_parser)]
        path: String,

        /// Resource file path
        #[clap(long, value_parser)]
        resource_file: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    let mut kbs_protocol_wrapper = KbsProtocolWrapper::new()?;

    match cli.command {
        Commands::Attest => {
            let token = kbs_protocol_wrapper.attest(String::from(&cli.url)).await?;
            println!("{token}");
        }
        Commands::GetResource { path } => {
            let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", &cli.url, &path);
            let resource_bytes = kbs_protocol_wrapper.http_get(resource_url).await?;
            println!("{}", base64::encode(resource_bytes));
        }
        Commands::Config(config) => {
            let auth_private_key =
                Ed25519KeyPair::from_pem(&std::fs::read_to_string(config.auth_private_key)?)?;
            let claims = Claims::create(Duration::from_hours(2));
            let token = auth_private_key.sign(claims)?;
            let http_client = reqwest::Client::new();
            match config.command {
                ConfigCommands::SetAttestationPolicy {
                    r#type,
                    id,
                    policy_file,
                } => {
                    let set_policy_url =
                        format!("{}/{KBS_URL_PREFIX}/attestation-policy", &cli.url);
                    let policy_bytes = std::fs::read(policy_file)?;
                    let post_input = SetPolicyInput {
                        r#type,
                        policy_id: id,
                        policy: base64::encode(policy_bytes.clone()),
                    };
                    let res = http_client
                        .post(set_policy_url)
                        .header("Content-Type", "application/json")
                        .bearer_auth(token.clone())
                        .json::<SetPolicyInput>(&post_input)
                        .send()
                        .await?;
                    match res.status() {
                        reqwest::StatusCode::OK => {
                            println!(
                                "Set attestation policy success \n policy: {}",
                                base64::encode(policy_bytes)
                            );
                        }
                        _ => {
                            bail!("Request Failed, Response: {:?}", res.text().await?)
                        }
                    }
                }
                ConfigCommands::SetResource {
                    path,
                    resource_file,
                } => {
                    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", &cli.url, &path);
                    let resource_bytes = std::fs::read(resource_file)?;
                    let res = http_client
                        .post(resource_url)
                        .header("Content-Type", "application/octet-stream")
                        .bearer_auth(token)
                        .body(resource_bytes.clone())
                        .send()
                        .await?;
                    match res.status() {
                        reqwest::StatusCode::OK => {
                            println!(
                                "Set resource success \n resource: {}",
                                base64::encode(resource_bytes)
                            );
                        }
                        _ => {
                            bail!("Request Failed, Response: {:?}", res.text().await?)
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
