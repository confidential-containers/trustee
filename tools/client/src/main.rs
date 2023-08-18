// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A simple KBS client for test.

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(name = "KBS client")]
#[clap(author, version, about = "A command line client tool for KBS APIs.", long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// The KBS server root URL.
    #[clap(long, value_parser, default_value_t = String::from("http://127.0.0.1:8080"))]
    url: String,

    /// The KBS HTTPS server custom root certificate file path (PEM format)
    #[clap(long, value_parser)]
    cert_file: Option<PathBuf>,
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

        /// Custom TEE private Key (RSA) file path (PEM format)
        /// Used to protect the Respond Payload
        ///
        /// If NOT set this argument,
        /// KBS client will generate a new TEE Key pair internally.
        #[clap(long, value_parser)]
        tee_key_file: Option<PathBuf>,

        /// Attestation Token file path
        ///
        /// If set this argument, `--tee_key_file` argument should also be set,
        /// and the public part of TEE Key should be consistent with tee-pubkey in the token.
        #[clap(long, value_parser)]
        attestation_token: Option<PathBuf>,
    },

    /// Attestation and get attestation results token
    Attest {
        /// Custom TEE private Key (RSA) file path (PEM format)
        /// The public part of this key will be included in the token obtained by attestation.
        ///
        /// If not set this argument,
        /// KBS client will generate a new TEE Key pair internally.
        #[clap(long, value_parser)]
        tee_key_file: Option<PathBuf>,
    },
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
        r#type: Option<String>,

        /// Policy ID, e.g "default"
        #[clap(long, value_parser)]
        id: Option<String>,

        /// Policy file path
        #[clap(long, value_parser)]
        policy_file: PathBuf,
    },

    /// Set resource policy
    SetResourcePolicy {
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

    let kbs_cert = match cli.cert_file {
        Some(p) => vec![std::fs::read_to_string(p)?],
        None => vec![],
    };

    match cli.command {
        Commands::Attest { tee_key_file } => {
            let tee_key = match tee_key_file {
                Some(f) => Some(std::fs::read_to_string(f)?),
                None => None,
            };
            let token = kbs_client::attestation(&cli.url, tee_key, kbs_cert.clone()).await?;
            println!("{token}");
        }
        Commands::GetResource {
            path,
            tee_key_file,
            attestation_token,
        } => {
            let tee_key = match tee_key_file {
                Some(f) => Some(std::fs::read_to_string(f)?),
                None => None,
            };
            let token = match attestation_token {
                Some(t) => Some(std::fs::read_to_string(t)?.trim().to_string()),
                None => None,
            };

            if token.is_some() {
                if tee_key.is_none() {
                    bail!("if `--attestation-token` is set, `--tee_key_file` argument should also be set, and the public part of TEE Key should be consistent with tee-pubkey in the token.");
                }
                let resource_bytes = kbs_client::get_resource_with_token(
                    &cli.url,
                    &path,
                    tee_key.unwrap(),
                    token.unwrap(),
                    kbs_cert.clone(),
                )
                .await?;
                println!("{}", STANDARD.encode(resource_bytes));
            } else {
                let resource_bytes = kbs_client::get_resource_with_attestation(
                    &cli.url,
                    &path,
                    tee_key,
                    kbs_cert.clone(),
                )
                .await?;
                println!("{}", STANDARD.encode(resource_bytes));
            }
        }
        Commands::Config(config) => {
            let auth_key = std::fs::read_to_string(config.auth_private_key)?;
            match config.command {
                ConfigCommands::SetAttestationPolicy {
                    r#type,
                    id,
                    policy_file,
                } => {
                    let policy_bytes = std::fs::read(policy_file)?;
                    kbs_client::set_attestation_policy(
                        &cli.url,
                        auth_key.clone(),
                        policy_bytes.clone(),
                        r#type,
                        id,
                        kbs_cert.clone(),
                    )
                    .await?;
                    println!(
                        "Set attestation policy success \n policy: {}",
                        STANDARD.encode(policy_bytes)
                    );
                }
                ConfigCommands::SetResourcePolicy { policy_file } => {
                    let policy_bytes = std::fs::read(policy_file)?;
                    kbs_client::set_resource_policy(
                        &cli.url,
                        auth_key.clone(),
                        policy_bytes.clone(),
                        kbs_cert.clone(),
                    )
                    .await?;
                    println!(
                        "Set resource policy success \n policy: {}",
                        STANDARD.encode(policy_bytes)
                    );
                }
                ConfigCommands::SetResource {
                    path,
                    resource_file,
                } => {
                    let resource_bytes = std::fs::read(resource_file)?;
                    kbs_client::set_resource(
                        &cli.url,
                        auth_key.clone(),
                        resource_bytes.clone(),
                        &path,
                        kbs_cert.clone(),
                    )
                    .await?;
                    println!(
                        "Set resource success \n resource: {}",
                        STANDARD.encode(resource_bytes)
                    );
                }
            }
        }
    }

    Ok(())
}
