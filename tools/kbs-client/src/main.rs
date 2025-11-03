// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A simple KBS client for test.

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use jwt_simple::algorithms::EdDSAKeyPairLike;
use jwt_simple::prelude::Duration;
use jwt_simple::prelude::{Claims, Ed25519KeyPair};
use serde_json::json;
use std::path::PathBuf;

/// A direcotry, relative to the user's home directory,
/// where the kbs-client can store data.
const KBS_CLIENT_DIRECTORY: &str = ".kbs-client";
/// The name of the file storing admin data
const KBS_CLIENT_ADMIN_DATA_FILE: &str = "admin-data.json";

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

    /// Login to the Trustee admin interface.
    /// If login is successful, an admin token will be saved locally.
    /// This token will be used with future admin requests
    /// until it expires, when the user must login again.
    ///
    /// This command is only supported when Trustee is configured
    /// with certain admin backends.
    ///
    /// This command should only be used when Trustee is configured
    /// with HTTPS, otherwise the credentials will be visible
    /// on the network.
    #[clap(arg_required_else_help = true)]
    AdminLogin { username: String, password: String },

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

    /// The path to an ED22519 private key in PEM format.
    /// When using the simple admin backend, the KBS
    /// expects to receive a bearer JWT signed by this key.
    /// The corresponding public key is specified in the
    /// KBS admin config.
    ///
    /// This should only be specified when using the simple
    /// admin backend. Otherwise, the admin login API should
    /// be used first.
    #[clap(long, value_parser)]
    auth_private_key: Option<PathBuf>,
}

#[allow(clippy::enum_variant_names)]
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
        #[clap(long, value_parser, group = "resource_policy")]
        policy_file: Option<PathBuf>,

        /// Use built-in policy that allows access to all resources
        #[clap(long, action, group = "resource_policy")]
        allow_all: bool,

        /// Use built-in policy that does not allow access to any resources
        #[clap(long, action, group = "resource_policy")]
        deny_all: bool,

        /// Use built-in policy that only releases resources if the attestation
        /// token is affirming (i.e. the attestation policy is met)
        #[clap(long, action, group = "resource_policy")]
        affirming: bool,

        /// Use built-in default policy that allows access to all policies
        /// unless the sample evidence is provided
        #[clap(long, action, group = "resource_policy")]
        default: bool,
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

    /// List reference values registered with RVPS
    GetReferenceValues,

    /// Add a sample reference value to the RVPS.
    /// The request will be proxied through the KBS
    /// The RVPS must enable the sample extractor
    /// or the reference value will not be registered.
    SetSampleReferenceValue {
        /// The name of the reference value.
        name: String,
        /// The reference value itself. This will be
        /// treated as an integer by default.
        value: String,
        /// If set, the value will be parsed as an integer.
        #[clap(long, action, group = "resource_type")]
        as_integer: bool,
        /// If set, the value will be parsed as a bool.
        #[clap(long, action, group = "resource_type")]
        as_bool: bool,
        /// By default the reference value will be a single
        /// member in a list.
        /// If this argument is set, the reference value
        /// will be a single value.
        #[clap(long, action)]
        as_single_value: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    let kbs_cert = match cli.cert_file {
        Some(ref p) => vec![std::fs::read_to_string(p)
            .inspect_err(|_| eprintln!("Failed to read: {}", p.display()))?],
        None => vec![],
    };

    match cli.command {
        Commands::Attest { tee_key_file } => {
            let tee_key = match tee_key_file {
                Some(ref f) => Some(
                    std::fs::read_to_string(f)
                        .inspect_err(|_| eprintln!("Failed to read: {}", f.display()))?,
                ),
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
                Some(ref f) => Some(
                    std::fs::read_to_string(f)
                        .inspect_err(|_| eprintln!("Failed to read: {}", f.display()))?,
                ),
                None => None,
            };
            let token = match attestation_token {
                Some(ref t) => Some(
                    std::fs::read_to_string(t)
                        .inspect_err(|_| eprintln!("Failed to read: {}", t.display()))?
                        .trim()
                        .to_string(),
                ),
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
        Commands::AdminLogin { username, password } => {
            let admin_token =
                kbs_client::admin_login(cli.url, username, password, kbs_cert.clone()).await?;

            // Write the admin data to the home directory.
            // Windows is not supported.
            let mut path = std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or(anyhow!("Could not find home directory."))?;

            path.push(KBS_CLIENT_DIRECTORY);
            tokio::fs::create_dir_all(path.clone()).await?;

            path.push(KBS_CLIENT_ADMIN_DATA_FILE);

            // For now, there is only one thing in the data file,
            // so it is ok to clobber the entire file.
            let data = json!({"admin_token": admin_token});
            tokio::fs::write(path, data.to_string()).await?;

            println!("Login Succeeded");
        }
        Commands::Config(config) => {
            let admin_token = match config.auth_private_key {
                // If the private key path is given, create a token signed by the key.
                Some(path) => {
                    let key = std::fs::read_to_string(&path)
                        .inspect_err(|_| eprintln!("Failed to read: {}", path.display()))?;

                    let key = Ed25519KeyPair::from_pem(&key)?;
                    let claims = Claims::create(Duration::from_hours(2));

                    key.sign(claims)?
                }
                // Otherwise use the token stored in the kbs-client data file.
                None => {
                    let mut path = std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .ok_or(anyhow!("Could not find home directory."))?;

                    path.push(KBS_CLIENT_DIRECTORY);
                    path.push(KBS_CLIENT_ADMIN_DATA_FILE);

                    if let Ok(admin_data) = tokio::fs::read_to_string(path).await {
                        let admin_data: serde_json::Value = serde_json::from_str(&admin_data)?;
                        admin_data
                            .pointer("/admin_token")
                            .ok_or(anyhow!("Could not find admin token."))?
                            .as_str()
                            .ok_or(anyhow!("Could not parse admin token as string."))?
                            .to_string()
                    } else {
                        bail!("No admin token found. Please login first.");
                    }
                }
            };
            match config.command {
                ConfigCommands::SetAttestationPolicy {
                    r#type,
                    id,
                    policy_file,
                } => {
                    let policy_bytes = std::fs::read(policy_file)?;
                    kbs_client::set_attestation_policy(
                        &cli.url,
                        admin_token.clone(),
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
                ConfigCommands::SetResourcePolicy {
                    policy_file,
                    allow_all,
                    deny_all,
                    affirming,
                    default,
                } => {
                    let policy_bytes: Vec<u8> = if let Some(file) = policy_file {
                        std::fs::read(file)?
                    } else if allow_all {
                        include_bytes!("../../../kbs/sample_policies/allow_all.rego").into()
                    } else if deny_all {
                        include_bytes!("../../../kbs/sample_policies/deny_all.rego").into()
                    } else if affirming {
                        include_bytes!("../../../kbs/sample_policies/affirming.rego").into()
                    } else if default {
                        include_bytes!("../../../kbs/src/policy_engine/opa/default_policy.rego")
                            .into()
                    } else {
                        bail!("No policy specified")
                    };
                    kbs_client::set_resource_policy(
                        &cli.url,
                        admin_token.clone(),
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
                        admin_token.clone(),
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
                ConfigCommands::SetSampleReferenceValue {
                    name,
                    value,
                    as_integer,
                    as_bool,
                    as_single_value,
                } => {
                    let parsed_value: serde_json::Value = if as_integer {
                        value.parse::<i32>()?.into()
                    } else if as_bool {
                        value.parse::<bool>()?.into()
                    } else {
                        serde_json::Value::String(value)
                    };

                    let rv = match as_single_value {
                        true => parsed_value,
                        false => json!([parsed_value]),
                    };

                    kbs_client::set_sample_rv(
                        cli.url,
                        name,
                        rv,
                        admin_token.clone(),
                        kbs_cert.clone(),
                    )
                    .await?;
                    println!("Reference Values Updated");
                }
                ConfigCommands::GetReferenceValues => {
                    let values =
                        kbs_client::get_rvs(cli.url, admin_token.clone(), kbs_cert.clone()).await?;
                    println!("{:?}", values);
                }
            }
        }
    }

    Ok(())
}
