// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "coco-as-grpc")]
use crate::attestation::coco::grpc::GrpcConfig;
#[cfg(feature = "intel-trust-authority-as")]
use crate::attestation::intel_trust_authority::IntelTrustAuthorityConfig;
#[cfg(feature = "policy")]
use crate::policy_engine::PolicyEngineConfig;
#[cfg(feature = "resource")]
use crate::resource::RepositoryConfig;
#[cfg(feature = "resource")]
use crate::token::AttestationTokenVerifierConfig;
use anyhow::anyhow;
#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
use attestation_service::config::Config as AsConfig;
use clap::Parser;
use config::{Config, File};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DEFAULT_INSECURE_API: bool = false;
const DEFAULT_INSECURE_HTTP: bool = false;
const DEFAULT_SOCKET: &str = "127.0.0.1:8080";
const DEFAULT_TIMEOUT: i64 = 5;

/// Contains all configurable KBS properties.
#[derive(Clone, Debug, Deserialize)]
pub struct KbsConfig {
    /// Resource repository config.
    #[cfg(feature = "resource")]
    pub repository_config: Option<RepositoryConfig>,

    /// Attestation token result broker config.
    #[cfg(feature = "resource")]
    pub attestation_token_config: AttestationTokenVerifierConfig,

    /// Configuration for the built-in Attestation Service.
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    pub as_config: Option<AsConfig>,

    /// Configuration for remote attestation over gRPC.
    #[cfg(feature = "coco-as-grpc")]
    pub grpc_config: Option<GrpcConfig>,

    /// Configuration for Intel Trust Authority attestation.
    #[cfg(feature = "intel-trust-authority-as")]
    pub intel_trust_authority_config: IntelTrustAuthorityConfig,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    pub sockets: Vec<SocketAddr>,

    /// HTTPS session timeout in minutes.
    pub timeout: i64,

    /// HTTPS private key.
    pub private_key: Option<PathBuf>,

    /// HTTPS Certificate.
    pub certificate: Option<PathBuf>,

    /// Insecure HTTP.
    /// WARNING: Using this option makes the HTTP connection insecure.
    pub insecure_http: bool,

    /// Public key used to authenticate the resource registration endpoint token (JWT).
    /// Only JWTs signed with the corresponding private keys are authenticated.
    pub auth_public_key: Option<PathBuf>,

    /// Insecure HTTP APIs.
    /// WARNING: Using this option enables KBS insecure APIs such as Resource Registration without
    /// verifying the JWK.
    pub insecure_api: bool,

    /// Policy engine configuration used for evaluating whether the TCB status has access to
    /// specific resources.
    #[cfg(feature = "policy")]
    pub policy_engine_config: Option<PolicyEngineConfig>,
}

impl TryFrom<&Path> for KbsConfig {
    type Error = anyhow::Error;

    /// Load `Config` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate. See `KbsConfig` for schema information.
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let c = Config::builder()
            .set_default("insecure_api", DEFAULT_INSECURE_API)?
            .set_default("insecure_http", DEFAULT_INSECURE_HTTP)?
            .set_default("sockets", vec![DEFAULT_SOCKET])?
            .set_default("timeout", DEFAULT_TIMEOUT)?
            .add_source(File::with_name(config_path.to_str().unwrap()))
            .build()?;

        c.try_deserialize()
            .map_err(|e| anyhow!("invalid config: {}", e.to_string()))
    }
}

/// KBS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a KBS config file. Supported formats: TOML, YAML, JSON and possibly other formats
    /// supported by the `config` crate.
    #[arg(short, long, env = "KBS_CONFIG_FILE")]
    pub config_file: String,
}
