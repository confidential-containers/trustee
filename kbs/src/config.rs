// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::admin::config::{AdminConfig, DEFAULT_INSECURE_API};
use crate::plugins::PluginsConfig;
use crate::policy_engine::PolicyEngineConfig;
use crate::token::AttestationTokenVerifierConfig;
use anyhow::anyhow;
use clap::Parser;
use config::{Config, File};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DEFAULT_INSECURE_HTTP: bool = false;
const DEFAULT_SOCKET: &str = "127.0.0.1:8080";
const DEFAULT_PAYLOAD_REQUEST_SIZE: u32 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct HttpServerConfig {
    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    pub sockets: Vec<SocketAddr>,

    /// HTTPS private key.
    pub private_key: Option<PathBuf>,

    /// HTTPS Certificate.
    pub certificate: Option<PathBuf>,

    /// Insecure HTTP.
    /// WARNING: Using this option makes the HTTP connection insecure.
    pub insecure_http: bool,

    /// Request payload size in MB
    pub payload_request_size: u32,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            sockets: vec![DEFAULT_SOCKET.parse().expect("unexpected parse error")],
            private_key: None,
            certificate: None,
            insecure_http: DEFAULT_INSECURE_HTTP,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        }
    }
}

/// Contains all configurable KBS properties.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KbsConfig {
    /// Attestation token result broker config.
    #[serde(default)]
    pub attestation_token: AttestationTokenVerifierConfig,

    /// Configuration for the Attestation Service.
    #[cfg(feature = "as")]
    #[serde(default)]
    pub attestation_service: crate::attestation::config::AttestationConfig,

    /// Configuration for the KBS Http Server
    pub http_server: HttpServerConfig,

    /// Configuration for the KBS admin API
    pub admin: AdminConfig,

    /// Policy engine configuration used for evaluating whether the TCB status has access to
    /// specific resources.
    #[serde(default)]
    pub policy_engine: PolicyEngineConfig,

    #[serde(default)]
    pub plugins: Vec<PluginsConfig>,
}

impl TryFrom<&Path> for KbsConfig {
    type Error = anyhow::Error;

    /// Load `Config` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate. See `KbsConfig` for schema information.
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let c = Config::builder()
            .set_default("admin.insecure_api", DEFAULT_INSECURE_API)?
            .set_default("http_server.insecure_http", DEFAULT_INSECURE_HTTP)?
            .set_default("http_server.sockets", vec![DEFAULT_SOCKET])?
            .set_default(
                "http_server.payload_request_size",
                DEFAULT_PAYLOAD_REQUEST_SIZE,
            )?
            .set_default("attestation_service.policy_ids", Vec::<&str>::new())?
            .add_source(File::with_name(config_path.to_str().unwrap()))
            .build()?;

        c.try_deserialize()
            .map_err(|e| anyhow!("invalid config: {}", e))
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::{
        admin::config::AdminConfig,
        config::{
            HttpServerConfig, DEFAULT_INSECURE_API, DEFAULT_INSECURE_HTTP,
            DEFAULT_PAYLOAD_REQUEST_SIZE, DEFAULT_SOCKET,
        },
        plugins::{
            implementations::{
                resource::local_fs::LocalFsRepoDesc, RepositoryConfig, SampleConfig,
            },
            PluginsConfig,
        },
        policy_engine::{PolicyEngineConfig, DEFAULT_POLICY_PATH},
        token::AttestationTokenVerifierConfig,
    };

    use super::KbsConfig;

    #[cfg(feature = "coco-as-builtin")]
    use attestation_service::{
        rvps::{grpc::RvpsRemoteConfig, RvpsConfig, RvpsCrateConfig},
        token::{simple, AttestationTokenConfig, COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION},
    };

    use reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig};

    use rstest::rstest;

    #[rstest]
    #[case("test_data/configs/coco-as-grpc-1.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec!["/etc/ca".into(), "/etc/ca2".into()],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-grpc")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASGrpc(
                    crate::attestation::coco::grpc::GrpcConfig {
                        as_addr: "http://127.0.0.1:50001".into(),
                        pool_size: 100,
                    },
                ),
            timeout: 600,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: Some("/etc/kbs-private.key".into()),
            certificate: Some("/etc/kbs-cert.pem".into()),
            insecure_http: false,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some(PathBuf::from("/etc/kbs-admin.pub")),
            insecure_api: false,
        },
        policy_engine: PolicyEngineConfig {
            policy_path: PathBuf::from("/etc/kbs-policy.rego"),
        },
        plugins: vec![PluginsConfig::Sample(SampleConfig {
            item: "value1".into(),
        }),
        PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
            LocalFsRepoDesc {
                dir_path: "/tmp/kbs-resource".into(),
            },
        ))],
    })]
    #[case("test_data/configs/coco-as-builtin-1.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-builtin")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASBuiltIn(
                    attestation_service::config::Config {
                        work_dir: "/opt/coco/attestation-service".into(),
                        rvps_config: RvpsConfig::GrpcRemote(RvpsRemoteConfig {
                            address: "http://127.0.0.1:50003".into(),
                        }),
                        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
                            duration_min: DEFAULT_TOKEN_DURATION,
                            issuer_name: COCO_AS_ISSUER_NAME.into(),
                            signer: None,
                            ..Default::default()
                        }),
                        verifier_config: None,
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec![DEFAULT_SOCKET.parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: DEFAULT_INSECURE_HTTP,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: None,
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig {
            policy_path: DEFAULT_POLICY_PATH.into(),
        },
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/intel-ta-1.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_jwk_sets: vec!["/etc/ca".into(), "/etc/ca2".into()],
            insecure_key: false,
            trusted_certs_paths: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "intel-trust-authority-as")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::IntelTA(
                    crate::attestation::intel_trust_authority::IntelTrustAuthorityConfig {
                        base_url: "example.io".into(),
                        api_key: "this-is-a-key".into(),
                        certs_file: "file:///etc/ita-cert.pem".into(),
                        allow_unmatched_policy: Some(true),
                        policy_ids: vec![],
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: Some("/etc/kbs-private.key".into()),
            certificate: Some("/etc/kbs-cert.pem".into()),
            insecure_http: false,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some(PathBuf::from("/etc/kbs-admin.pub")),
            insecure_api: false,
        },
        policy_engine: PolicyEngineConfig {
            policy_path: PathBuf::from("/etc/kbs-policy.rego"),
        },
        plugins: vec![PluginsConfig::Sample(SampleConfig {
            item: "value1".into(),
        }),
        PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
            LocalFsRepoDesc {
                dir_path: "/tmp/kbs-resource".into(),
            },
        ))],
    })]
    #[case("test_data/configs/coco-as-grpc-2.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            ..Default::default()
        },
        #[cfg(feature = "coco-as-grpc")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASGrpc(
                    crate::attestation::coco::grpc::GrpcConfig {
                        as_addr: "http://as:50004".into(),
                        pool_size: crate::attestation::coco::grpc::DEFAULT_POOL_SIZE,
                    },
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: true,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some(PathBuf::from("/opt/confidential-containers/kbs/user-keys/public.pub")),
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-builtin-2.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-builtin")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASBuiltIn(
                    attestation_service::config::Config {
                        work_dir: "/opt/confidential-containers/attestation-service".into(),
                        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig{
                            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config{
                                file_path: "/opt/confidential-containers/attestation-service/reference_values".into(),
                            }),
                            extractors: None,
                        }),
                        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration{
                            duration_min: 5,
                            ..Default::default()
                        }),
                        verifier_config: None,
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: true,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some("/kbs/kbs.pem".into()),
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/intel-ta-2.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_jwk_sets: vec!["https://portal.trustauthority.intel.com".into()],
            insecure_key: false,
            trusted_certs_paths: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "intel-trust-authority-as")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::IntelTA(
                    crate::attestation::intel_trust_authority::IntelTrustAuthorityConfig {
                        base_url: "https://api.trustauthority.intel.com".into(),
                        api_key: "tBfd5kKX2x9ahbodKV1...".into(),
                        certs_file: "https://portal.trustauthority.intel.com".into(),
                        allow_unmatched_policy: None,
                        policy_ids: vec![],
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: true,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some("/kbs/kbs.pem".into()),
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-grpc-3.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            ..Default::default()
        },
        #[cfg(feature = "coco-as-grpc")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASGrpc(
                    crate::attestation::coco::grpc::GrpcConfig {
                        as_addr: "http://127.0.0.1:50004".into(),
                        pool_size: 100,
                    },
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            insecure_http: true,
            ..Default::default()
        },
        admin: AdminConfig {
            insecure_api: true,
            ..Default::default()
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/intel-ta-3.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_jwk_sets: vec!["https://portal.trustauthority.intel.com".into()],
            insecure_key: false,
            trusted_certs_paths: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "intel-trust-authority-as")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::IntelTA(
                    crate::attestation::intel_trust_authority::IntelTrustAuthorityConfig {
                        base_url: "https://api.trustauthority.intel.com".into(),
                        api_key: "tBfd5kKX2x9ahbodKV1...".into(),
                        certs_file: "https://portal.trustauthority.intel.com".into(),
                        allow_unmatched_policy: None,
                        policy_ids: vec![],
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            insecure_http: true,
            ..Default::default()
        },
        admin: AdminConfig {
            insecure_api: true,
            ..Default::default()
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-builtin-3.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-builtin")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASBuiltIn(
                    attestation_service::config::Config {
                        work_dir: "/opt/confidential-containers/attestation-service".into(),
                        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig::default()),
                        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
                            duration_min: 5,
                            policy_dir: "/opt/confidential-containers/attestation-service/simple-policies".into(),
                            ..Default::default()
                        }),
                        verifier_config: None,
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            insecure_http: true,
            ..Default::default()
        },
        admin: AdminConfig {
            insecure_api: true,
            ..Default::default()
        },
        policy_engine: PolicyEngineConfig {
            policy_path: "/opa/confidential-containers/kbs/policy.rego".into(),
        },
        plugins: vec![
        PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
            LocalFsRepoDesc {
                dir_path: "/opt/confidential-containers/kbs/repository".into(),
            },
        ))],
    })]
    fn read_config(#[case] config_path: &str, #[case] expected: KbsConfig) {
        let config = KbsConfig::try_from(Path::new(config_path)).unwrap();
        assert_eq!(config, expected, "case {config_path}");
    }
}
