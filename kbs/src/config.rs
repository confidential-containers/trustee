// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::admin::AdminConfig;
use crate::plugins::PluginsConfig;
use crate::token::AttestationTokenVerifierConfig;
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use config::{Config, File};
use key_value_storage::StorageBackendConfig;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DEFAULT_INSECURE_HTTP: bool = false;
const DEFAULT_SOCKET: &str = "127.0.0.1:8080";
const DEFAULT_PAYLOAD_REQUEST_SIZE: u32 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
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

    /// Number of worker threads for the actix-web server.
    /// If not specified, defaults to the number of logical CPU cores.
    pub worker_count: Option<usize>,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            sockets: vec![DEFAULT_SOCKET.parse().expect("unexpected parse error")],
            private_key: None,
            certificate: None,
            insecure_http: DEFAULT_INSECURE_HTTP,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
            worker_count: None,
        }
    }
}

/// Contains all configurable KBS properties.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
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

    /// Unified storage backend configuration for all storage needs in KBS.
    /// When provided, this will be used to create storage instances for:
    /// - KBS itself (instance: "kbs")
    /// - Resource plugin storage (instance: [`plugins::RESOURCE_STORAGE_NAMESPACE`])
    /// - Built-in AS policy storage (instance: [`attestation_service::CONFIG_POLICY_STORAGE_NAMESPACE`])
    /// - Built-in AS RVPS storage (instance: [`rvps::REFERENCE_VALUE_STORAGE_NAMESPACE`])
    #[serde(default)]
    pub storage_backend: StorageBackendConfig,

    #[serde(default)]
    pub plugins: Vec<PluginsConfig>,
}

impl TryFrom<&Path> for KbsConfig {
    type Error = anyhow::Error;

    /// Load `Config` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate. See `KbsConfig` for schema information.
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let c = Config::builder()
            .add_source(File::with_name(config_path.to_str().unwrap()))
            .build()?;

        c.try_deserialize().map_err(|e| {
            anyhow!(
                "invalid config: {e}\n\n\
If you are upgrading from an older Trustee/KBS version, the configuration schema has changed and some fields were renamed or removed.\n\n\
Common removed/changed fields include: [policy_engine], attestation_service.work_dir, attestation_service.policy_engine, \
attestation_service.attestation_token_broker.policy_dir, attestation_service.rvps_config.storage, and the resource plugin \
fields `type`/`dir_path` (now use `backend = \"kvstorage\"` plus [storage_backend]).\n\n\
For more information, use the `--print-example-config` subcommand/flag to print an example configuration for your version, then compare/update your config accordingly.\n\
You can also refer to the KBS config documentation:\n\n\
\thttps://github.com/confidential-containers/trustee/blob/main/kbs/docs/config.md\n\n\
(Tip: for an exact match to this binary, replace `main` with the `commit` hash printed at startup.)"
            )
        })
    }
}

/// KBS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to a KBS config file. Supported formats: TOML, YAML, JSON and possibly other formats
    /// supported by the `config` crate.
    #[arg(short, long, env = "KBS_CONFIG_FILE")]
    pub config_file: String,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print an example KBS configuration file to stdout.
    ///
    /// The output includes comments explaining what each field does.
    PrintExampleConfig,
}

/// An example KBS configuration in TOML format with per-field comments.
pub fn example_config_toml() -> &'static str {
    r#"# KBS example configuration (TOML)
# This file is meant as a starting point for new deployments and upgrades.
#
# Tip: KBS can run in different modes via features and configuration. If you are upgrading,
# compare your existing config with this example and the version-matched docs for your binary.

# HTTP server settings for KBS.
[http_server]
# One or more sockets to listen on (IP:port).
sockets = ["0.0.0.0:8080"]
# Set to true to disable TLS (development only).
insecure_http = true
# Optional TLS key/certificate paths.
# private_key = "/etc/kbs-private.key"
# certificate = "/etc/kbs-cert.pem"
# Maximum request payload size (MiB) accepted by KBS.
payload_request_size = 2
# Optional: number of HTTP worker threads (defaults to logical CPU cores).
# worker_count = 8

# Admin API authentication/authorization settings.
[admin]
# Admin auth backend. Common values: "DenyAll", "Simple", "InsecureAllowAll".
type = "Simple"

# Define one or more admin personas (public keys) for the "Simple" backend.
[[admin.personas]]
# A human-readable identifier for this admin persona.
id = "admin"
# Path to the public key that verifies admin tokens for this persona.
public_key_path = "/etc/kbs-admin.pub"

# Optional role-based access control rules for admin endpoints.
# If omitted, admins can access all admin endpoints after authentication.
# [[admin.roles]]
# id = "Admin"
# allowed_endpoints = "^/kbs/v1/.*$"

# Attestation Token verification settings used when serving protected resources.
[attestation_token]
# Additional trusted certificate bundle paths (PEM) used to validate JWT signing keys.
trusted_certs_paths = ["/etc/ca-certificates"]
# If true, do not validate the trustworthiness of the JWK inside a token (unsafe).
insecure_key = false
# Optional: URLs/paths to JWK sets (e.g. OpenID discovery) for token verification.
# trusted_jwk_sets = ["https://example.com/.well-known/jwks.json"]
# Optional: extra JSON paths in the JWT body where a TEE public key may be stored.
# extra_teekey_paths = ["/attester_runtime_data/tee-pubkey"]

# Unified storage backend configuration used across KBS components.
# Namespaces are created automatically (kbs, repository, attestation-service-policy, reference-value).
[storage_backend]
# Storage type. Common values: "Memory", "LocalFs", "LocalJson", "Postgres".
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
# Base directory to store persistent data for all namespaces.
dir_path = "/opt/confidential-containers/storage"

# Attestation Service configuration used by the RCAR protocol.
[attestation_service]
# Select the attestation service implementation.
# Common values: "coco_as_builtin", "coco_as_grpc", "intel_ta".
type = "coco_as_builtin"

# When using `coco_as_builtin`, configure the built-in RVPS integration.
[attestation_service.rvps_config]
type = "BuiltIn"

# Attestation result token configuration (EAR token broker).
[attestation_service.attestation_token_broker]
# Token validity duration in minutes.
duration_min = 5
# Optional: provide a signer to persist the signing key/cert chain instead of using an ephemeral key.
# [attestation_service.attestation_token_broker.signer]
# key_path = "/etc/as-token.key"
# cert_path = "/etc/as-token-cert-chain.pem"

# Plugin configuration sections.
[[plugins]]
# Enable the resource plugin (a.k.a. repository) to serve secrets/resources.
name = "resource"
# Use the unified storage backend with namespace `repository`.
backend = "kvstorage"
"#
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        admin::{
            simple::{SimpleAdminConfig, SimplePersonaConfig},
            AdminBackendType, AdminConfig,
        },
        config::{
            HttpServerConfig, DEFAULT_INSECURE_HTTP, DEFAULT_PAYLOAD_REQUEST_SIZE, DEFAULT_SOCKET,
        },
        plugins::{
            implementations::{RepositoryConfig, SampleConfig},
            PluginsConfig,
        },
        token::AttestationTokenVerifierConfig,
    };

    use super::KbsConfig;

    #[cfg(feature = "coco-as-builtin")]
    use attestation_service::{
        ear_token::{EarTokenConfiguration, COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION},
        rvps::{grpc::RvpsRemoteConfig, RvpsConfig},
    };

    use key_value_storage::{
        local_json, KeyValueStorageStructConfig, KeyValueStorageType, StorageBackendConfig,
    };

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
            worker_count: None,
        },
        admin: AdminConfig {
            admin_backend: AdminBackendType::DenyAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::LocalJson,
            backends: KeyValueStorageStructConfig {
                local_json: Some(local_json::Config {
                    file_dir_path: "/opt/confidential-containers/trustee".into(),
                }),
                local_fs: None,
                postgres: None,
            },
        },
        plugins: vec![PluginsConfig::Sample(SampleConfig {
            item: "value1".into(),
        }),
        PluginsConfig::ResourceStorage(RepositoryConfig::KvStorage)],
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
                    crate::attestation::coco::builtin::Config {
                        rvps_config: RvpsConfig::GrpcRemote(RvpsRemoteConfig {
                            address: "http://127.0.0.1:50003".into(),
                        }),
                        attestation_token_broker: EarTokenConfiguration {
                            duration_min: DEFAULT_TOKEN_DURATION,
                            issuer_name: COCO_AS_ISSUER_NAME.into(),
                            signer: None,
                            ..Default::default()
                        },
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
            worker_count: None,
        },
        admin: AdminConfig {
            admin_backend: AdminBackendType::DenyAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::LocalJson,
            backends: KeyValueStorageStructConfig {
                local_json: Some(local_json::Config {
                    file_dir_path: "/opt/confidential-containers/trustee".into(),
                }),
                local_fs: None,
                postgres: None,
            },
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
            worker_count: None,
        },
        admin: AdminConfig {
            admin_backend: AdminBackendType::DenyAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::LocalJson,
            backends: KeyValueStorageStructConfig {
                local_json: Some(local_json::Config {
                    file_dir_path: "/opt/confidential-containers/trustee".into(),
                }),
                local_fs: None,
                postgres: None,
            },
        },
        plugins: vec![PluginsConfig::Sample(SampleConfig {
            item: "value1".into(),
        }),
        PluginsConfig::ResourceStorage(RepositoryConfig::KvStorage)],
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
            worker_count: None,
        },
        admin: AdminConfig {
            admin_backend: AdminBackendType::Simple(SimpleAdminConfig {
                personas: vec![SimplePersonaConfig {
                    id: "admin1".to_string(),
                    public_key_path: "/opt/confidential-containers/trustee/admin1-pubkey.pem".into()
                }],
            }),
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::LocalJson,
            backends: KeyValueStorageStructConfig {
                local_json: Some(local_json::Config {
                    file_dir_path: "/opt/confidential-containers/trustee".into(),
                }),
                local_fs: None,
                postgres: None,
            },
        },
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
                    crate::attestation::coco::builtin::Config {
                        rvps_config: RvpsConfig::BuiltIn { extractors: None },
                        attestation_token_broker: EarTokenConfiguration {
                            duration_min: 5,
                            ..Default::default()
                        },
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
            worker_count: None,
        },
        admin: AdminConfig {
            admin_backend: AdminBackendType::InsecureAllowAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::Memory,
            backends: KeyValueStorageStructConfig {
                local_json: None,
                local_fs: None,
                postgres: None,
            },
        },
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
            worker_count: None,
        },
        admin: AdminConfig {
            admin_backend: AdminBackendType::DenyAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig::default(),
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
            admin_backend: AdminBackendType::DenyAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig::default(),
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
            admin_backend: AdminBackendType::DenyAll,
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig::default(),
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
                    crate::attestation::coco::builtin::Config {
                        rvps_config: RvpsConfig::BuiltIn { extractors: None },
                        attestation_token_broker: EarTokenConfiguration {
                            duration_min: 5,
                            ..Default::default()
                        },
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
            admin_backend: AdminBackendType::Simple(SimpleAdminConfig {
                personas: Vec::new(),
            }),
            roles: Vec::new(),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::LocalJson,
            backends: KeyValueStorageStructConfig {
                    local_json: Some(local_json::Config {
                    file_dir_path: "/opt/confidential-containers/trustee".into(),
                }),
                local_fs: None,
                postgres: None,
            },
        },
        plugins: vec![
            PluginsConfig::ResourceStorage(RepositoryConfig::KvStorage),
        ],
    })]
    fn read_config(#[case] config_path: &str, #[case] expected: KbsConfig) {
        let config = KbsConfig::try_from(Path::new(config_path)).unwrap();
        assert_eq!(config, expected, "case {config_path}");
    }
}
