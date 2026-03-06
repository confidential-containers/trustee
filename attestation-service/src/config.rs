use crate::ear_token::EarTokenConfiguration;
use crate::rvps::RvpsConfig;

use config::{Config as RawConfig, File as RawFile};
use key_value_storage::StorageBackendConfig;
pub use verifier::VerifierConfig;

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configurations for RVPS.
    #[serde(default)]
    pub rvps_config: RvpsConfig,

    /// The Attestation Result Token Broker Config
    #[serde(default)]
    pub attestation_token_broker: EarTokenConfiguration,

    /// Optional configuration for verifier modules
    #[serde(default)]
    pub verifier_config: Option<VerifierConfig>,

    /// Unified storage backend configuration for all storage needs in CoCo AS.
    /// When provided, this will be used to create storage instances for:
    /// - Built-in AS policy storage (instance: "attestation-service-policy")
    /// - Built-in AS RVPS storage (instance: "reference-value")
    #[serde(default)]
    pub storage_backend: StorageBackendConfig,
}

impl Config {
    /// An example Attestation Service configuration in TOML format with per-field comments.
    pub fn example_config_toml() -> &'static str {
        r#"# Attestation Service example configuration (TOML)
# This file is meant as a starting point for new deployments and upgrades.

# Unified storage backend configuration used by the built-in AS policy store and the built-in RVPS.
[storage_backend]
# Storage type. Common values: Memory, LocalFs, LocalJson, Postgres.
storage_type = "LocalFs"
[storage_backend.backends.local_fs]
# Base directory used for persistent data (namespaces are created internally).
dir_path = "/opt/confidential-containers/storage"

# RVPS integration configuration.
[rvps_config]
# Select RVPS mode. Common values: BuiltIn, GrpcRemote.
type = "BuiltIn"
# Optional: provenance extractor configuration for BuiltIn RVPS.
# extractors = {}

# Attestation Result Token Broker configuration (EAR token settings).
[attestation_token_broker]
# Token validity duration in minutes.
duration_min = 5
# Optional: configure a persistent signing key/certificate chain.
# [attestation_token_broker.signer]
# key_path = "/etc/as-token.key"
# cert_path = "/etc/as-token-cert-chain.pem"

# Optional: verifier-specific configuration (for example TPM verifier limits).
# [verifier_config.tpm_verifier]
# trusted_ak_keys_dir = "/etc/tpm/trusted_ak_keys"
# max_trusted_ak_keys = 100
"#
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error(
        "invalid AS config: {0}\n\n\
If you are upgrading from an older version, the configuration format may have changed.\n\
Fields removed or replaced in this version: work_dir, policy_engine, attestation_token_broker.policy_dir, rvps_config.storage (for BuiltIn).\n\
For more information, use the `--print-example-config` subcommand/flag to print an example configuration for your version, then compare/update your config accordingly.\n\
You can also refer to the Attestation Service config documentation:\n\
https://github.com/confidential-containers/trustee/blob/main/attestation-service/docs/config.md\n\
(Tip: for an exact match to this binary, replace `main` with the `commit` hash printed at startup.)"
    )]
    Parse(#[from] config::ConfigError),
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file. Example:
    ///    {
    ///        "storage_backend": {
    ///            "storage_type": "LocalFs",
    ///            "backends": {
    ///                "local_fs": {
    ///                    "dir_path": "/var/lib/attestation-service/storage"
    ///                }
    ///            }
    ///        }
    ///        },
    ///        "rvps_config": {
    ///            "type": "BuiltIn"
    ///        },
    ///        "attestation_token_broker": {
    ///            "duration_min": 5
    ///        },
    ///        "verifier_config": {
    ///            "tpm_verifier": {
    ///                "trusted_ak_keys_dir": "/etc/tpm/trusted_ak_keys",
    ///                "max_trusted_ak_keys": 100
    ///            }
    ///        }
    ///    }
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let c = RawConfig::builder()
            .add_source(RawFile::with_name(config_path.to_str().unwrap()))
            .build()?;
        c.try_deserialize().map_err(ConfigError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::Config;
    use crate::ear_token::TokenSignerConfig;
    use crate::{ear_token::EarTokenConfiguration, rvps::RvpsConfig};
    use key_value_storage::{
        local_fs, KeyValueStorageStructConfig, KeyValueStorageType, StorageBackendConfig,
    };

    #[rstest]
    #[case("./tests/configs/example1.json", Config {
        rvps_config: RvpsConfig::BuiltIn { extractors: None },
        attestation_token_broker: EarTokenConfiguration {
            duration_min: 5,
            issuer_name: "test".into(),
            signer: None,
            developer_name: "someone".into(),
            build_name: "0.1.0".into(),
            profile_name: "tag:github.com,2024:confidential-containers/Trustee".into(),
        },
        verifier_config: None,
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::LocalFs,
            backends: KeyValueStorageStructConfig {
                local_fs: Some(local_fs::Config {
                    dir_path: "/opt/confidential-containers/attestation-service".into(),
                }),
                local_json: None,
                postgres: None,
            },
        },
    })]
    #[case("./tests/configs/example2.json", Config {
        rvps_config: RvpsConfig::BuiltIn { extractors: None },
        attestation_token_broker: EarTokenConfiguration {
            duration_min: 5,
            issuer_name: "test".into(),
            developer_name: "someone".into(),
            build_name: "0.1.0".into(),
            profile_name: "tag:github.com,2024:confidential-containers/Trustee".into(),
            signer: Some(TokenSignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into())
            }),
        },
        storage_backend: StorageBackendConfig {
            storage_type: KeyValueStorageType::Memory,
            backends: KeyValueStorageStructConfig::default(),
        },
        verifier_config: None,
    })]
    fn read_config(#[case] config: &str, #[case] expected: Config) {
        let config = std::fs::read_to_string(config).unwrap();
        let config: Config = serde_json::from_str(&config).unwrap();
        assert_eq!(config, expected);
    }
}
