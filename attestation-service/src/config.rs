use crate::ear_token::EarTokenConfiguration;
use crate::rvps::RvpsConfig;

use key_value_storage::StorageBackendConfig;
pub use verifier::VerifierConfig;

use serde::Deserialize;
use std::fs::File;
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
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

    /// Unified storage backend configuration for all storage needs in KBS.
    /// When provided, this will be used to create storage instances for:
    /// - Built-in AS policy storage (instance: "attestation-service-policy")
    /// - Built-in AS RVPS storage (instance: "reference-value")
    #[serde(default)]
    pub storage_backend: StorageBackendConfig,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to parse AS config file: {0}")]
    FileParse(#[source] std::io::Error),
    #[error("failed to parse AS config file: {0}")]
    JsonFileParse(#[source] serde_json::Error),
    #[error("Illegal format of the content of the configuration file: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/attestation-service/",
    ///        "policy_engine": "opa",
    ///        "rvps_config": {
    ///            "storage": {
    ///                "type": "LocalFs"
    ///            }
    ///            "store_config": {},
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
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, Config>(file).map_err(ConfigError::JsonFileParse)
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
                local_fs: Some(local_fs::ShimConfig {
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
