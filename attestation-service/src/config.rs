use crate::rvps::RvpsConfig;
use crate::token::AttestationTokenConfig;

use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Environment macro for Attestation Service work dir.
const AS_WORK_DIR: &str = "AS_WORK_DIR";
pub const DEFAULT_WORK_DIR: &str = "/opt/confidential-containers/attestation-service";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    /// The location for Attestation Service to store data.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// Configurations for RVPS.
    #[serde(default)]
    pub rvps_config: RvpsConfig,

    /// The Attestation Result Token Broker Config
    #[serde(default)]
    pub attestation_token_broker: AttestationTokenConfig,
}

fn default_work_dir() -> PathBuf {
    PathBuf::from(std::env::var(AS_WORK_DIR).unwrap_or_else(|_| DEFAULT_WORK_DIR.to_string()))
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

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            work_dir: default_work_dir(),
            rvps_config: RvpsConfig::default(),
            attestation_token_broker: AttestationTokenConfig::default(),
        }
    }
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
    ///            "type": "Ear",
    ///            "duration_min": 5
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
    use std::path::PathBuf;

    use super::Config;
    use crate::rvps::RvpsCrateConfig;
    use crate::{
        rvps::RvpsConfig,
        token::{ear_broker, simple, AttestationTokenConfig},
    };
    use reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig};

    #[rstest]
    #[case("./tests/configs/example1.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
            duration_min: 5,
            issuer_name: "test".into(),
            signer: None,
            policy_dir: "/var/lib/attestation-service/policies".into(),
        })
    })]
    #[case("./tests/configs/example2.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
            duration_min: 5,
            issuer_name: "test".into(),
            policy_dir: "/var/lib/attestation-service/policies".into(),
            signer: Some(simple::TokenSignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into())
            })
        })
    })]
    #[case("./tests/configs/example3.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Ear(ear_broker::Configuration {
            duration_min: 5,
            issuer_name: "test".into(),
            signer: None,
            policy_dir: "/var/lib/attestation-service/policies".into(),
            developer_name: "someone".into(),
            build_name: "0.1.0".into(),
            profile_name: "tag:github.com,2024:confidential-containers/Trustee".into()
        })
    })]
    #[case("./tests/configs/example4.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Ear(ear_broker::Configuration {
            duration_min: 5,
            issuer_name: "test".into(),
            policy_dir: "/var/lib/attestation-service/policies".into(),
            developer_name: "someone".into(),
            build_name: "0.1.0".into(),
            profile_name: "tag:github.com,2024:confidential-containers/Trustee".into(),
            signer: Some(ear_broker::TokenSignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into())
            })
        })
    })]
    fn read_config(#[case] config: &str, #[case] expected: Config) {
        let config = std::fs::read_to_string(config).unwrap();
        let config: Config = serde_json::from_str(&config).unwrap();
        assert_eq!(config, expected);
    }
}
