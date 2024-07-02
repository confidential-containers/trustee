use crate::rvps::RvpsConfig;
use crate::token::{AttestationTokenBrokerType, AttestationTokenConfig};

use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Environment macro for Attestation Service work dir.
const AS_WORK_DIR: &str = "AS_WORK_DIR";
const DEFAULT_WORK_DIR: &str = "/opt/confidential-containers/attestation-service";

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The location for Attestation Service to store data.
    pub work_dir: PathBuf,

    /// Policy Engine type.
    pub policy_engine: String,

    /// Configurations for RVPS.
    pub rvps_config: RvpsConfig,

    /// The Attestation Result Token Broker type.
    ///
    /// Possible values:
    /// * `Simple`
    pub attestation_token_broker: AttestationTokenBrokerType,

    /// The Attestation Result Token Broker Config
    pub attestation_token_config: AttestationTokenConfig,
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
        let work_dir = PathBuf::from(
            std::env::var(AS_WORK_DIR).unwrap_or_else(|_| DEFAULT_WORK_DIR.to_string()),
        );

        Config {
            work_dir,
            policy_engine: "opa".to_string(),
            rvps_config: RvpsConfig::default(),
            attestation_token_broker: AttestationTokenBrokerType::Simple,
            attestation_token_config: AttestationTokenConfig::default(),
        }
    }
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/attestation-service/",
    ///        "policy_engine": "opa",
    ///        "rvps_config": {
    ///            "store_type": "LocalFs",
    ///            "store_config": {},
    ///            "remote_addr": ""
    ///        },
    ///        "attestation_token_broker": "Simple",
    ///        "attestation_token_config": {
    ///            "duration_min": 5
    ///        }
    ///    }
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, Config>(file).map_err(ConfigError::JsonFileParse)
    }
}
