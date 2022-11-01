use anyhow::{anyhow, Result};
use rvps::store::StoreType;
use serde::Deserialize;
use std::convert::TryFrom;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Environment macro for Attestation Service work dir.
const AS_WORK_DIR: &str = "AS_WORK_DIR";
const DEFAULT_WORK_DIR: &str = "/opt/confidential-containers/attestation-service";

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The location for Attestation Service to store data.
    pub work_dir: PathBuf,

    /// Policy Engine type.
    pub policy_engine: String,

    pub rvps_store_type: StoreType,
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
            rvps_store_type: StoreType::LocalFs,
        }
    }
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/attestation-service/",
    ///        "policy_engine": "opa",
    ///        "rvps_store_type": "LocalFs"
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path)
            .map_err(|e| anyhow!("failed to open AS config file {}", e.to_string()))?;

        serde_json::from_reader::<File, Config>(file)
            .map_err(|e| anyhow!("failed to parse AS config file {}", e.to_string()))
    }
}
