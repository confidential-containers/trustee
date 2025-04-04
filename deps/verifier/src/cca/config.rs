// Copyright (c) 2025 Linaro Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const DEFAULT_CCA_CONFIG: &str =
    "/opt/confidential-containers/attestation-service/cca/config.json";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub cca_verifier: CcaVerifierConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum CcaVerifierConfig {
    #[serde(rename_all = "kebab-case")]
    #[serde(rename = "local")]
    Local {
        ta_store: PathBuf,
        rv_store: PathBuf,
    },
    #[serde(rename_all = "kebab-case")]
    #[serde(rename = "remote")]
    Remote {
        address: String,
        ca_cert: Option<PathBuf>,
    },
}

impl Default for CcaVerifierConfig {
    fn default() -> Self {
        CcaVerifierConfig::Local {
            ta_store: PathBuf::default(),
            rv_store: PathBuf::default(),
        }
    }
}

impl TryFrom<&Path> for Config {
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, Config>(file).map_err(ConfigError::JsonFileParse)
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to parse CCA config file: {0}")]
    JsonFileParse(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_type() {
        let tc = r#"{
            "cca-verifier": {
                "type": "random",
                "whatever": "xyz"
            }
        }"#
        .to_string();

        let result: Result<Config, serde_json::Error> = serde_json::from_str(&tc);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "unknown variant `random`, expected `local` or `remote` at line 3 column 32"
        );
    }

    #[test]
    fn local_ok() {
        let tc = r#"{
            "cca-verifier": {
                "type": "local",
                "rv-store": "./rv.json",
                "ta-store": "./ta.json"
            }
        }"#
        .to_string();

        let c: Config = serde_json::from_str(&tc).unwrap();

        println!("{:#?}", c);

        assert!(matches!(c.cca_verifier, CcaVerifierConfig::Local { .. }));

        if let CcaVerifierConfig::Local { ta_store, rv_store } = c.cca_verifier {
            assert_eq!(ta_store, PathBuf::from("./ta.json"));
            assert_eq!(rv_store, PathBuf::from("./rv.json"));
        }
    }

    #[test]
    fn local_missing_mandatory_ta_store() {
        let tc = r#"{
            "cca-verifier": {
                "type": "local",
                "rv-store": "./rv.json"
            }
        }"#
        .to_string();

        let result: Result<Config, serde_json::Error> = serde_json::from_str(&tc);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "missing field `ta-store` at line 6 column 9"
        );
    }

    #[test]
    fn local_missing_mandatory_rv_store() {
        let tc = r#"{
            "cca-verifier": {
                "type": "local",
                "ta-store": "./ta.json"
            }
        }"#
        .to_string();

        let result: Result<Config, serde_json::Error> = serde_json::from_str(&tc);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "missing field `rv-store` at line 6 column 9"
        );
    }

    #[test]
    fn remote_ok() {
        let tc = r#"{
            "cca-verifier": {
                "type": "remote",
                "address": "https://localhost:8443",
                "ca-cert": "./rootCA.crt"
            }
        }"#
        .to_string();

        let c: Config = serde_json::from_str(&tc).unwrap();

        println!("{:#?}", c);

        assert!(matches!(c.cca_verifier, CcaVerifierConfig::Remote { .. }));

        if let CcaVerifierConfig::Remote { address, ca_cert } = c.cca_verifier {
            assert_eq!(address, "https://localhost:8443");
            assert!(ca_cert.is_some());
            assert_eq!(ca_cert.unwrap(), PathBuf::from("./rootCA.crt"));
        }
    }

    #[test]
    fn remote_ok_missing_optional_ca_cert() {
        let tc = r#"{
            "cca-verifier": {
                "type": "remote",
                "address": "https://localhost:8443"
            }
        }"#
        .to_string();

        let c: Config = serde_json::from_str(&tc).unwrap();

        println!("{:#?}", c);

        assert!(matches!(c.cca_verifier, CcaVerifierConfig::Remote { .. }));

        if let CcaVerifierConfig::Remote { address, ca_cert } = c.cca_verifier {
            assert_eq!(address, "https://localhost:8443");
            assert!(ca_cert.is_none());
        }
    }

    #[test]
    fn remote_missing_mandatory_address() {
        let tc = r#"{
            "cca-verifier": {
                "type": "remote",
                "ca-cert": "rootCA.crt"
            }
        }"#
        .to_string();

        let result: Result<Config, serde_json::Error> = serde_json::from_str(&tc);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "missing field `address` at line 6 column 9"
        );
    }
}
