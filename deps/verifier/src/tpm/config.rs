// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

use super::{DEFAULT_TRUSTED_AK_KEYS_DIR, MAX_TRUSTED_AK_KEYS};

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub tpm_verifier: TpmVerifierConfig,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TpmVerifierConfig {
    #[serde(default = "default_trusted_ak_keys_dir")]
    pub trusted_ak_keys_dir: PathBuf,
    /// Maximum number of trusted AK keys to load. Defaults to 100.
    #[serde(default = "default_max_trusted_ak_keys")]
    pub max_trusted_ak_keys: usize,
}

fn default_trusted_ak_keys_dir() -> PathBuf {
    PathBuf::from(DEFAULT_TRUSTED_AK_KEYS_DIR)
}

fn default_max_trusted_ak_keys() -> usize {
    MAX_TRUSTED_AK_KEYS
}

impl Default for TpmVerifierConfig {
    fn default() -> Self {
        Self {
            trusted_ak_keys_dir: default_trusted_ak_keys_dir(),
            max_trusted_ak_keys: default_max_trusted_ak_keys(),
        }
    }
}

impl TryFrom<&Path> for Config {
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let file = std::fs::File::open(config_path)?;
        serde_json::from_reader(file).map_err(ConfigError::JsonFileParse)
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to parse TPM config file: {0}")]
    JsonFileParse(#[source] serde_json::Error),
}
