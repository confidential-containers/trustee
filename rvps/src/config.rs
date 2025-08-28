// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use anyhow::{Context, Result};
use serde::Deserialize;

use crate::extractors::ExtractorsConfig;
use crate::storage::ReferenceValueStorageConfig;

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Config {
    #[serde(default)]
    pub storage: ReferenceValueStorageConfig,

    #[serde(default)]
    pub extractors: Option<ExtractorsConfig>,
}

impl Config {
    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }
}
