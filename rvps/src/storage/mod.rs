// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Store is responsible for storing verified Reference Values

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use strum::Display;

use self::local_fs::LocalFs;
use self::local_json::LocalJson;

use super::ReferenceValue;

pub mod local_fs;
pub mod local_json;

#[derive(Clone, Debug, Deserialize, Display, PartialEq)]
#[serde(tag = "type")]
pub enum ReferenceValueStorageConfig {
    LocalFs(local_fs::Config),
    LocalJson(local_json::Config),
}

impl Default for ReferenceValueStorageConfig {
    fn default() -> Self {
        ReferenceValueStorageConfig::LocalFs(local_fs::Config::default())
    }
}

impl ReferenceValueStorageConfig {
    pub fn to_storage(&self) -> Result<Box<dyn ReferenceValueStorage + Send + Sync>> {
        match self {
            ReferenceValueStorageConfig::LocalFs(cfg) => Ok(Box::new(LocalFs::new(cfg.clone())?)
                as Box<dyn ReferenceValueStorage + Send + Sync>),
            ReferenceValueStorageConfig::LocalJson(cfg) => {
                Ok(Box::new(LocalJson::new(cfg.clone())?)
                    as Box<dyn ReferenceValueStorage + Send + Sync>)
            }
        }
    }
}

/// Interface for `ReferenceValueStorage`.
/// Reference value storage facilities should implement this trait.
#[async_trait]
pub trait ReferenceValueStorage {
    /// Store a reference value. If the given `name` exists,
    /// return the previous `Some<ReferenceValue>`, otherwise return `None`
    fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>>;

    /// Retrieve reference value by name
    fn get(&self, name: &str) -> Result<Option<ReferenceValue>>;

    /// Retrieve reference values
    fn get_values(&self) -> Result<Vec<ReferenceValue>>;
}
