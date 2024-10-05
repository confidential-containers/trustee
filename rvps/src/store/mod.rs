// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Store is responsible for storing verified Reference Values

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use strum::EnumString;

use self::local_fs::LocalFs;
use self::local_json::LocalJson;

use super::ReferenceValue;

pub mod local_fs;
pub mod local_json;

#[derive(Deserialize, Debug, Clone, EnumString)]
pub enum StoreType {
    LocalFs,
    LocalJson,
}

impl StoreType {
    pub fn to_store(&self, config: Value) -> Result<Box<dyn Store + Send + Sync>> {
        match self {
            StoreType::LocalFs => {
                Ok(Box::new(LocalFs::new(config)?) as Box<dyn Store + Send + Sync>)
            }
            StoreType::LocalJson => {
                Ok(Box::new(LocalJson::new(config)?) as Box<dyn Store + Send + Sync>)
            }
        }
    }
}

/// Interface of a `Store`.
/// Reference value storage facilities should implement this trait.
#[async_trait]
pub trait Store {
    /// Store a reference value. If the given `name` exists,
    /// return the previous `Some<ReferenceValue>`, otherwise return `None`
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>>;

    // Retrieve reference value by name
    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>>;

    // Retrieve reference values
    async fn get_values(&self) -> Result<Vec<ReferenceValue>>;
}
