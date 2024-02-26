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
/// We only provide a simple instance here which implements
/// Store. In more scenarios, RV should be stored in persistent
/// storage, like database, file and so on. All of the mentioned
/// forms will have the same interface as following.
#[async_trait]
pub trait Store {
    /// Store a reference value. If the given `name` exists,
    /// return the previous `Some<ReferenceValue>`, otherwise return `None`
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>>;

    // Retrieve a reference value
    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>>;
}
