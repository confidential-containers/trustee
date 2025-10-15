// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A key-value storage interface and implementations.

use async_trait::async_trait;
use serde::Deserialize;

use std::sync::Arc;

pub mod error;
pub use error::{KeyValueStorageError, Result};

pub mod simple;

#[cfg(feature = "postgres")]
pub mod postgres;

#[async_trait]
pub trait KeyValueStorage: Send + Sync {
    async fn set_key(&self, key: String, value: String, overwrite: bool) -> Result<()>;

    async fn list_keys(&self) -> Result<Vec<String>>;

    async fn get_key(&self, key: String) -> Result<String>;
}

#[derive(Deserialize, Debug, Default, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum KeyValueStorageConfig {
    #[cfg(feature = "postgres")]
    #[serde(alias = "postgres")]
    Postgres(postgres::Config),

    #[serde(alias = "simple")]
    #[default]
    Simple,
}

impl KeyValueStorageConfig {
    pub async fn to_key_value_storage(&self) -> Result<Arc<dyn KeyValueStorage>> {
        match self {
            #[cfg(feature = "postgres")]
            KeyValueStorageConfig::Postgres(config) => Ok(Arc::new(
                postgres::PostgresClient::new(config.clone())
                    .await
                    .map_err(|e| KeyValueStorageError::InitializeBackendFailed {
                        source: e.into(),
                    })?,
            )),
            KeyValueStorageConfig::Simple => Ok(Arc::new(simple::SimpleKeyValueStorage::default())),
        }
    }
}
