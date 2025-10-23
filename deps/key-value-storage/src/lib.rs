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

#[derive(Default)]
pub struct SetParameters {
    /// Whether to overwrite the existing value.
    pub overwrite: bool,
}

#[async_trait]
pub trait KeyValueStorage: Send + Sync {
    /// Set a value for a key.
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<()>;

    /// List all keys.
    async fn list(&self) -> Result<Vec<String>>;

    /// Get a value for a key.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a value for a key.
    /// Return the deleted value if it exists.
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>>;
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

/// Check if the key is valid.
///
/// The key is valid if it only contains ASCII alphanumeric characters, `-`, `_` or `.`.
/// No spaces and other special characters are allowed to prevent SQL injection.
pub(crate) fn is_valid_key(key: &str) -> bool {
    key.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}
