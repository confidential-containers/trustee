// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A key-value storage interface and implementations.

use async_trait::async_trait;
use serde::Deserialize;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub mod error;
pub use error::{KeyValueStorageError, Result};

pub mod memory;

#[cfg(feature = "postgres")]
pub mod postgres;

pub mod local_json;

pub mod local_fs;

#[derive(Default)]
pub struct SetParameters {
    /// Whether to overwrite the existing value.
    pub overwrite: bool,
}

pub enum SetResult {
    Inserted,
    AlreadyExists,
}

#[async_trait]
pub trait KeyValueStorage: Send + Sync {
    /// Set a value for a key.
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult>;

    /// List all keys.
    async fn list(&self) -> Result<Vec<String>>;

    /// Get a value for a key.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a value for a key.
    /// Return the deleted value if it exists.
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>>;
}

pub type KeyValueStorageInstance = Arc<dyn KeyValueStorage>;

#[derive(Deserialize, Debug, Default, Clone, PartialEq)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum KeyValueStorageConfig {
    #[cfg(feature = "postgres")]
    #[serde(alias = "postgres")]
    Postgres(postgres::Config),

    #[serde(alias = "Memory")]
    #[default]
    Memory,

    #[serde(alias = "LocalJson")]
    LocalJson(local_json::Config),

    #[serde(alias = "LocalFs")]
    LocalFs(local_fs::Config),
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
            ) as _),
            KeyValueStorageConfig::Memory => {
                Ok(Arc::new(memory::MemoryKeyValueStorage::default()) as _)
            }
            KeyValueStorageConfig::LocalJson(config) => {
                Ok(Arc::new(local_json::LocalJson::new(config.clone())?) as _)
            }
            KeyValueStorageConfig::LocalFs(config) => {
                Ok(Arc::new(local_fs::LocalFs::new(config.clone())?) as _)
            }
        }
    }
}

#[derive(Deserialize, Debug, Default, Clone, PartialEq)]
pub enum KeyValueStorageType {
    #[default]
    Memory,
    LocalJson,
    LocalFs,
    Postgres,
}

#[derive(Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KeyValueStorageStructConfig {
    #[cfg(feature = "postgres")]
    postgres: Option<postgres::ShimConfig>,
    local_json: Option<local_json::ShimConfig>,
    local_fs: Option<local_fs::ShimConfig>,
}

impl KeyValueStorageStructConfig {
    /// Convert the configuration to a client with the given instance name.
    ///
    /// The instance name is used to interpreted by the concrete backend, e.g.
    /// the PostgreSQL backend will use the instance name as the table name.
    ///
    /// The
    pub async fn to_client_with_instance(
        &self,
        r#type: KeyValueStorageType,
        instance: &str,
    ) -> Result<Arc<dyn KeyValueStorage>> {
        match r#type {
            #[cfg(feature = "postgres")]
            KeyValueStorageType::Postgres => {
                let config = self
                    .postgres
                    .as_ref()
                    .ok_or(KeyValueStorageError::InvalidConfiguration {
                        message: "PostgreSQL configuration is required".to_string(),
                    })?
                    .to_instance_config(instance);
                Ok(Arc::new(postgres::PostgresClient::new(config).await?) as _)
            }
            KeyValueStorageType::LocalJson => {
                let config = self
                    .local_json
                    .as_ref()
                    .ok_or(KeyValueStorageError::InvalidConfiguration {
                        message: "Local JSON configuration is required".to_string(),
                    })?
                    .to_instance_config(instance);
                Ok(Arc::new(local_json::LocalJson::new(config)?) as _)
            }
            KeyValueStorageType::LocalFs => {
                let config = self
                    .local_fs
                    .as_ref()
                    .ok_or(KeyValueStorageError::InvalidConfiguration {
                        message: "Local FS configuration is required".to_string(),
                    })?
                    .to_instance_config(instance);
                Ok(Arc::new(local_fs::LocalFs::new(config)?) as _)
            }
            KeyValueStorageType::Memory => {
                Ok(Arc::new(memory::MemoryKeyValueStorage::default()) as _)
            }
        }
    }

    pub fn replace_base_dir(&mut self, base_dir: &Path) {
        if let Some(config) = self.local_fs.as_mut() {
            config.dir_path = replace_base_dir(Path::new(&config.dir_path), base_dir)
                .to_string_lossy()
                .into_owned()
        };
        if let Some(config) = self.local_json.as_mut() {
            config.file_dir_path = replace_base_dir(Path::new(&config.file_dir_path), base_dir)
                .to_string_lossy()
                .into_owned()
        };
    }
}

/// Check if the key is valid.
///
/// The key is valid if it only contains ASCII alphanumeric characters, `-`, `_` or `.`.
/// No spaces and other special characters are allowed to prevent SQL injection.
pub(crate) fn is_valid_key(key: &str) -> bool {
    key.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
}

/// replace_base_dir replaces the leading `/opt/confidential-containers/` in the path with a new base path.
///
/// This behavior is a compromise to set the base directory at runtime and workaround the hardcoded paths all around the codebase.
/// replace_base_dir will become obsolete when it's possible to set the base directory at runtime project-wide.
fn replace_base_dir(path: &Path, new_base: &Path) -> PathBuf {
    let old_base = "/opt/confidential-containers/";
    if let Ok(suffix) = path.strip_prefix(old_base) {
        new_base.join(suffix)
    } else if path.starts_with("/") {
        path.to_path_buf()
    } else {
        new_base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_value_storage_config() {
        let config = r#"
[postgres]
db = "test"
username = "test"
password = "test"
port = 5432
host = "localhost"

[local_json]
file_dir_path = "/opt/confidential-containers/storage/local_json"

[local_fs]
dir_path = "/opt/confidential-containers/storage/local_fs"
        "#;
        let config: KeyValueStorageStructConfig = toml::from_str(config).unwrap();
        assert_eq!(config.postgres.as_ref().unwrap().db, "test");
        assert_eq!(
            config.local_json.as_ref().unwrap().file_dir_path,
            "/opt/confidential-containers/storage/local_json"
        );
        assert_eq!(
            config.local_fs.as_ref().unwrap().dir_path,
            "/opt/confidential-containers/storage/local_fs"
        );
    }
}
