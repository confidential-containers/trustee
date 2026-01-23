// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Local file of JSON format for the key-value storage.
//!
//! All key-value pairs are stored in a single JSON file.

use std::{collections::HashMap, fs, path::PathBuf};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::{KeyValueStorage, KeyValueStorageError, Result, SetParameters, SetResult};

/// Default file path for the local JSON file.
const FILE_PATH: &str = "/opt/confidential-containers/storage/local_json/key_value.json";

/// Default file directory path for the local JSON file.
const FILE_DIR_PATH: &str = "/opt/confidential-containers/storage/local_json";

pub struct LocalJson {
    file_path: String,
    lock: RwLock<i32>,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct ShimConfig {
    pub file_dir_path: String,
}

impl Default for ShimConfig {
    fn default() -> Self {
        Self {
            file_dir_path: FILE_DIR_PATH.to_string(),
        }
    }
}

impl ShimConfig {
    pub fn to_instance_config(&self, file_name: &str) -> Config {
        Config {
            file_path: self.file_dir_path.clone() + "/" + file_name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub file_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_path: FILE_PATH.to_string(),
        }
    }
}

impl LocalJson {
    pub fn new(config: Config) -> Result<Self> {
        let mut path = PathBuf::new();
        path.push(&config.file_path);

        let parent_dir =
            path.parent()
                .ok_or_else(|| KeyValueStorageError::InitializeBackendFailed {
                    source: anyhow::anyhow!(
                        "Illegal `file_path` for LocalJson's config without a parent dir."
                    ),
                })?;
        debug!(path =? parent_dir, "create file path for LocalJson backend");
        fs::create_dir_all(parent_dir)
            .map_err(|e| KeyValueStorageError::InitializeBackendFailed { source: e.into() })?;

        if !path.exists() {
            debug!(path =? path, "creating empty file for LocalJson backend");
            std::fs::write(config.file_path.clone(), "{}")
                .map_err(|e| KeyValueStorageError::InitializeBackendFailed { source: e.into() })?;
        }

        Ok(Self {
            file_path: config.file_path,
            lock: RwLock::new(0),
        })
    }
}

#[async_trait]
impl KeyValueStorage for LocalJson {
    #[instrument(skip_all, name = "LocalJson::set", fields(key = key))]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            }
        })?;
        let mut items: HashMap<String, String> = serde_json::from_slice(&file)
            .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
        let value_b64 = URL_SAFE.encode(value);
        if parameters.overwrite && items.contains_key(key) {
            return Ok(SetResult::AlreadyExists);
        }

        items.insert(key.to_string(), value_b64);

        let new_contents =
            serde_json::to_string(&items).map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        tokio::fs::write(&self.file_path, new_contents)
            .await
            .map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        Ok(SetResult::Inserted)
    }

    #[instrument(skip_all, name = "LocalJson::get", fields(key = key))]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: anyhow::anyhow!("failed to read the file: {}", e),
                key: key.to_string(),
            }
        })?;
        let items: HashMap<String, String> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::MalformedValue {
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let value = items
            .get(key)
            .map(|v| URL_SAFE.decode(v))
            .transpose()
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: anyhow::anyhow!("failed to base64 decode the content inside json: {e}"),
                key: key.to_string(),
            });
        value
    }

    async fn list(&self) -> Result<Vec<String>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::ListKeysFailed {
                source: anyhow::anyhow!("failed to read the file: {}", e),
            }
        })?;
        let items: HashMap<String, String> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::ListKeysFailed {
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let keys = items.keys().cloned().collect();
        Ok(keys)
    }

    #[instrument(skip_all, name = "LocalJson::delete", fields(key = key))]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            }
        })?;
        let mut items: HashMap<String, String> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                key: key.to_string(),
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let value = items
            .remove(key)
            .map(|v| URL_SAFE.decode(v))
            .transpose()
            .map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                source: anyhow::anyhow!("failed to base64 decode value: {e}"),
                key: key.to_string(),
            })?;
        let contents =
            serde_json::to_vec(&items).map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                key: key.to_string(),
                source: e.into(),
            })?;
        tokio::fs::write(&self.file_path, contents)
            .await
            .map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                source: anyhow::anyhow!("failed to write back to the file: {}", e),
                key: key.to_string(),
            })?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_json() {
        let work_dir = tempfile::tempdir().unwrap();
        let json_file = work_dir.path().join("key_value.json");
        let config = Config {
            file_path: json_file.to_string_lossy().to_string(),
        };
        let storage = LocalJson::new(config).unwrap();
        storage
            .set("test", b"test", SetParameters::default())
            .await
            .unwrap();
        let keys = storage.list().await.unwrap();
        assert_eq!(keys, vec!["test"]);
        let value = storage.get("test").await.unwrap().unwrap();
        assert_eq!(value, b"test");
        let value = storage.delete("test").await.unwrap().unwrap();
        assert_eq!(value, b"test");
        let keys = storage.list().await.unwrap();
        assert_eq!(keys, Vec::<String>::new());
    }
}
