// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Local file of JSON format for the key-value storage.
//!
//! All key-value pairs are stored in a single JSON file.

use std::{collections::HashMap, fs, path::PathBuf};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::{KeyValueStorage, KeyValueStorageError, Result, SetParameters};

/// Default file path for the local JSON file.
const FILE_PATH: &str = "/opt/confidential-containers/storage/local_json/key_value.json";

pub struct LocalJson {
    file_path: String,
    lock: RwLock<i32>,
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
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<()> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            }
        })?;
        let mut items: HashMap<String, Vec<u8>> = serde_json::from_slice(&file)
            .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
        if parameters.overwrite {
            items.insert(key.to_string(), value.to_vec());
        } else {
            if items.contains_key(key) {
                return Err(KeyValueStorageError::SetKeyFailed {
                    source: anyhow::anyhow!("key already exists"),
                    key: key.to_string(),
                });
            }
            items.insert(key.to_string(), value.to_vec());
        }

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
        Ok(())
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
        let items: HashMap<String, Vec<u8>> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::MalformedValue {
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let value = items.get(key).cloned();
        Ok(value)
    }

    async fn list(&self) -> Result<Vec<String>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::ListKeysFailed {
                source: anyhow::anyhow!("failed to read the file: {}", e),
            }
        })?;
        let items: HashMap<String, Vec<u8>> =
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
        let mut items: HashMap<String, Vec<u8>> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                key: key.to_string(),
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let value = items.remove(key);
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
