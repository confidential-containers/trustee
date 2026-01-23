// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Local file system for the key-value storage.
//!
//! Each key-value pair is stored in a separate file in the file system.

use std::{fs, path::PathBuf};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::instrument;

use crate::{
    is_valid_key, KeyValueStorage, KeyValueStorageError, Result, SetParameters, SetResult,
};

/// Default file path for the local JSON file.
const FILE_PATH: &str = "/opt/confidential-containers/storage/local_fs/default";

/// Default directory path for the local file system.
const DEFAULT_DIR_PATH: &str = "/opt/confidential-containers/storage/local_fs";

pub struct LocalFs {
    dir_path: PathBuf,
    lock: RwLock<i32>,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct ShimConfig {
    /// The directory path for the local file system.
    /// Note that this is a common directory path for all instances.
    ///
    /// Different instances will be stored in different subdirectories under this path.
    pub dir_path: String,
}

impl Default for ShimConfig {
    fn default() -> Self {
        Self {
            dir_path: DEFAULT_DIR_PATH.to_string(),
        }
    }
}

impl ShimConfig {
    pub fn to_instance_config(&self, instance: &str) -> Config {
        Config {
            dir_path: self.dir_path.clone() + "/" + instance,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub dir_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dir_path: FILE_PATH.to_string(),
        }
    }
}

impl LocalFs {
    pub fn new(config: Config) -> Result<Self> {
        let dir_path = PathBuf::from(&config.dir_path);

        fs::create_dir_all(&dir_path)
            .map_err(|e| KeyValueStorageError::InitializeBackendFailed { source: e.into() })?;

        Ok(Self {
            dir_path,
            lock: RwLock::new(0),
        })
    }
}

#[async_trait]
impl KeyValueStorage for LocalFs {
    #[instrument(skip_all, name = "LocalFs::set", fields(key = key))]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult> {
        if !is_valid_key(key) {
            return Err(KeyValueStorageError::SetKeyFailed {
                source: anyhow::anyhow!("key contains invalid characters"),
                key: key.to_string(),
            });
        }

        let _ = self.lock.write().await;
        let file_path = self.dir_path.join(key.replace('/', "\\x2F"));

        if parameters.overwrite || !file_path.exists() {
            tokio::fs::write(&file_path, value).await.map_err(|e| {
                KeyValueStorageError::SetKeyFailed {
                    source: e.into(),
                    key: key.to_string(),
                }
            })?;
        }

        if !parameters.overwrite && file_path.exists() {
            return Ok(SetResult::AlreadyExists);
        }

        Ok(SetResult::Inserted)
    }

    #[instrument(skip_all, name = "LocalFs::get", fields(key = key))]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _ = self.lock.read().await;
        let file_path = self.dir_path.join(key.replace('/', "\\x2F"));

        if !file_path.exists() {
            return Ok(None);
        }

        let file =
            tokio::fs::read(&file_path)
                .await
                .map_err(|e| KeyValueStorageError::GetKeyFailed {
                    source: anyhow::anyhow!("failed to read the file: {}", e),
                    key: key.to_string(),
                })?;
        Ok(Some(file))
    }

    async fn list(&self) -> Result<Vec<String>> {
        let _ = self.lock.read().await;

        let mut keys = Vec::new();
        let mut files = tokio::fs::read_dir(&self.dir_path).await.map_err(|e| {
            KeyValueStorageError::ListKeysFailed {
                source: anyhow::anyhow!("failed to read the directory: {}", e),
            }
        })?;

        while let Some(file) =
            files
                .next_entry()
                .await
                .map_err(|e| KeyValueStorageError::ListKeysFailed {
                    source: anyhow::anyhow!("failed to read the directory: {}", e),
                })?
        {
            if let Some(file_name) = file.path().file_name() {
                keys.push(
                    file_name
                        .to_string_lossy()
                        .to_string()
                        .replace("\\x2F", "/"),
                );
            }
        }
        Ok(keys)
    }

    #[instrument(skip_all, name = "LocalFs::delete", fields(key = key))]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _ = self.lock.write().await;
        let file_path = self.dir_path.join(key.replace('/', "\\x2F"));
        if !file_path.exists() {
            return Ok(None);
        }

        let file =
            tokio::fs::read(&file_path)
                .await
                .map_err(|e| KeyValueStorageError::GetKeyFailed {
                    source: e.into(),
                    key: key.to_string(),
                })?;

        tokio::fs::remove_file(&file_path).await.map_err(|e| {
            KeyValueStorageError::DeleteKeyFailed {
                source: e.into(),
                key: key.to_string(),
            }
        })?;
        Ok(Some(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_fs() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let local_fs = LocalFs::new(config).unwrap();
        local_fs
            .set("test/12/3", b"test", SetParameters { overwrite: true })
            .await
            .unwrap();
        let value = local_fs.get("test/12/3").await.unwrap().unwrap();
        assert_eq!(value, b"test");
        let keys = local_fs.list().await.unwrap();
        assert_eq!(keys, vec!["test/12/3"]);
        let value = local_fs.delete("test/12/3").await.unwrap().unwrap();
        assert_eq!(value, b"test");
        let keys = local_fs.list().await.unwrap();
        assert_eq!(keys, Vec::<String>::new());
    }
}
