// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Local file of JSON format for the key-value storage.
//!
//! All key-value pairs are stored in a single JSON file.

use std::{collections::HashMap, fs, path::PathBuf, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::{
    expires_at_millis, now_millis, KeyValueStorage, KeyValueStorageError, Result, SetParameters,
    SetResult,
};

/// Default file directory path for the local JSON file.
const FILE_DIR_PATH: &str = "/opt/confidential-containers/storage/local_json";

/// A value in the JSON file. Entries without a TTL keep the original plain
/// base64 string, so files that never use TTL are unchanged.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StoredValue {
    Plain(String),
    Expiring {
        value: String,
        /// Unix time in milliseconds.
        expires_at: u64,
    },
}

impl StoredValue {
    fn new(value: &[u8], ttl: Option<Duration>) -> Self {
        let value = URL_SAFE.encode(value);
        // A TTL too large to represent never expires.
        match ttl.and_then(expires_at_millis) {
            Some(expires_at) => Self::Expiring { value, expires_at },
            None => Self::Plain(value),
        }
    }

    fn is_live(&self, now: u64) -> bool {
        match self {
            Self::Plain(_) => true,
            Self::Expiring { expires_at, .. } => *expires_at > now,
        }
    }

    fn encoded(&self) -> &str {
        match self {
            Self::Plain(value) | Self::Expiring { value, .. } => value,
        }
    }
}

pub struct LocalJson {
    file_path: String,
    lock: RwLock<i32>,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct Config {
    pub file_dir_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_dir_path: FILE_DIR_PATH.to_string(),
        }
    }
}

impl LocalJson {
    pub fn new(config: Config, namespace: &str) -> Result<Self> {
        let path = PathBuf::new();
        let path = path.join(&config.file_dir_path).join(namespace);

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
            std::fs::write(&path, "{}")
                .map_err(|e| KeyValueStorageError::InitializeBackendFailed { source: e.into() })?;
        }

        Ok(Self {
            file_path: path.to_string_lossy().to_string(),
            lock: RwLock::new(0),
        })
    }
}

#[async_trait]
impl KeyValueStorage for LocalJson {
    #[instrument(skip_all, name = "LocalJson::set", fields(key = key))]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult> {
        let _guard = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            }
        })?;
        let mut items: HashMap<String, StoredValue> = serde_json::from_slice(&file)
            .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
        let now = now_millis();
        items.retain(|_, stored| stored.is_live(now));
        if !parameters.overwrite && items.contains_key(key) {
            return Ok(SetResult::AlreadyExists);
        }

        let stored = StoredValue::new(value, parameters.ttl);
        if items.insert(key.to_string(), stored).is_some() {
            debug!(key = key, "key already exists, overwriting");
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
        Ok(SetResult::Inserted)
    }

    #[instrument(skip_all, name = "LocalJson::get", fields(key = key))]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _guard = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: anyhow::anyhow!("failed to read the file: {}", e),
                key: key.to_string(),
            }
        })?;
        let items: HashMap<String, StoredValue> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::MalformedValue {
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let now = now_millis();
        let value = items
            .get(key)
            .filter(|stored| stored.is_live(now))
            .map(|stored| URL_SAFE.decode(stored.encoded()))
            .transpose()
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: anyhow::anyhow!("failed to base64 decode the content inside json: {e}"),
                key: key.to_string(),
            });
        value
    }

    async fn list(&self) -> Result<Vec<String>> {
        let _guard = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::ListKeysFailed {
                source: anyhow::anyhow!("failed to read the file: {}", e),
            }
        })?;
        let items: HashMap<String, StoredValue> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::ListKeysFailed {
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let now = now_millis();
        let keys = items
            .into_iter()
            .filter(|(_, stored)| stored.is_live(now))
            .map(|(key, _)| key)
            .collect();
        Ok(keys)
    }

    #[instrument(skip_all, name = "LocalJson::delete", fields(key = key))]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _guard = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await.map_err(|e| {
            KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            }
        })?;
        let mut items: HashMap<String, StoredValue> =
            serde_json::from_slice(&file).map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                key: key.to_string(),
                source: anyhow::anyhow!("failed to deserialize the file: {}", e),
            })?;
        let now = now_millis();
        let value = items
            .remove(key)
            .filter(|stored| stored.is_live(now))
            .map(|stored| URL_SAFE.decode(stored.encoded()))
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

    fn supports_ttl(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn test_local_json() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            file_dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let storage = LocalJson::new(config, "key_value.json").unwrap();
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

    #[tokio::test]
    async fn test_overwrite_true_replaces_existing() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            file_dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let storage = LocalJson::new(config, "key_value.json").unwrap();
        storage
            .set(
                "key",
                b"original",
                SetParameters {
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let res = storage
            .set(
                "key",
                b"updated",
                SetParameters {
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(res, SetResult::Inserted);
        let value = storage.get("key").await.unwrap().unwrap();
        assert_eq!(value, b"updated");
    }

    #[tokio::test]
    async fn test_overwrite_false_preserves_existing() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            file_dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let storage = LocalJson::new(config, "key_value.json").unwrap();
        storage
            .set(
                "key",
                b"original",
                SetParameters {
                    overwrite: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let res = storage
            .set(
                "key",
                b"updated",
                SetParameters {
                    overwrite: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(res, SetResult::AlreadyExists);
        let value = storage.get("key").await.unwrap().unwrap();
        assert_eq!(value, b"original");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_set_keeps_every_key() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            file_dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let storage = Arc::new(LocalJson::new(config, "key_value.json").unwrap());

        let handles: Vec<_> = (0..50)
            .map(|i| {
                let storage = Arc::clone(&storage);
                tokio::spawn(async move {
                    storage
                        .set(&format!("key_{i}"), b"value", SetParameters::default())
                        .await
                        .unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(storage.list().await.unwrap().len(), 50);
        for i in 0..50 {
            let value = storage.get(&format!("key_{i}")).await.unwrap();
            assert_eq!(value.as_deref(), Some(&b"value"[..]));
        }
    }

    fn new_storage(work_dir: &tempfile::TempDir) -> LocalJson {
        let config = Config {
            file_dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        LocalJson::new(config, "key_value.json").unwrap()
    }

    fn with_ttl(overwrite: bool, ttl: Duration) -> SetParameters {
        SetParameters {
            overwrite,
            ttl: Some(ttl),
        }
    }

    #[tokio::test]
    async fn test_expired_entry_is_absent() {
        let work_dir = tempfile::tempdir().unwrap();
        let storage = new_storage(&work_dir);
        storage
            .set("gone", b"v", with_ttl(true, Duration::ZERO))
            .await
            .unwrap();
        storage
            .set("live", b"v", with_ttl(true, Duration::from_secs(3600)))
            .await
            .unwrap();

        assert_eq!(storage.get("gone").await.unwrap(), None);
        assert_eq!(storage.list().await.unwrap(), vec!["live"]);
        assert_eq!(storage.delete("gone").await.unwrap(), None);
        assert_eq!(storage.get("live").await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn test_write_purges_expired_entries() {
        let work_dir = tempfile::tempdir().unwrap();
        let storage = new_storage(&work_dir);
        storage
            .set("gone", b"v", with_ttl(true, Duration::ZERO))
            .await
            .unwrap();
        storage
            .set("other", b"v", SetParameters::default())
            .await
            .unwrap();

        let file = std::fs::read(&storage.file_path).unwrap();
        let items: HashMap<String, serde_json::Value> = serde_json::from_slice(&file).unwrap();
        assert!(!items.contains_key("gone"));
    }

    #[tokio::test]
    async fn test_ttl_semantics() {
        let work_dir = tempfile::tempdir().unwrap();
        let storage = new_storage(&work_dir);
        let hour = Duration::from_secs(3600);

        storage
            .set("key", b"v1", with_ttl(false, hour))
            .await
            .unwrap();
        let res = storage
            .set("key", b"v2", with_ttl(false, hour))
            .await
            .unwrap();
        assert_eq!(res, SetResult::AlreadyExists);

        // An overwrite without a TTL makes the entry permanent.
        let no_ttl = SetParameters {
            overwrite: true,
            ttl: None,
        };
        storage.set("key", b"v3", no_ttl).await.unwrap();
        let file = std::fs::read(&storage.file_path).unwrap();
        let items: HashMap<String, serde_json::Value> = serde_json::from_slice(&file).unwrap();
        assert!(items["key"].is_string());

        // Setting without overwrite onto an expired entry succeeds.
        storage
            .set("old", b"v1", with_ttl(true, Duration::ZERO))
            .await
            .unwrap();
        let res = storage
            .set("old", b"v2", with_ttl(false, hour))
            .await
            .unwrap();
        assert_eq!(res, SetResult::Inserted);
        assert_eq!(storage.get("old").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_reads_file_written_without_ttl_support() {
        let work_dir = tempfile::tempdir().unwrap();
        let storage = new_storage(&work_dir);
        let legacy = format!(r#"{{"key": "{}"}}"#, URL_SAFE.encode(b"value"));
        std::fs::write(&storage.file_path, legacy).unwrap();
        assert_eq!(storage.get("key").await.unwrap(), Some(b"value".to_vec()));
    }
}
