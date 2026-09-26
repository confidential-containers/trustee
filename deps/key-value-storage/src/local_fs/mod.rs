// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Local file system for the key-value storage.
//!
//! Each key-value pair is stored in a separate file in the file system.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::{
    expires_at_millis, is_valid_key, now_millis, KeyValueStorage, KeyValueStorageError, Result,
    SetParameters, SetResult,
};

/// File holding each expiring key's Unix expiry time in milliseconds. `#` is
/// not allowed in keys, so it can never collide with a stored value.
const EXPIRY_INDEX: &str = "#expiry";
const EXPIRY_INDEX_TMP: &str = "#expiry.tmp";

/// Default directory path for the local file system.
const DEFAULT_DIR_PATH: &str = "/opt/confidential-containers/storage/local_fs";

pub struct LocalFs {
    dir_path: PathBuf,
    lock: RwLock<i32>,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct Config {
    /// The directory path for the local file system.
    /// Note that this is a common directory path for all instances.
    ///
    /// Different instances will be stored in different subdirectories under this path.
    pub dir_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dir_path: DEFAULT_DIR_PATH.to_string(),
        }
    }
}

impl LocalFs {
    pub fn new(config: Config, namespace: &str) -> Result<Self> {
        let dir_path = PathBuf::from(&config.dir_path).join(namespace);

        fs::create_dir_all(&dir_path)
            .map_err(|e| KeyValueStorageError::InitializeBackendFailed { source: e.into() })?;

        Ok(Self {
            dir_path,
            lock: RwLock::new(0),
        })
    }
}

impl LocalFs {
    fn file_path(&self, key: &str) -> PathBuf {
        self.dir_path.join(key.replace('/', "\\x2F"))
    }

    async fn load_expiries(&self) -> anyhow::Result<HashMap<String, u64>> {
        match tokio::fs::read(self.dir_path.join(EXPIRY_INDEX)).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Replaces the index atomically, so a crash never leaves it half written.
    async fn save_expiries(&self, expiries: &HashMap<String, u64>) -> anyhow::Result<()> {
        let path = self.dir_path.join(EXPIRY_INDEX);
        if expiries.is_empty() {
            return remove_if_exists(&path).await;
        }
        let tmp = self.dir_path.join(EXPIRY_INDEX_TMP);
        tokio::fs::write(&tmp, serde_json::to_vec(expiries)?).await?;
        tokio::fs::rename(&tmp, &path).await?;
        Ok(())
    }

    async fn is_expired(&self, key: &str) -> anyhow::Result<bool> {
        let expiries = self.load_expiries().await?;
        Ok(expiries.get(key).is_some_and(|at| *at <= now_millis()))
    }
}

async fn remove_if_exists(path: &Path) -> anyhow::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

// The index and a value file cannot be updated together atomically. The index
// is always updated before a value is written and after one is deleted, so a
// crash in between leaves either an index entry for a missing file (ignored)
// or the old value under the new write's expiry, never a written value with
// the wrong expiry.
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
        let set_failed = |source: anyhow::Error| KeyValueStorageError::SetKeyFailed {
            source,
            key: key.to_string(),
        };

        let _guard = self.lock.write().await;
        let mut expiries = self.load_expiries().await.map_err(set_failed)?;
        let now = now_millis();
        let expired: Vec<String> = expiries
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(expired_key, _)| expired_key.clone())
            .collect();
        for expired_key in &expired {
            remove_if_exists(&self.file_path(expired_key))
                .await
                .map_err(set_failed)?;
            expiries.remove(expired_key);
        }

        let file_path = self.file_path(key);
        if !parameters.overwrite && file_path.exists() {
            if !expired.is_empty() {
                self.save_expiries(&expiries).await.map_err(set_failed)?;
            }
            return Ok(SetResult::AlreadyExists);
        }

        if file_path.exists() {
            debug!(file_path =? file_path, "file already exists, overwriting");
        }

        let expires_at = parameters.ttl.and_then(expires_at_millis);
        let index_changed = match expires_at {
            Some(at) => expiries.insert(key.to_string(), at) != Some(at),
            None => expiries.remove(key).is_some(),
        };
        if index_changed || !expired.is_empty() {
            self.save_expiries(&expiries).await.map_err(set_failed)?;
        }

        tokio::fs::write(&file_path, value)
            .await
            .map_err(|e| set_failed(e.into()))?;

        Ok(SetResult::Inserted)
    }

    #[instrument(skip_all, name = "LocalFs::get", fields(key = key))]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _guard = self.lock.read().await;
        let file_path = self.file_path(key);

        let expired =
            self.is_expired(key)
                .await
                .map_err(|source| KeyValueStorageError::GetKeyFailed {
                    source,
                    key: key.to_string(),
                })?;
        if expired || !file_path.exists() {
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
        let _guard = self.lock.read().await;

        let expiries = self
            .load_expiries()
            .await
            .map_err(|source| KeyValueStorageError::ListKeysFailed { source })?;
        let now = now_millis();

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
                let file_name = file_name.to_string_lossy();
                if file_name.starts_with('#') {
                    continue;
                }
                let key = file_name.replace("\\x2F", "/");
                if expiries.get(&key).is_some_and(|at| *at <= now) {
                    continue;
                }
                keys.push(key);
            }
        }
        Ok(keys)
    }

    #[instrument(skip_all, name = "LocalFs::delete", fields(key = key))]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let delete_failed = |source: anyhow::Error| KeyValueStorageError::DeleteKeyFailed {
            source,
            key: key.to_string(),
        };

        let _guard = self.lock.write().await;
        let file_path = self.file_path(key);
        let mut expiries = self.load_expiries().await.map_err(delete_failed)?;
        let expires_at = expiries.remove(key);
        if !file_path.exists() {
            if expires_at.is_some() {
                self.save_expiries(&expiries).await.map_err(delete_failed)?;
            }
            return Ok(None);
        }

        let file =
            tokio::fs::read(&file_path)
                .await
                .map_err(|e| KeyValueStorageError::GetKeyFailed {
                    source: e.into(),
                    key: key.to_string(),
                })?;

        tokio::fs::remove_file(&file_path)
            .await
            .map_err(|e| delete_failed(e.into()))?;
        if expires_at.is_some() {
            self.save_expiries(&expiries).await.map_err(delete_failed)?;
        }

        let live = expires_at.is_none_or(|at| at > now_millis());
        Ok(live.then_some(file))
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
    async fn test_local_fs() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let local_fs = LocalFs::new(config, "test").unwrap();
        local_fs
            .set(
                "test/12/3",
                b"test",
                SetParameters {
                    overwrite: true,
                    ..Default::default()
                },
            )
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_set_without_overwrite_inserts_once() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = Config {
            dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        let local_fs = Arc::new(LocalFs::new(config, "test").unwrap());

        let handles: Vec<_> = (0..50)
            .map(|i| {
                let local_fs = Arc::clone(&local_fs);
                tokio::spawn(async move {
                    let value = format!("value_{i}");
                    let res = local_fs
                        .set(
                            "key",
                            value.as_bytes(),
                            SetParameters {
                                overwrite: false,
                                ..Default::default()
                            },
                        )
                        .await
                        .unwrap();
                    (res, value)
                })
            })
            .collect();
        let mut inserted = Vec::new();
        for handle in handles {
            let (res, value) = handle.await.unwrap();
            if res == SetResult::Inserted {
                inserted.push(value);
            }
        }

        assert_eq!(inserted.len(), 1);
        let stored = local_fs.get("key").await.unwrap().unwrap();
        assert_eq!(stored, inserted[0].as_bytes());
    }

    fn new_local_fs(work_dir: &tempfile::TempDir) -> LocalFs {
        let config = Config {
            dir_path: work_dir.path().to_string_lossy().to_string(),
        };
        LocalFs::new(config, "test").unwrap()
    }

    fn with_ttl(overwrite: bool, ttl: std::time::Duration) -> SetParameters {
        SetParameters {
            overwrite,
            ttl: Some(ttl),
        }
    }

    const HOUR: std::time::Duration = std::time::Duration::from_secs(3600);
    const EXPIRED: std::time::Duration = std::time::Duration::ZERO;

    #[tokio::test]
    async fn test_expired_entry_is_absent_and_index_is_hidden() {
        let work_dir = tempfile::tempdir().unwrap();
        let local_fs = new_local_fs(&work_dir);
        local_fs
            .set("gone", b"v", with_ttl(true, EXPIRED))
            .await
            .unwrap();
        local_fs
            .set("live", b"v", with_ttl(true, HOUR))
            .await
            .unwrap();

        assert_eq!(local_fs.get("gone").await.unwrap(), None);
        assert_eq!(local_fs.list().await.unwrap(), vec!["live"]);
        assert_eq!(local_fs.delete("gone").await.unwrap(), None);
        assert_eq!(local_fs.get("live").await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn test_write_purges_expired_entries() {
        let work_dir = tempfile::tempdir().unwrap();
        let local_fs = new_local_fs(&work_dir);
        local_fs
            .set("gone", b"v", with_ttl(true, EXPIRED))
            .await
            .unwrap();
        local_fs
            .set("other", b"v", SetParameters::default())
            .await
            .unwrap();

        assert!(!local_fs.file_path("gone").exists());
        assert!(local_fs.load_expiries().await.unwrap().is_empty());
        // No expiring entries left, so no index file either.
        assert!(!local_fs.dir_path.join(EXPIRY_INDEX).exists());
    }

    #[tokio::test]
    async fn test_ttl_semantics() {
        let work_dir = tempfile::tempdir().unwrap();
        let local_fs = new_local_fs(&work_dir);

        local_fs
            .set("key", b"v1", with_ttl(false, HOUR))
            .await
            .unwrap();
        let res = local_fs
            .set("key", b"v2", with_ttl(false, HOUR))
            .await
            .unwrap();
        assert_eq!(res, SetResult::AlreadyExists);

        // An overwrite without a TTL makes the entry permanent.
        let no_ttl = SetParameters {
            overwrite: true,
            ttl: None,
        };
        local_fs.set("key", b"v3", no_ttl).await.unwrap();
        assert!(!local_fs.load_expiries().await.unwrap().contains_key("key"));
        assert_eq!(local_fs.get("key").await.unwrap(), Some(b"v3".to_vec()));

        // Setting without overwrite onto an expired entry succeeds.
        local_fs
            .set("old", b"v1", with_ttl(true, EXPIRED))
            .await
            .unwrap();
        let res = local_fs
            .set("old", b"v2", with_ttl(false, HOUR))
            .await
            .unwrap();
        assert_eq!(res, SetResult::Inserted);
        assert_eq!(local_fs.get("old").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_delete_removes_index_entry() {
        let work_dir = tempfile::tempdir().unwrap();
        let local_fs = new_local_fs(&work_dir);
        local_fs
            .set("a/b", b"v", with_ttl(true, HOUR))
            .await
            .unwrap();
        assert_eq!(local_fs.delete("a/b").await.unwrap(), Some(b"v".to_vec()));
        assert!(local_fs.load_expiries().await.unwrap().is_empty());
    }
}
