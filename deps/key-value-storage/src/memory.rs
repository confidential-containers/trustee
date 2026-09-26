// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Memory backend for the key-value storage.

use async_trait::async_trait;
use tokio::{sync::RwLock, time::Instant};

use crate::{KeyValueStorage, Result, SetParameters, SetResult};
use std::collections::{BTreeSet, HashMap};
use tracing::instrument;

#[derive(Default)]
pub struct MemoryKeyValueStorage {
    items: RwLock<Items>,
}

struct Entry {
    value: Vec<u8>,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
}

/// `expiries` holds `(expires_at, key)` for exactly the entries that have an
/// expiry, so expired entries can be purged from the front without a scan.
#[derive(Default)]
struct Items {
    entries: HashMap<String, Entry>,
    expiries: BTreeSet<(Instant, String)>,
}

impl Items {
    fn purge_expired(&mut self, now: Instant) {
        while self.expiries.first().is_some_and(|(at, _)| *at <= now) {
            if let Some((_, key)) = self.expiries.pop_first() {
                self.entries.remove(&key);
            }
        }
    }

    fn remove(&mut self, key: &str) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        if let Some(at) = entry.expires_at {
            self.expiries.remove(&(at, key.to_string()));
        }
        Some(entry)
    }
}

#[async_trait]
impl KeyValueStorage for MemoryKeyValueStorage {
    #[instrument(skip_all, name = "MemoryKeyValueStorage::set", fields(key = key))]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult> {
        let now = Instant::now();
        let mut items = self.items.write().await;
        items.purge_expired(now);

        if !parameters.overwrite && items.entries.contains_key(key) {
            return Ok(SetResult::AlreadyExists);
        }

        items.remove(key);
        // A TTL too large to represent never expires.
        let expires_at = parameters.ttl.and_then(|ttl| now.checked_add(ttl));
        if let Some(at) = expires_at {
            items.expiries.insert((at, key.to_string()));
        }
        items.entries.insert(
            key.to_string(),
            Entry {
                value: value.to_vec(),
                expires_at,
            },
        );
        Ok(SetResult::Inserted)
    }

    #[instrument(skip_all, name = "MemoryKeyValueStorage::list")]
    async fn list(&self) -> Result<Vec<String>> {
        let now = Instant::now();
        let keys = self
            .items
            .read()
            .await
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_live(now))
            .map(|(key, _)| key.clone())
            .collect();
        Ok(keys)
    }

    #[instrument(skip_all, name = "MemoryKeyValueStorage::get", fields(key = key))]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let now = Instant::now();
        let res = self
            .items
            .read()
            .await
            .entries
            .get(key)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.value.clone());
        Ok(res)
    }

    #[instrument(skip_all, name = "MemoryKeyValueStorage::delete", fields(key = key))]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let now = Instant::now();
        let res = self
            .items
            .write()
            .await
            .remove(key)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.value);
        Ok(res)
    }

    fn supports_ttl(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;

    fn with_ttl(secs: u64) -> SetParameters {
        SetParameters {
            overwrite: true,
            ttl: Some(Duration::from_secs(secs)),
        }
    }

    /// Every entry with an expiry has a matching index entry, and nothing else.
    async fn assert_index_consistent(storage: &MemoryKeyValueStorage) {
        let items = storage.items.read().await;
        let expected: BTreeSet<_> = items
            .entries
            .iter()
            .filter_map(|(key, entry)| entry.expires_at.map(|at| (at, key.clone())))
            .collect();
        assert_eq!(items.expiries, expected);
    }

    #[tokio::test]
    async fn test_memory_key_value_storage() {
        let storage = MemoryKeyValueStorage::default();
        let parameters = SetParameters::default();
        storage.set("test", b"test", parameters).await.unwrap();
        let keys = storage.list().await.unwrap();
        assert_eq!(keys, vec!["test"]);
        let res = storage.delete("test").await.unwrap();
        assert_eq!(res, Some(b"test".to_vec()));
        let keys = storage.list().await.unwrap();
        assert_eq!(keys, Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn test_expired_entry_is_hidden_then_freed() {
        let storage = MemoryKeyValueStorage::default();
        storage.set("short", b"v", with_ttl(10)).await.unwrap();
        storage
            .set("forever", b"v", SetParameters::default())
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(storage.get("short").await.unwrap(), None);
        assert_eq!(storage.list().await.unwrap(), vec!["forever"]);
        assert_eq!(storage.delete("short").await.unwrap(), None);

        storage.set("short2", b"v", with_ttl(10)).await.unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        // Any write purges what has expired.
        storage
            .set("other", b"v", SetParameters::default())
            .await
            .unwrap();
        let items = storage.items.read().await;
        assert!(!items.entries.contains_key("short2"));
        assert!(items.expiries.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_overwrite_replaces_ttl() {
        let storage = MemoryKeyValueStorage::default();
        storage.set("key", b"v1", with_ttl(10)).await.unwrap();
        tokio::time::advance(Duration::from_secs(5)).await;
        storage.set("key", b"v2", with_ttl(10)).await.unwrap();
        assert_index_consistent(&storage).await;

        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(storage.get("key").await.unwrap(), Some(b"v2".to_vec()));

        let no_ttl = SetParameters {
            overwrite: true,
            ttl: None,
        };
        storage.set("key", b"v3", no_ttl).await.unwrap();
        assert_index_consistent(&storage).await;
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(storage.get("key").await.unwrap(), Some(b"v3".to_vec()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_same_expiry_for_different_keys() {
        let storage = MemoryKeyValueStorage::default();
        storage.set("a", b"v", with_ttl(10)).await.unwrap();
        storage.set("b", b"v", with_ttl(10)).await.unwrap();
        storage.delete("a").await.unwrap();
        assert_index_consistent(&storage).await;
        assert_eq!(storage.get("b").await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_set_without_overwrite() {
        let storage = MemoryKeyValueStorage::default();
        let no_overwrite = || SetParameters {
            overwrite: false,
            ttl: Some(Duration::from_secs(10)),
        };
        assert_eq!(
            storage.set("key", b"v1", no_overwrite()).await.unwrap(),
            SetResult::Inserted
        );
        assert_eq!(
            storage.set("key", b"v2", no_overwrite()).await.unwrap(),
            SetResult::AlreadyExists
        );

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            storage.set("key", b"v3", no_overwrite()).await.unwrap(),
            SetResult::Inserted
        );
        assert_eq!(storage.get("key").await.unwrap(), Some(b"v3".to_vec()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_set_without_overwrite_inserts_once() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let handles: Vec<_> = (0..50)
            .map(|i| {
                let storage = Arc::clone(&storage);
                tokio::spawn(async move {
                    storage
                        .set("key", &[i], SetParameters::default())
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut inserted = 0;
        for handle in handles {
            if handle.await.unwrap() == SetResult::Inserted {
                inserted += 1;
            }
        }
        assert_eq!(inserted, 1);
    }
}
