// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Backs [`pluggable_cache`] persistent and tiered caches with Trustee's
//! [`key_value_storage`].
//!
//! A [`KvByteStoreProvider`] wraps a [`StorageProvider`], so cache namespaces
//! live in the same backend (local file system, PostgreSQL, Redis, ...) the
//! rest of the component is configured with, or in one named by the cache
//! configuration's `persistent.storage_type`.

use std::sync::Arc;

use async_trait::async_trait;
use key_value_storage::{
    KeyValueStorageError, KeyValueStorageInstance, KeyValueStorageType, SetParameters,
    StorageProvider,
};
use pluggable_cache::{
    store::{ByteStore, ByteStoreInstance, ByteStoreProvider},
    CacheError, Result,
};
use serde::{de::value::StrDeserializer, Deserialize};

fn backend_error(source: KeyValueStorageError) -> CacheError {
    CacheError::Backend {
        source: Box::new(source),
    }
}

/// Parse the name of a storage backend, e.g. `memory` or `local_fs`.
fn parse_backend(name: &str) -> Result<KeyValueStorageType> {
    KeyValueStorageType::deserialize(StrDeserializer::<serde::de::value::Error>::new(name)).map_err(
        |_| CacheError::InvalidConfiguration {
            message: format!("unknown storage backend `{name}`"),
        },
    )
}

/// A [`ByteStore`] over one key-value storage namespace.
struct KvByteStore(KeyValueStorageInstance);

#[async_trait]
impl ByteStore for KvByteStore {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.0
            .set(key, value, SetParameters { overwrite: true })
            .await
            .map(|_| ())
            .map_err(backend_error)
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.0.get(key).await.map_err(backend_error)
    }

    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.0.delete(key).await.map_err(backend_error)
    }

    async fn list(&self) -> Result<Vec<String>> {
        self.0.list().await.map_err(backend_error)
    }
}

/// A [`ByteStoreProvider`] minting stores from a [`StorageProvider`].
pub struct KvByteStoreProvider {
    storage: Arc<dyn StorageProvider>,
}

impl KvByteStoreProvider {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Arc<Self> {
        Arc::new(Self { storage })
    }
}

#[async_trait]
impl ByteStoreProvider for KvByteStoreProvider {
    fn validate_backend(&self, backend: &str) -> Result<()> {
        parse_backend(backend).map(|_| ())
    }

    async fn get_or_register(
        &self,
        namespace: &str,
        backend: Option<&str>,
    ) -> Result<ByteStoreInstance> {
        let storage = match backend {
            Some(name) => {
                self.storage
                    .get_or_register_with_type(namespace, parse_backend(name)?)
                    .await
            }
            None => self.storage.get_or_register(namespace).await,
        }
        .map_err(backend_error)?;
        Ok(Arc::new(KvByteStore(storage)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::{KeyValueStorageStructConfig, KvStorageProvider, StorageBackendConfig};

    fn provider() -> (Arc<KvStorageProvider>, Arc<KvByteStoreProvider>) {
        let storage = KvStorageProvider::new(StorageBackendConfig {
            storage_type: KeyValueStorageType::Memory,
            backends: KeyValueStorageStructConfig::default(),
        });
        let provider = KvByteStoreProvider::new(storage.clone());
        (storage, provider)
    }

    #[test]
    fn backend_names_match_the_configuration_spelling() {
        let (_, provider) = provider();
        for name in [
            "memory", "Memory", "local_fs", "LocalFs", "redis", "postgres",
        ] {
            provider.validate_backend(name).unwrap();
        }
        assert!(provider.validate_backend("nonsense").is_err());
    }

    #[tokio::test]
    async fn stores_share_data_with_the_storage_namespace() {
        let (storage, provider) = provider();
        let store = provider.get_or_register("cache_ns", None).await.unwrap();
        store.set("k", b"v1").await.unwrap();
        store.set("k", b"v2").await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), Some(b"v2".to_vec()));
        assert_eq!(store.list().await.unwrap(), ["k"]);

        let direct = storage.get_or_register("cache_ns").await.unwrap();
        assert_eq!(direct.get("k").await.unwrap(), Some(b"v2".to_vec()));

        assert_eq!(store.delete("k").await.unwrap(), Some(b"v2".to_vec()));
        assert_eq!(store.get("k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn named_backend_is_honoured() {
        let (_, provider) = provider();
        provider
            .get_or_register("cache_ns", Some("memory"))
            .await
            .unwrap();
        assert!(provider
            .get_or_register("cache_other", Some("nonsense"))
            .await
            .is_err());
    }
}
