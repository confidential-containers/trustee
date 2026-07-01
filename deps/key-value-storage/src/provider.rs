// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! On-demand provider for namespaced key-value storages.
//!
//! Instead of threading a concrete storage handle (or the backend config)
//! through every layer, a component is handed a [`StorageProvider`] and mints
//! the namespaces it needs in-place, e.g.:
//!
//! ```ignore
//! let policy = provider.get_or_register("attestation_service_policy").await?;
//! ```
//!
//! The provider owns the backend configuration, so callers stay decoupled from
//! the concrete backend (postgres, redis, local fs, ...). The dependency is
//! explicit (it shows up in the constructor signature), there is no global
//! initialization order to get right, and multiple providers with different
//! configs can coexist in one process (useful for tests and the all-in-one
//! binary).
//!
//! Use [`scoped`] to hand a *restricted* provider to less-trusted code (such as
//! an individual verifier): every namespace it requests is confined under a
//! fixed prefix, so it cannot reach a sibling component's namespace.

use crate::{
    KeyValueStorageError, KeyValueStorageInstance, KeyValueStorageType, Result,
    StorageBackendConfig,
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

/// Mints namespaced key-value storage instances on demand.
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Return the storage for `namespace`, creating it if necessary, using the
    /// provider's default storage type.
    ///
    /// Idempotent: repeated calls for the same namespace return the same
    /// instance.
    async fn get_or_register(&self, namespace: &str) -> Result<KeyValueStorageInstance>;

    /// Like [`StorageProvider::get_or_register`] but pins the backend type for
    /// this namespace, overriding the provider's default.
    async fn get_or_register_with_type(
        &self,
        namespace: &str,
        storage_type: KeyValueStorageType,
    ) -> Result<KeyValueStorageInstance>;
}

/// The default [`StorageProvider`], backed by a single [`StorageBackendConfig`].
pub struct KvStorageProvider {
    config: StorageBackendConfig,
    instances: RwLock<HashMap<String, KeyValueStorageInstance>>,
}

impl KvStorageProvider {
    /// Create a provider that mints storages from `config`.
    pub fn new(config: StorageBackendConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            instances: RwLock::new(HashMap::new()),
        })
    }

    /// The backend configuration this provider mints storages from.
    pub fn config(&self) -> &StorageBackendConfig {
        &self.config
    }
}

#[async_trait]
impl StorageProvider for KvStorageProvider {
    async fn get_or_register(&self, namespace: &str) -> Result<KeyValueStorageInstance> {
        self.get_or_register_with_type(namespace, self.config.storage_type)
            .await
    }

    async fn get_or_register_with_type(
        &self,
        namespace: &str,
        storage_type: KeyValueStorageType,
    ) -> Result<KeyValueStorageInstance> {
        validate_namespace(namespace)?;

        if let Some(storage) = self.instances.read().await.get(namespace) {
            return Ok(storage.clone());
        }

        // Build the client outside the write lock: `to_client_with_namespace`
        // may do I/O (e.g. open a DB connection) and we don't want to block
        // other namespaces meanwhile. Re-checking under the write lock keeps the
        // mint idempotent if another task raced us to the same namespace.
        let storage = self
            .config
            .backends
            .to_client_with_namespace(storage_type, namespace)
            .await?;

        let mut instances = self.instances.write().await;
        if let Some(existing) = instances.get(namespace) {
            return Ok(existing.clone());
        }
        instances.insert(namespace.to_string(), storage.clone());
        Ok(storage)
    }
}

/// A [`StorageProvider`] that confines every namespace under a fixed prefix.
///
/// Created via [`scoped`]. A request for `"foo"` is served as `"<prefix>/foo"`
/// against the inner provider, and there is no way to escape the prefix. Note
/// that the prefix becomes part of the namespace identifier (table name for
/// SQL backends, sub-directory for file backends), so the chosen prefix and
/// sub-namespaces must be valid for the configured backend.
struct ScopedStorageProvider {
    inner: Arc<dyn StorageProvider>,
    prefix: String,
}

impl ScopedStorageProvider {
    fn scoped_namespace(&self, namespace: &str) -> Result<String> {
        validate_namespace(namespace)?;
        Ok(format!("{}/{}", self.prefix, namespace))
    }
}

#[async_trait]
impl StorageProvider for ScopedStorageProvider {
    async fn get_or_register(&self, namespace: &str) -> Result<KeyValueStorageInstance> {
        let namespace = self.scoped_namespace(namespace)?;
        self.inner.get_or_register(&namespace).await
    }

    async fn get_or_register_with_type(
        &self,
        namespace: &str,
        storage_type: KeyValueStorageType,
    ) -> Result<KeyValueStorageInstance> {
        let namespace = self.scoped_namespace(namespace)?;
        self.inner
            .get_or_register_with_type(&namespace, storage_type)
            .await
    }
}

/// Wrap `provider` so that every namespace it mints is confined under `prefix`.
///
/// Use this to grant storage access to less-trusted components (such as
/// individual verifiers) without exposing sibling components' namespaces.
pub fn scoped(provider: Arc<dyn StorageProvider>, prefix: &str) -> Arc<dyn StorageProvider> {
    Arc::new(ScopedStorageProvider {
        inner: provider,
        prefix: prefix.to_string(),
    })
}

/// Reject namespaces that are empty or could escape their intended location
/// (e.g. path traversal in file-backed stores, or breaking out of a scope
/// prefix).
fn validate_namespace(namespace: &str) -> Result<()> {
    let valid = !namespace.is_empty()
        && !namespace.starts_with('/')
        && !namespace.ends_with('/')
        && namespace
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    if !valid {
        return Err(KeyValueStorageError::InvalidNamespace {
            namespace: namespace.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyValueStorageStructConfig, SetParameters};

    fn memory_provider() -> Arc<KvStorageProvider> {
        KvStorageProvider::new(StorageBackendConfig {
            storage_type: KeyValueStorageType::Memory,
            backends: KeyValueStorageStructConfig::default(),
        })
    }

    #[tokio::test]
    async fn get_or_register_is_idempotent() {
        let provider = memory_provider();
        let first = provider.get_or_register("ns").await.unwrap();
        first
            .set("k", b"v", SetParameters::default())
            .await
            .unwrap();

        // A second call returns the same backing instance, so the value persists.
        let second = provider.get_or_register("ns").await.unwrap();
        assert_eq!(second.get("k").await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn scoped_provider_confines_namespace() {
        let provider = memory_provider();
        let verifier = scoped(provider.clone(), "verifier");

        // The scoped handle writes under "verifier/foo" ...
        let scoped_store = verifier.get_or_register("foo").await.unwrap();
        scoped_store
            .set("k", b"v", SetParameters::default())
            .await
            .unwrap();

        // ... which is a different namespace than the unscoped "foo".
        let root_store = provider.get_or_register("foo").await.unwrap();
        assert_eq!(root_store.get("k").await.unwrap(), None);

        let prefixed = provider.get_or_register("verifier/foo").await.unwrap();
        assert_eq!(prefixed.get("k").await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn invalid_namespaces_are_rejected() {
        let provider = memory_provider();
        for bad in ["", "/abs", "trailing/", "a//b", "a/../b", "."] {
            assert!(
                provider.get_or_register(bad).await.is_err(),
                "namespace {bad:?} should be rejected"
            );
        }
    }
}
