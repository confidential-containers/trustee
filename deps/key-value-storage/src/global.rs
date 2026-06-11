// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{KeyValueStorage, KeyValueStorageError, Result};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use tokio::sync::RwLock;

pub type KeyValueStorageInstance = Arc<dyn KeyValueStorage>;

struct RegistryInner {
    storages: RwLock<HashMap<String, KeyValueStorageInstance>>,
}

static REGISTRY: OnceLock<RegistryInner> = OnceLock::new();

pub async fn register_namespace(namespace: &str, storage: KeyValueStorageInstance) -> Result<()> {
    let registry = REGISTRY.get_or_init(|| RegistryInner {
        storages: RwLock::new(HashMap::new()),
    });
    let mut storages = registry.storages.write().await;
    if storages.contains_key(namespace) {
        return Err(KeyValueStorageError::StorageRegistryAlreadyInitialized);
    }
    storages.insert(namespace.to_string(), storage);
    Ok(())
}

pub async fn get_namespace(namespace: &str) -> Result<KeyValueStorageInstance> {
    let registry = REGISTRY
        .get()
        .ok_or(KeyValueStorageError::StorageRegistryNotInitialized)?;
    let storages = registry.storages.read().await;
    let storage = storages.get(namespace).cloned().ok_or_else(|| {
        KeyValueStorageError::UninitializedStorageNamespace {
            namespace: namespace.to_string(),
        }
    })?;
    Ok(storage)
}
