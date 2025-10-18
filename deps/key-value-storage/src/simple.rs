// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{KeyValueStorage, KeyValueStorageError, Result};
use std::collections::HashMap;
use tracing::instrument;

#[derive(Default)]
pub struct SimpleKeyValueStorage {
    items: RwLock<HashMap<String, String>>,
}

#[async_trait]
impl KeyValueStorage for SimpleKeyValueStorage {
    #[instrument(skip_all, name = "SimpleKeyValueStorage::set_key")]
    async fn set_key(&self, key: String, value: String, overwrite: bool) -> Result<()> {
        if overwrite {
            self.items.write().await.insert(key, value);
        } else {
            if self.items.read().await.contains_key(&key) {
                return Ok(());
            }
            self.items.write().await.insert(key, value);
        }
        Ok(())
    }

    #[instrument(skip_all, name = "SimpleKeyValueStorage::list_keys")]
    async fn list_keys(&self) -> Result<Vec<String>> {
        let keys = self
            .items
            .read()
            .await
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        Ok(keys)
    }

    #[instrument(skip_all, name = "SimpleKeyValueStorage::get_key")]
    async fn get_key(&self, key: String) -> Result<String> {
        Ok(self
            .items
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or(KeyValueStorageError::KeyNotFound { key })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_key_value_storage() {
        let storage = SimpleKeyValueStorage::default();
        storage
            .set_key("test".to_string(), "test".to_string(), false)
            .await
            .unwrap();
        let key = storage.get_key("test".to_string()).await.unwrap();
        assert_eq!(key, "test");
        let keys = storage.list_keys().await.unwrap();
        assert_eq!(keys, vec!["test"]);
    }
}
