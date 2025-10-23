// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{KeyValueStorage, Result, SetParameters};
use std::collections::HashMap;
use tracing::instrument;

#[derive(Default)]
pub struct SimpleKeyValueStorage {
    items: RwLock<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl KeyValueStorage for SimpleKeyValueStorage {
    #[instrument(skip_all, name = "SimpleKeyValueStorage::set")]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<()> {
        if parameters.overwrite {
            self.items
                .write()
                .await
                .insert(key.to_string(), value.to_vec());
        } else {
            if self.items.read().await.contains_key(key) {
                return Ok(());
            }
            self.items
                .write()
                .await
                .insert(key.to_string(), value.to_vec());
        }
        Ok(())
    }

    #[instrument(skip_all, name = "SimpleKeyValueStorage::list")]
    async fn list(&self) -> Result<Vec<String>> {
        let keys = self
            .items
            .read()
            .await
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        Ok(keys)
    }

    #[instrument(skip_all, name = "SimpleKeyValueStorage::get")]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let res = self.items.read().await.get(key).cloned();
        Ok(res)
    }

    #[instrument(skip_all, name = "SimpleKeyValueStorage::delete")]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let res = self.items.write().await.remove(key);
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_key_value_storage() {
        let storage = SimpleKeyValueStorage::default();
        let parameters = SetParameters::default();
        storage.set("test", b"test", parameters).await.unwrap();
        let keys = storage.list().await.unwrap();
        assert_eq!(keys, vec!["test"]);
        let res = storage.delete("test").await.unwrap();
        assert_eq!(res, Some(b"test".to_vec()));
        let keys = storage.list().await.unwrap();
        assert_eq!(keys, Vec::<String>::new());
    }
}
