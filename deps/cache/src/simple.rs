// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//
//

use super::Cache;

use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct SimpleCache {
    cache: RwLock<HashMap<String, String>>,
}

impl Default for SimpleCache {
    fn default() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl Cache for SimpleCache {
    async fn get(&self, key: String) -> Option<String> {
        self.cache.read().await.get(&key).cloned()
    }

    async fn set(&self, key: String, value: String) -> Result<()> {
        let _ = self.cache.write().await.insert(key, value);
        Ok(())
    }
}
