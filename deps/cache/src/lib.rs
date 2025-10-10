// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//
//

pub mod simple;

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// A cache allows any component in the Attestation Service
/// to store and retrieve values.
///
/// A cache has String keys and String values.
/// The caller should namespace the keys to avoid collisions.
/// The caller should marshal values to/from String as needed.
#[async_trait::async_trait]
pub trait Cache {
    /// Get a value from the cache
    async fn get(&self, key: String) -> Option<String>;

    /// Set a value in the cache. This can be called
    /// after trying to get a value or it can be called
    /// during setup to provision values from a config
    /// into the cache.
    /// Cache implementations should use internal mutability.
    async fn set(&self, key: String, value: String) -> Result<()>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub enum CacheType {
    Simple,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct CacheConfig {
    pub r#type: CacheType,

    /// Any key, value pairs that should be added to the cache on startup.
    /// This can be used to pre-provision values in offline environments.
    /// For persistent cache backends, the behavior of the initial_values
    /// is determined by the implementation.
    pub initial_values: Option<HashMap<String, String>>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            r#type: CacheType::Simple,
            initial_values: None,
        }
    }
}

impl CacheConfig {
    pub async fn to_cache(&self) -> Result<Arc<dyn Cache + Send + Sync>> {
        let cache = match self.r#type {
            CacheType::Simple => simple::SimpleCache::default(),
        };

        if let Some(iv) = &self.initial_values {
            for (key, value) in iv {
                // If any duplicate keys are present, only one will be added
                // to the cache.
                let _ = cache.set(key.to_string(), value.to_string()).await;
            }
        }

        Ok(Arc::new(cache) as Arc<dyn Cache + Send + Sync>)
    }
}
