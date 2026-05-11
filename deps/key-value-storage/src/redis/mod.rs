// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Redis backend for the key-value storage.

use anyhow::anyhow;
use async_trait::async_trait;
use redis::{cmd, AsyncCommands};
use serde::Deserialize;
use tracing::instrument;

use crate::{
    is_valid_key, KeyValueStorage, KeyValueStorageError, Result, SetParameters, SetResult,
};

/// Default Redis URL.
const DEFAULT_URL: &str = "redis://127.0.0.1:6379";

#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct Config {
    /// The Redis connection URL.
    pub url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: DEFAULT_URL.to_string(),
        }
    }
}

pub struct RedisClient {
    client: redis::Client,
    namespace: String,
}

impl RedisClient {
    pub async fn new(config: Config, namespace: &str) -> Result<Self> {
        let client = redis::Client::open(config.url.as_str())
            .map_err(|e| KeyValueStorageError::InitializeBackendFailed { source: e.into() })?;

        Ok(Self {
            client,
            namespace: namespace.to_string(),
        })
    }

    /// Redis combines the namespace with the key to form a unique key.
    fn namespaced_key(&self, key: &str) -> String {
        format!("{}:{key}", self.namespace)
    }
}

#[async_trait]
impl KeyValueStorage for RedisClient {
    #[instrument(skip_all, name = "RedisClient::set", fields(key = key))]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult> {
        if !is_valid_key(key) {
            return Err(KeyValueStorageError::SetKeyFailed {
                source: anyhow!("key contains invalid characters"),
                key: key.to_string(),
            });
        }

        let redis_key = self.namespaced_key(key);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;

        if parameters.overwrite {
            connection
                .set::<&str, &[u8], ()>(&redis_key, value)
                .await
                .map_err(|e| KeyValueStorageError::SetKeyFailed {
                    source: e.into(),
                    key: key.to_string(),
                })?;
            return Ok(SetResult::Inserted);
        }

        let inserted = connection
            .set_nx::<&str, &[u8], bool>(&redis_key, value)
            .await
            .map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        if inserted {
            Ok(SetResult::Inserted)
        } else {
            Ok(SetResult::AlreadyExists)
        }
    }

    #[instrument(skip_all, name = "RedisClient::list")]
    async fn list(&self) -> Result<Vec<String>> {
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| KeyValueStorageError::ListKeysFailed { source: e.into() })?;
        let pattern = format!("{}:*", self.namespace);

        let keys: Vec<String> = connection
            .keys(pattern)
            .await
            .map_err(|e| KeyValueStorageError::ListKeysFailed { source: e.into() })?;

        let prefix = format!("{}:", self.namespace);
        Ok(keys
            .into_iter()
            .map(|key| key.strip_prefix(&prefix).unwrap_or(&key).into())
            .collect())
    }

    #[instrument(skip_all, name = "RedisClient::get", fields(key = key))]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let redis_key = self.namespaced_key(key);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        let value = connection
            .get::<&str, Option<Vec<u8>>>(&redis_key)
            .await
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        Ok(value)
    }

    #[instrument(skip_all, name = "RedisClient::delete", fields(key = key))]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let redis_key = self.namespaced_key(key);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;

        // Use Redis GETDEL for atomic read-and-delete to avoid race conditions.
        cmd("GETDEL")
            .arg(&redis_key)
            .query_async(&mut connection)
            .await
            .map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        redis::{Config, RedisClient},
        KeyValueStorage, SetParameters, SetResult,
    };

    #[ignore]
    #[tokio::test]
    async fn test_redis_client() {
        let client = RedisClient::new(Config::default(), "key_value")
            .await
            .unwrap();

        let value = client.get("test").await.unwrap();
        assert_eq!(value, None);
        client
            .set("test", b"test", SetParameters { overwrite: true })
            .await
            .unwrap();
        let keys = client.list().await.unwrap();
        assert_eq!(keys, vec!["test"]);
        let value = client.get("test").await.unwrap();
        assert_eq!(value, Some(b"test".to_vec()));
        let res = client
            .set("test", b"test2", SetParameters { overwrite: false })
            .await;
        assert_eq!(res.unwrap(), SetResult::AlreadyExists);
        let value = client.delete("test").await.unwrap();
        assert_eq!(value, Some(b"test".to_vec()));
    }

    #[test]
    fn test_config_parsing() {
        let config = r#"
url = "redis://127.0.0.1:6379"
        "#;
        let config: Config = toml::from_str(config).unwrap();
        assert_eq!(config.url, "redis://127.0.0.1:6379");
    }
}
