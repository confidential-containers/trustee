// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Redis backend for the key-value storage.

use std::{env, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use redis::{cmd, AsyncCommands, ExistenceCheck, SetExpiry, SetOptions};
use serde::Deserialize;
use tracing::instrument;

use crate::{
    is_valid_key, KeyValueStorage, KeyValueStorageError, Result, SetParameters, SetResult,
};

/// Default Redis URL.
const DEFAULT_URL: &str = "redis://127.0.0.1:6379";

/// The environment variable name for the Redis connection URL. When set, it
/// takes precedence over the URL from the configuration file, mirroring the
/// `POSTGRES_URL` behavior of the PostgreSQL backend. This allows the URL
/// (which may embed credentials) to be injected from a secret store instead
/// of being written into a config file.
pub const REDIS_URL_ENV_VAR: &str = "REDIS_URL";

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
        let url = env::var(REDIS_URL_ENV_VAR).unwrap_or(config.url);
        let client = redis::Client::open(url.as_str())
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

/// Redis expiries are whole milliseconds and must be positive, so round up.
/// Redis rejects expiries that overflow when added to the current time; a TTL
/// that large never expires, the same as in the memory backend.
fn ttl_millis(ttl: Duration) -> Option<u64> {
    const MAX_MILLIS: u128 = (i64::MAX / 2) as u128;
    let millis = ttl.as_nanos().div_ceil(1_000_000).max(1);
    (millis <= MAX_MILLIS).then_some(millis as u64)
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

        let mut options = SetOptions::default();
        if !parameters.overwrite {
            options = options.conditional_set(ExistenceCheck::NX);
        }
        if let Some(millis) = parameters.ttl.and_then(ttl_millis) {
            options = options.with_expiration(SetExpiry::PX(millis));
        }

        // A single SET keeps the existence check and the expiry atomic. It
        // replies nil only when NX finds the key already present.
        let reply = connection
            .set_options::<&str, &[u8], Option<String>>(&redis_key, value, options)
            .await
            .map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        match reply {
            Some(_) => Ok(SetResult::Inserted),
            None => Ok(SetResult::AlreadyExists),
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

    fn supports_ttl(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use crate::{
        redis::{ttl_millis, Config, RedisClient},
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
            .set(
                "test",
                b"test",
                SetParameters {
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys = client.list().await.unwrap();
        assert_eq!(keys, vec!["test"]);
        let value = client.get("test").await.unwrap();
        assert_eq!(value, Some(b"test".to_vec()));
        let res = client
            .set(
                "test",
                b"test2",
                SetParameters {
                    overwrite: false,
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(res.unwrap(), SetResult::AlreadyExists);
        let value = client.delete("test").await.unwrap();
        assert_eq!(value, Some(b"test".to_vec()));
    }

    #[ignore]
    #[tokio::test]
    async fn test_redis_ttl() {
        let client = RedisClient::new(Config::default(), "ttl_ns").await.unwrap();
        let with_ttl = |overwrite| SetParameters {
            overwrite,
            ttl: Some(Duration::from_millis(300)),
        };

        assert_eq!(
            client.set("key", b"v1", with_ttl(false)).await.unwrap(),
            SetResult::Inserted
        );
        assert_eq!(
            client.set("key", b"v2", with_ttl(false)).await.unwrap(),
            SetResult::AlreadyExists
        );

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(client.get("key").await.unwrap(), None);
        assert!(client.list().await.unwrap().is_empty());
        assert_eq!(
            client.set("key", b"v3", with_ttl(false)).await.unwrap(),
            SetResult::Inserted
        );

        // An overwrite without a TTL makes the key permanent.
        let no_ttl = SetParameters {
            overwrite: true,
            ttl: None,
        };
        client.set("key", b"v4", no_ttl).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(client.get("key").await.unwrap(), Some(b"v4".to_vec()));
        client.delete("key").await.unwrap();
    }

    #[test]
    fn test_ttl_millis() {
        assert_eq!(ttl_millis(Duration::ZERO), Some(1));
        assert_eq!(ttl_millis(Duration::from_micros(1)), Some(1));
        assert_eq!(ttl_millis(Duration::from_micros(1500)), Some(2));
        assert_eq!(ttl_millis(Duration::from_secs(60)), Some(60_000));
        assert_eq!(ttl_millis(Duration::MAX), None);
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
