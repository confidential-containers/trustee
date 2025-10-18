// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL backend for the key-value storage.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::Engine;
use derivative::Derivative;
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::{postgres::PgPoolOptions, query, Row};
use tracing::{debug, info, instrument};

use crate::{KeyValueStorage, KeyValueStorageError, Result};

#[derive(Deserialize, Derivative, Clone, PartialEq)]
#[derivative(Debug)]
pub struct Config {
    /// The name of the PostgreSQL database.
    #[serde(default = "default_db")]
    pub db: String,

    /// The username of the PostgreSQL database.
    #[serde(default = "default_username")]
    pub username: String,

    /// The password of the PostgreSQL database.
    #[derivative(Debug = "ignore")]
    #[serde(default)]
    pub password: Option<String>,

    /// The port of the PostgreSQL database.
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_host")]
    pub host: String,

    /// The name of the policy table.
    #[serde(default = "default_table")]
    pub table: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: default_db(),
            username: default_username(),
            password: None,
            port: default_port(),
            host: default_host(),
            table: default_table(),
        }
    }
}

fn default_db() -> String {
    "postgres".to_string()
}

fn default_username() -> String {
    "postgres".to_string()
}

fn default_host() -> String {
    "localhost".to_string()
}

fn default_port() -> u16 {
    5432
}

fn default_table() -> String {
    "key_value".to_string()
}

pub struct PostgresClient {
    pool: Arc<PgPool>,
    table: String,
}

impl PostgresClient {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing PostgreSQL client");
        debug!("Connecting to PostgreSQL DB: {config:?}");
        let auth_part = config
            .password
            .map(|password| format!("{}:{password}@", config.username))
            .unwrap_or(format!("{}@", config.username));

        let url = format!(
            "postgres://{}{}:{}/{}",
            auth_part, config.host, config.port, config.db
        );

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .context("failed to connect to PostgreSQL DB")
            .map_err(|e| KeyValueStorageError::InitializeBackendFailed {
                source: anyhow!("failed to connect to PostgreSQL DB: {e}"),
            })?;

        Ok(Self {
            pool: Arc::new(pool),
            table: config.table,
        })
    }

    /// Check if the key is valid.
    ///
    /// The key is valid if it only contains ASCII alphanumeric characters, `-` or `_`.
    /// No spaces and other special characters are allowed to prevent SQL injection.
    fn is_valid_key(key: &str) -> bool {
        key.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }
}

pub struct PolicyItem {
    pub key: String,
    pub value: String,
}

#[async_trait]
impl KeyValueStorage for PostgresClient {
    #[instrument(skip_all, name = "PostgresClient::set_key")]
    async fn set_key(&self, key: String, value: String, overwrite: bool) -> Result<()> {
        if !Self::is_valid_key(&key) {
            return Err(KeyValueStorageError::SetKeyFailed {
                source: anyhow::anyhow!("key contains invalid characters"),
                key,
            });
        }

        // we do the base64 encoding here to avoid SQL injection.
        let value_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());

        let sql = match overwrite {
            true => format!(
                "
INSERT INTO {} (key, value) 
VALUES ( $1, $2 ) 
ON CONFLICT (key) DO UPDATE SET value = $2",
                self.table
            ),
            false => format!(
                "
INSERT INTO {} (key, value) 
VALUES ( $1, $2 )",
                self.table
            ),
        };
        let _ = query(&sql)
            .bind(&key)
            .bind(&value_b64)
            .execute(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key,
            })?;

        Ok(())
    }

    #[instrument(skip_all, name = "PostgresClient::list_keys")]
    async fn list_keys(&self) -> Result<Vec<String>> {
        let sql = format!("SELECT (key) FROM {}", self.table);
        let rec = query(&sql)
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::ListKeysFailed { source: e.into() })?;
        let mut keys = Vec::new();
        for rec in &rec {
            let key: String = rec.get("key");
            keys.push(key);
        }
        Ok(keys)
    }

    #[instrument(skip_all, name = "PostgresClient::get_key")]
    async fn get_key(&self, key: String) -> Result<String> {
        let sql = format!("SELECT (value) FROM {} WHERE key = $1", self.table);
        let value = query(&sql)
            .bind(&key)
            .fetch_one(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.clone(),
            })?;

        if value.is_empty() {
            return Err(KeyValueStorageError::KeyNotFound { key });
        }

        let b64_value: String = value.get("value");
        let policy = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64_value)
            .map_err(|_| KeyValueStorageError::MalformedValue {
                source: anyhow!("failed to decode value with base64 URL_SAFE_NO_PAD"),
            })?;
        let value =
            String::from_utf8(policy).map_err(|_| KeyValueStorageError::MalformedValue {
                source: anyhow!("The value is not a valid UTF-8 string"),
            })?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_postgres_client() {
        let config = Config {
            db: "postgres".to_string(),
            host: "localhost".to_string(),
            port: 6432,
            username: "postgres".to_string(),
            password: None,
            table: "key_value".to_string(),
        };
        let client = PostgresClient::new(config).await.unwrap();
        client
            .set_key("test".to_string(), "test".to_string(), true)
            .await
            .unwrap();
        let value = client.get_key("test".to_string()).await.unwrap();
        assert_eq!(value, "test");
    }
}
