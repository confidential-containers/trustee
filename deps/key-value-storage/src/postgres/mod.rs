// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL backend for the key-value storage.

use std::env;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use educe::Educe;
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::{postgres::PgPoolOptions, query, Row};
use tracing::{debug, info, instrument};

use crate::{is_valid_key, KeyValueStorage, KeyValueStorageError, Result, SetParameters};

/// The maximum number of connections to the PostgreSQL database.
pub const MAX_CONNECTIONS: u32 = 5;

/// The name of the key column.
pub const KEY_COLUMN: &str = "key";

/// The name of the value column.
pub const VALUE_COLUMN: &str = "value";

/// The environment variable name for the PostgreSQL URL.
pub const POSTGRES_URL_ENV_VAR: &str = "POSTGRES_URL";

#[derive(Deserialize, Educe, Clone, PartialEq)]
#[educe(Debug)]
#[serde(default)]
pub struct Config {
    /// The name of the PostgreSQL database.
    pub db: String,

    /// The username of the PostgreSQL database.
    pub username: String,

    /// The password of the PostgreSQL database.
    #[educe(Debug(ignore))]
    pub password: Option<String>,

    /// The port of the PostgreSQL database.
    pub port: u16,

    /// The host of the PostgreSQL database.
    pub host: String,

    /// The name of the policy table.
    pub table: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: "postgres".to_string(),
            username: "postgres".to_string(),
            password: None,
            port: 5432,
            host: "localhost".to_string(),
            table: "key_value".to_string(),
        }
    }
}

pub struct PostgresClient {
    pool: Arc<PgPool>,
    table: String,
}

impl PostgresClient {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing PostgreSQL client");
        debug!("Connecting to PostgreSQL DB: {config:?}");
        let url = env::var(POSTGRES_URL_ENV_VAR).unwrap_or(format!(
            "postgresql://{}@{}:{}/{}",
            config
                .password
                .map(|password| format!(":{password}"))
                .unwrap_or(config.username.to_string()),
            config.host,
            config.port,
            config.db
        ));
        let url = pg_connection_string::ConnectionString::from_str(&url)
            .map_err(|e| KeyValueStorageError::InitializeBackendFailed {
                source: anyhow!("failed to parse PostgreSQL connection string: {e}"),
            })?
            .to_string();
        info!("Connecting to PostgreSQL DB: {url}");

        let pool = PgPoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
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
}

pub struct PolicyItem {
    pub key: String,
    pub value: String,
}

#[async_trait]
impl KeyValueStorage for PostgresClient {
    #[instrument(skip_all, name = "PostgresClient::set")]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<()> {
        if !is_valid_key(key) {
            return Err(KeyValueStorageError::SetKeyFailed {
                source: anyhow::anyhow!("key contains invalid characters"),
                key: key.to_string(),
            });
        }

        if parameters.overwrite {
            let sql = format!(
                "INSERT INTO {} ({KEY_COLUMN}, {VALUE_COLUMN}) VALUES ( $1, $2 ) ON CONFLICT ({KEY_COLUMN}) DO UPDATE SET {VALUE_COLUMN} = $2",
                self.table
            );
            let _ = query(&sql)
                .bind(key)
                .bind(value)
                .execute(&*self.pool)
                .await
                .map_err(|e| KeyValueStorageError::SetKeyFailed {
                    source: e.into(),
                    key: key.to_string(),
                })?;
        } else {
            let sql = format!(
                "INSERT INTO {} ({KEY_COLUMN}, {VALUE_COLUMN}) VALUES ( $1, $2 ) ON CONFLICT ({KEY_COLUMN}) DO NOTHING RETURNING *",
                self.table
            );
            let result = query(&sql)
                .bind(key)
                .bind(value)
                .fetch_optional(&*self.pool)
                .await
                .map_err(|e| KeyValueStorageError::SetKeyFailed {
                    source: e.into(),
                    key: key.to_string(),
                })?;
            if result.is_none() {
                return Err(KeyValueStorageError::SetKeyFailed {
                    source: anyhow::anyhow!("key already exists"),
                    key: key.to_string(),
                });
            }
        }

        Ok(())
    }

    #[instrument(skip_all, name = "PostgresClient::list")]
    async fn list(&self) -> Result<Vec<String>> {
        let sql = format!("SELECT ({KEY_COLUMN}) FROM {}", self.table);
        let keys = sqlx::query_scalar::<_, String>(&sql)
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::ListKeysFailed { source: e.into() })?;
        Ok(keys)
    }

    #[instrument(skip_all, name = "PostgresClient::set")]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let sql = format!(
            "SELECT ({VALUE_COLUMN}) FROM {} WHERE {KEY_COLUMN} = $1",
            self.table
        );
        let value = query(&sql)
            .bind(key)
            .fetch_one(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;

        if value.is_empty() {
            return Ok(None);
        }

        let value: Vec<u8> = value
            .try_get(VALUE_COLUMN)
            .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
        Ok(Some(value))
    }

    #[instrument(skip_all, name = "PostgresClient::delete")]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let sql = format!(
            "DELETE FROM {} WHERE {KEY_COLUMN} = $1 RETURNING {VALUE_COLUMN}",
            self.table
        );
        let row = query(&sql)
            .bind(key)
            .fetch_optional(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::DeleteKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;

        if let Some(row) = row {
            let value: Vec<u8> = row
                .try_get("value")
                .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
            return Ok(Some(value));
        }

        Ok(None)
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
        assert!(res.is_err());
        let value = client.delete("test").await.unwrap();
        assert_eq!(value, Some(b"test".to_vec()));
        let keys = client.list().await.unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_config_parsing() {
        let config = r#"
db = "db1"
username = "username"
        "#;
        let config: Config = toml::from_str(config).unwrap();
        assert_eq!(config.db, "db1");
        assert_eq!(config.username, "username");
        assert_eq!(config.password, None);
        assert_eq!(config.port, 5432);
        assert_eq!(config.host, "localhost");
        assert_eq!(config.table, "key_value");
    }
}
