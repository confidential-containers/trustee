// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL backend for the key-value storage.

use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use educe::Educe;
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::{Row, postgres::PgPoolOptions, query};
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

use crate::{
    KeyValueStorage, KeyValueStorageError, Result, SetParameters, SetResult, is_valid_key,
};

/// The maximum number of connections to the PostgreSQL database.
pub const MAX_CONNECTIONS: u32 = 5;

/// The name of the key column.
pub const KEY_COLUMN: &str = "key";

/// The name of the value column.
pub const VALUE_COLUMN: &str = "value";

/// The name of the expiry column, which every table must have. `NULL` means
/// the row never expires.
pub const EXPIRES_AT_COLUMN: &str = "expires_at";

/// SQL condition that holds for rows that have not expired.
const LIVE_CONDITION: &str = "(expires_at IS NULL OR expires_at > now())";

/// How often a write also deletes expired rows.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// TTLs above this (100,000 years) never expire; far larger ones overflow
/// PostgreSQL's timestamp range.
const MAX_TTL_MILLIS: u128 = 100_000 * 365 * 24 * 3600 * 1000;

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: "postgres".to_string(),
            username: "postgres".to_string(),
            password: None,
            port: 5432,
            host: "localhost".to_string(),
        }
    }
}

pub struct PostgresClient {
    pool: Arc<PgPool>,
    table: String,
    last_purge: Mutex<Option<Instant>>,
}

impl PostgresClient {
    pub async fn new(config: Config, namespace: &str) -> Result<Self> {
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
            table: namespace.to_string(),
            last_purge: Mutex::new(None),
        })
    }

    /// Deletes expired rows, at most once per `PURGE_INTERVAL`. Failures are
    /// only logged: reads already ignore expired rows.
    async fn maybe_purge_expired(&self) {
        {
            let mut last_purge = self.last_purge.lock().unwrap_or_else(|e| e.into_inner());
            if last_purge.is_some_and(|at| at.elapsed() < PURGE_INTERVAL) {
                return;
            }
            *last_purge = Some(Instant::now());
        }
        let sql = format!(
            "DELETE FROM {} WHERE {EXPIRES_AT_COLUMN} <= now()",
            self.table
        );
        if let Err(e) = query(&sql).execute(&*self.pool).await {
            warn!(table = self.table, error = %e, "failed to delete expired rows");
        }
    }
}

pub struct PolicyItem {
    pub key: String,
    pub value: String,
}

#[async_trait]
impl KeyValueStorage for PostgresClient {
    #[instrument(skip_all, name = "PostgresClient::set")]
    async fn set(&self, key: &str, value: &[u8], parameters: SetParameters) -> Result<SetResult> {
        if !is_valid_key(key) {
            return Err(KeyValueStorageError::SetKeyFailed {
                source: anyhow::anyhow!("key contains invalid characters"),
                key: key.to_string(),
            });
        }

        // NULL means the row never expires. The deadline is computed by the
        // database so that every KBS replica agrees on it.
        let ttl_millis = parameters.ttl.and_then(|ttl| {
            let millis = ttl.as_nanos().div_ceil(1_000_000);
            if millis > MAX_TTL_MILLIS {
                warn!(
                    ?ttl,
                    "TTL too large to represent, the entry will never expire"
                );
                return None;
            }
            Some(millis as f64)
        });
        let table = &self.table;
        let mut sql = format!(
            "INSERT INTO {table} ({KEY_COLUMN}, {VALUE_COLUMN}, {EXPIRES_AT_COLUMN}) \
             VALUES ($1, $2, now() + $3::float8 * interval '1 millisecond') \
             ON CONFLICT ({KEY_COLUMN}) DO UPDATE SET \
             {VALUE_COLUMN} = EXCLUDED.{VALUE_COLUMN}, \
             {EXPIRES_AT_COLUMN} = EXCLUDED.{EXPIRES_AT_COLUMN}"
        );
        if !parameters.overwrite {
            // Without overwrite, only an expired row may be replaced.
            sql.push_str(&format!(" WHERE {table}.{EXPIRES_AT_COLUMN} <= now()"));
        }
        sql.push_str(&format!(" RETURNING {KEY_COLUMN}"));

        let inserted = query(&sql)
            .bind(key)
            .bind(value)
            .bind(ttl_millis)
            .fetch_optional(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::SetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;
        self.maybe_purge_expired().await;

        Ok(match inserted {
            Some(_) => SetResult::Inserted,
            None => SetResult::AlreadyExists,
        })
    }

    #[instrument(skip_all, name = "PostgresClient::list")]
    async fn list(&self) -> Result<Vec<String>> {
        let sql = format!(
            "SELECT ({KEY_COLUMN}) FROM {} WHERE {LIVE_CONDITION}",
            self.table
        );
        let keys = sqlx::query_scalar::<_, String>(&sql)
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::ListKeysFailed { source: e.into() })?;
        Ok(keys)
    }

    #[instrument(skip_all, name = "PostgresClient::set")]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let sql = format!(
            "SELECT ({VALUE_COLUMN}) FROM {} WHERE {KEY_COLUMN} = $1 AND {LIVE_CONDITION}",
            self.table
        );
        let value = query(&sql)
            .bind(key)
            .fetch_optional(&*self.pool)
            .await
            .map_err(|e| KeyValueStorageError::GetKeyFailed {
                source: e.into(),
                key: key.to_string(),
            })?;

        let Some(value) = value else {
            return Ok(None);
        };

        let value: Vec<u8> = value
            .try_get(VALUE_COLUMN)
            .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
        Ok(Some(value))
    }

    #[instrument(skip_all, name = "PostgresClient::delete")]
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // An expired row is deleted too, but reported as absent.
        let sql = format!(
            "DELETE FROM {} WHERE {KEY_COLUMN} = $1 RETURNING {VALUE_COLUMN}, {LIVE_CONDITION} AS live",
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
            let live: bool = row
                .try_get("live")
                .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
            if !live {
                return Ok(None);
            }
            let value: Vec<u8> = row
                .try_get("value")
                .map_err(|e| KeyValueStorageError::MalformedValue { source: e.into() })?;
            return Ok(Some(value));
        }

        Ok(None)
    }

    fn supports_ttl(&self) -> bool {
        true
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
        };
        let client = PostgresClient::new(config, "key_value").await.unwrap();
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
        let res = res.unwrap();
        assert_eq!(res, SetResult::AlreadyExists);
        let value = client.delete("test").await.unwrap();
        assert_eq!(value, Some(b"test".to_vec()));
        let keys = client.list().await.unwrap();
        assert!(keys.is_empty());
        let value = client.get("test").await.unwrap();
        assert_eq!(value, None);
    }

    fn test_config() -> Config {
        Config {
            db: "postgres".to_string(),
            host: "localhost".to_string(),
            port: 6432,
            username: "postgres".to_string(),
            password: None,
        }
    }

    /// Recreates `table` with the key, value and expiry columns.
    async fn create_table(table: &str) {
        let pool = PgPool::connect("postgresql://postgres@localhost:6432/postgres")
            .await
            .unwrap();
        query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(&pool)
            .await
            .unwrap();
        query(&format!(
            "CREATE TABLE {table} (value BYTEA, key TEXT PRIMARY KEY, expires_at TIMESTAMPTZ)"
        ))
        .execute(&pool)
        .await
        .unwrap();
    }

    fn with_ttl(overwrite: bool, ttl: Duration) -> SetParameters {
        SetParameters {
            overwrite,
            ttl: Some(ttl),
        }
    }

    const HOUR: Duration = Duration::from_secs(3600);

    #[ignore]
    #[tokio::test]
    async fn test_postgres_ttl() {
        create_table("ttl_test").await;
        let client = PostgresClient::new(test_config(), "ttl_test")
            .await
            .unwrap();
        assert!(client.supports_ttl());

        // The first write runs the purge; later ones skip it for a minute, so
        // the expired row stays in the table for the checks below.
        client
            .set("live", b"v", with_ttl(true, HOUR))
            .await
            .unwrap();
        client
            .set("gone", b"v", with_ttl(true, Duration::ZERO))
            .await
            .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM ttl_test WHERE key = 'gone'")
            .fetch_one(&*client.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(client.get("gone").await.unwrap(), None);
        assert_eq!(client.list().await.unwrap(), vec!["live"]);

        // Without overwrite: refused on a live row, allowed on an expired one.
        let res = client.set("live", b"v2", with_ttl(false, HOUR)).await;
        assert_eq!(res.unwrap(), SetResult::AlreadyExists);
        let res = client.set("gone", b"v2", with_ttl(false, HOUR)).await;
        assert_eq!(res.unwrap(), SetResult::Inserted);
        assert_eq!(client.get("gone").await.unwrap(), Some(b"v2".to_vec()));

        // A row without expiry is never replaced without overwrite.
        client
            .set("forever", b"v", SetParameters::default())
            .await
            .unwrap();
        let res = client.set("forever", b"v2", with_ttl(false, HOUR)).await;
        assert_eq!(res.unwrap(), SetResult::AlreadyExists);

        // An overwrite without a TTL, or with one too large to store, never
        // expires.
        let no_ttl = SetParameters {
            overwrite: true,
            ttl: None,
        };
        client.set("live", b"v3", no_ttl).await.unwrap();
        client
            .set("huge", b"v", with_ttl(true, Duration::MAX))
            .await
            .unwrap();
        let never: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ttl_test WHERE key IN ('live', 'huge') AND expires_at IS NULL",
        )
        .fetch_one(&*client.pool)
        .await
        .unwrap();
        assert_eq!(never, 2);

        client
            .set("expired", b"v", with_ttl(true, Duration::ZERO))
            .await
            .unwrap();
        assert_eq!(client.delete("expired").await.unwrap(), None);
        assert_eq!(client.delete("gone").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[ignore]
    #[tokio::test]
    async fn test_postgres_write_purges_expired_rows() {
        create_table("purge_test").await;
        let client = PostgresClient::new(test_config(), "purge_test")
            .await
            .unwrap();
        client
            .set("gone", b"v", with_ttl(true, Duration::ZERO))
            .await
            .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM purge_test")
            .fetch_one(&*client.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
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
    }
}
