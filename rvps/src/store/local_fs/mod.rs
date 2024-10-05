// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This Store stores RV information inside a local file

use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::ReferenceValue;

use super::Store;

/// Local directory path to store the reference values,
/// which is created by sled engine.
const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values";

/// `LocalFs` implements [`Store`] trait. And
/// it uses rocksdb inside.
pub struct LocalFs {
    engine: sled::Db,
}

fn default_file_path() -> String {
    FILE_PATH.to_string()
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default = "default_file_path")]
    file_path: String,
}

impl LocalFs {
    /// Create a new [`LocalFs`] with given config
    pub fn new(config: Value) -> Result<Self> {
        let config: Config = serde_json::from_value(config)?;
        let engine = sled::open(config.file_path)?;
        Ok(Self { engine })
    }
}

#[async_trait]
impl Store for LocalFs {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let rv_serde = serde_json::to_vec(&rv)?;
        let res = match self
            .engine
            .insert(name, rv_serde)
            .context("insert into sled")?
        {
            Some(v) => {
                let v = serde_json::from_slice(&v)?;
                Ok(Some(v))
            }
            None => Ok(None),
        };

        self.engine.flush()?;
        res
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        match self.engine.get(name).context("read from sled")? {
            Some(v) => {
                let v = serde_json::from_slice(&v)?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let mut values = Vec::new();

        for (_k, v) in self.engine.iter().flatten() {
            values.push(serde_json::from_slice(&v)?);
        }

        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use serial_test::serial;

    use crate::{ReferenceValue, Store};

    use super::LocalFs;

    const KEY: &str = "test1";

    /// This test will test the `set` and `get` interface
    /// for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn set_and_get() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let store = LocalFs::new(json!({
                "file_path": dir_str
            }))
            .expect("create local fs store failed.");
            let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
            assert!(
                store
                    .set(KEY.to_owned(), rv.clone())
                    .await
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );
            let got = store
                .get(KEY)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }

    /// This test will test the `set` interface with the
    /// duplicated key for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn set_duplicated() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let store = LocalFs::new(json!({
                "file_path": dir_str
            }))
            .expect("create local fs store failed.");
            let rv_old = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("old");

            let rv_new = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("new");

            assert!(
                store
                    .set(KEY.to_owned(), rv_old.clone())
                    .await
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );

            let got = store
                .set(KEY.to_owned(), rv_new)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");

            assert_eq!(got, rv_old);
        }
    }

    /// This test will simulate a restart operation
    /// for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn restart() {
        let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let store = LocalFs::new(json!({
                "file_path": dir_str
            }))
            .expect("create local fs store failed.");
            store
                .set(KEY.to_owned(), rv.clone())
                .await
                .expect("set rv failed.");
        }
        {
            let store = LocalFs::new(json!({
                "file_path": dir_str
            }))
            .expect("create local fs store failed.");
            let got = store
                .get(KEY)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }
}
