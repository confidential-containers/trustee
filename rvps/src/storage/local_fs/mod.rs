// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This Store stores RV information inside a local file

use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;

use crate::ReferenceValue;

use super::ReferenceValueStorage;

/// Local directory path to store the reference values,
/// which is created by sled engine.
const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values";

/// `LocalFs` implements [`ReferenceValueStorage`] trait. And
/// it uses rocksdb inside.
pub struct LocalFs {
    engine: sled::Db,
}

fn default_file_path() -> String {
    FILE_PATH.to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default = "default_file_path")]
    pub file_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_path: default_file_path(),
        }
    }
}

impl LocalFs {
    /// Create a new [`LocalFs`] with given config
    pub fn new(config: Config) -> Result<Self> {
        let engine = sled::open(config.file_path)?;
        Ok(Self { engine })
    }
}

#[async_trait]
impl ReferenceValueStorage for LocalFs {
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
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use crate::{ReferenceValue, ReferenceValueStorage};

    use super::{Config, LocalFs};

    const KEY: &str = "test1";

    /// This test will test the `set` and `get` interface
    /// for [`LocalFs`].
    #[tokio::test]
    #[serial]
    async fn set_and_get() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        let dir_str = temp_dir.path().to_string_lossy().to_string();
        {
            let storage =
                LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
            let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
            assert!(
                storage
                    .set(KEY.to_owned(), rv.clone())
                    .await
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );
            let got = storage
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
            let storage =
                LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
            let rv_old = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("old");

            let rv_new = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("new");

            assert!(
                storage
                    .set(KEY.to_owned(), rv_old.clone())
                    .await
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );

            let got = storage
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
            let storage = LocalFs::new(Config {
                file_path: dir_str.clone(),
            })
            .expect("create local fs store failed.");
            storage
                .set(KEY.to_owned(), rv.clone())
                .await
                .expect("set rv failed.");
        }
        {
            let storage =
                LocalFs::new(Config { file_path: dir_str }).expect("create local fs store failed.");
            let got = storage
                .get(KEY)
                .await
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }
}
