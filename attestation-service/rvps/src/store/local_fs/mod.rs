// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This Store stores RV information inside a local file

use std::path::Path;

use anyhow::*;

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

impl Default for LocalFs {
    /// Create a `LocalFs` storage, which will use path [`FILE_PATH`]
    /// to store files.
    fn default() -> Self {
        let path = Path::new(FILE_PATH);
        LocalFs::new(path).expect("Failed to create LocalFs Store.")
    }
}

impl LocalFs {
    /// Create a new [`LocalFs`] with given
    /// file storage path.
    fn new(path: &Path) -> Result<Self> {
        let engine = sled::open(path)?;
        Ok(Self { engine })
    }
}

impl Store for LocalFs {
    fn set(&mut self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
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

    fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
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

    use crate::{ReferenceValue, Store};

    use super::LocalFs;

    const KEY: &str = "test1";

    /// This test will test the `set` and `get` interface
    /// for [`LocalFs`].
    #[test]
    #[serial]
    fn set_and_get() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        {
            let mut store = LocalFs::new(temp_dir.path()).expect("create local fs store failed.");
            let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
            assert!(
                store
                    .set(KEY.to_owned(), rv.clone())
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );
            let got = store
                .get(KEY)
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }

    /// This test will test the `set` interface with the
    /// duplicated key for [`LocalFs`].
    #[test]
    #[serial]
    fn set_duplicated() {
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        {
            let mut store = LocalFs::new(temp_dir.path()).expect("create local fs store failed.");
            let rv_old = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("old");

            let rv_new = ReferenceValue::new()
                .expect("create ReferenceValue failed.")
                .set_name("new");

            assert!(
                store
                    .set(KEY.to_owned(), rv_old.clone())
                    .expect("set rv failed.")
                    .is_none(),
                "the storage has previous key of {}",
                KEY
            );

            let got = store
                .set(KEY.to_owned(), rv_new)
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");

            assert_eq!(got, rv_old);
        }
    }

    /// This test will simulate a restart operation
    /// for [`LocalFs`].
    #[test]
    #[serial]
    fn restart() {
        let rv = ReferenceValue::new().expect("create ReferenceValue failed.");
        let temp_dir = tempfile::tempdir().expect("create tempdir failed");
        {
            let mut store = LocalFs::new(temp_dir.path()).expect("create local fs store failed.");
            store
                .set(KEY.to_owned(), rv.clone())
                .expect("set rv failed.");
        }
        {
            let store =
                LocalFs::new(temp_dir.path()).expect("read previous local fs store failed.");
            let got = store
                .get(KEY)
                .expect("get rv failed.")
                .expect("get None from LocalFs Store");
            assert_eq!(got, rv);
        }
    }
}
