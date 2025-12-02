// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{ResourceDesc, StorageBackend};
use anyhow::{bail, Result};
use key_value_storage::{KeyValueStorage, KeyValueStorageInstance, SetParameters};
use std::sync::Arc;

pub struct KvStorage {
    pub storage: Arc<dyn KeyValueStorage>,
}

#[async_trait::async_trait]
impl StorageBackend for KvStorage {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        let Some(resource_byte) = self.storage.get(&ref_resource_path).await? else {
            bail!("resource not found: {}", ref_resource_path);
        };

        Ok(resource_byte)
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        self.storage
            .set(&ref_resource_path, data, SetParameters { overwrite: true })
            .await?;

        Ok(())
    }
}

impl KvStorage {
    pub fn new(storage: KeyValueStorageInstance) -> Self {
        Self { storage }
    }
}

#[cfg(test)]
mod tests {
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};

    use crate::plugins::resource::{kv_storage::KvStorage, RESOURCE_STORAGE_INSTANCE};

    use super::super::{ResourceDesc, StorageBackend};

    const TEST_DATA: &[u8] = b"testdata";

    #[tokio::test]
    async fn write_and_read_resource() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_INSTANCE)
            .await
            .expect("create key value storage failed");

        let local_fs = KvStorage::new(storage);
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "test".into(),
        };

        local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = local_fs
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }
}
