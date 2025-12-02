// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{ResourceDesc, StorageBackend};
use anyhow::{bail, Result};
use key_value_storage::{KeyValueStorage, KeyValueStorageConfig, SetParameters};
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
    pub async fn new(repo_desc: &KeyValueStorageConfig) -> anyhow::Result<Self> {
        let storage = repo_desc.to_key_value_storage().await?;
        Ok(Self { storage })
    }
}

#[cfg(test)]
mod tests {
    use crate::plugins::resource::kv_storage::KvStorage;

    use super::super::{ResourceDesc, StorageBackend};
    use key_value_storage::KeyValueStorageConfig;

    const TEST_DATA: &[u8] = b"testdata";

    #[tokio::test]
    async fn write_and_read_resource() {
        let repo_desc = KeyValueStorageConfig::Memory;

        let local_fs = KvStorage::new(&repo_desc)
            .await
            .expect("create local fs failed");
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
