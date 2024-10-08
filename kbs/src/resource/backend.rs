// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::Deserialize;

use super::local_fs;
use super::{Error, Result};

type RepositoryInstance = Arc<dyn StorageBackend>;

/// Interface of a `Repository`.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Read secret resource from repository.
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>>;

    /// Write secret resource into repository
    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
}

impl TryFrom<&str> for ResourceDesc {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let path_parts: Vec<&str> = value.split('/').collect();
        let resource_description = match path_parts.len() {
            2 => Self {
                repository_name: "default".into(),
                resource_type: path_parts[0].into(),
                resource_tag: path_parts[1].into(),
            },
            3 => Self {
                repository_name: path_parts[0].into(),
                resource_type: path_parts[1].into(),
                resource_tag: path_parts[2].into(),
            },
            _ => return Err(Error::ParseResourceDescription),
        };

        if path_parts[0] == "."
            || path_parts[0] == ".."
            || path_parts[1] == "."
            || path_parts[1] == ".."
        {
            return Err(Error::MalwaredResourceDescription);
        }

        Ok(resource_description)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum RepositoryConfig {
    LocalFs(local_fs::LocalFsRepoDesc),

    #[cfg(feature = "aliyun")]
    #[serde(alias = "aliyun")]
    Aliyun(super::aliyun_kms::AliyunKmsBackendConfig),
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self::LocalFs(local_fs::LocalFsRepoDesc::default())
    }
}

#[derive(Clone)]
pub struct ResourceStorage {
    backend: RepositoryInstance,
}

impl TryFrom<RepositoryConfig> for ResourceStorage {
    type Error = Error;

    fn try_from(value: RepositoryConfig) -> Result<Self> {
        match value {
            RepositoryConfig::LocalFs(desc) => {
                let backend = local_fs::LocalFs::new(&desc)
                    .map_err(|e| Error::ResourceStorageInitialization { source: e })?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
            #[cfg(feature = "aliyun")]
            RepositoryConfig::Aliyun(config) => {
                let client = super::aliyun_kms::AliyunKmsBackend::new(&config)?;
                Ok(Self {
                    backend: Arc::new(client),
                })
            }
        }
    }
}

impl ResourceStorage {
    pub(crate) async fn set_secret_resource(
        &self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<()> {
        self.backend
            .write_secret_resource(resource_desc, data)
            .await
    }

    pub(crate) async fn get_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        self.backend.read_secret_resource(resource_desc).await
    }
}
