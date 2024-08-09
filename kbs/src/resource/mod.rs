// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

mod local_fs;
pub mod plugin;

#[cfg(feature = "aliyun")]
mod aliyun_kms;

/// Interface of a `Repository`.
#[async_trait::async_trait]
pub trait Repository {
    /// Read secret resource from repository.
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>>;

    /// Write secret resource into repository
    async fn write_secret_resource(
        &mut self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
}

impl ResourceDesc {
    pub fn is_valid(&self) -> bool {
        if &self.repository_name == "."
            || &self.repository_name == ".."
            || &self.resource_type == "."
            || &self.resource_type == ".."
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum RepositoryConfig {
    LocalFs(local_fs::LocalFsRepoDesc),

    #[cfg(feature = "aliyun")]
    Aliyun(aliyun_kms::AliyunKmsBackendConfig),
}

impl RepositoryConfig {
    pub fn initialize(&self) -> Result<Arc<RwLock<dyn Repository + Send + Sync>>> {
        match self {
            Self::LocalFs(desc) => {
                // Create repository dir.
                let dir_path = desc
                    .dir_path
                    .clone()
                    .unwrap_or(local_fs::DEFAULT_REPO_DIR_PATH.to_string());

                if !Path::new(&dir_path).exists() {
                    fs::create_dir_all(&dir_path)?;
                }
                // Create default repo.
                if !Path::new(&format!("{}/default", &dir_path)).exists() {
                    fs::create_dir_all(format!("{}/default", &dir_path))?;
                }

                Ok(Arc::new(RwLock::new(local_fs::LocalFs::new(desc)?))
                    as Arc<RwLock<dyn Repository + Send + Sync>>)
            }
            #[cfg(feature = "aliyun")]
            Self::Aliyun(config) => {
                let client = aliyun_kms::AliyunKmsBackend::new(config)?;
                Ok(Arc::new(RwLock::new(client)) as Arc<RwLock<dyn Repository + Send + Sync>>)
            }
        }
    }
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self::LocalFs(local_fs::LocalFsRepoDesc::default())
    }
}

pub(crate) async fn set_secret_resource(
    repository: &Arc<RwLock<dyn Repository + Send + Sync>>,
    resource_desc: ResourceDesc,
    data: &[u8],
) -> Result<()> {
    repository
        .write()
        .await
        .write_secret_resource(resource_desc, data)
        .await
}
