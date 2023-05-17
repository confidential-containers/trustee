// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Resource Library

use anyhow::*;
use local_fs::{LocalFs, LocalFsRepoDesc};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::RwLock;

mod local_fs;

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

/// Resource Description
#[derive(Debug, Clone)]
pub struct ResourceDesc {
    /// Repository Name
    pub repository_name: String,
    /// Resource Type
    pub resource_type: String,
    /// resource Tag
    pub resource_tag: String,
}

/// Resource Repository Type
#[derive(Deserialize, Debug, Clone, EnumString)]
pub enum RepositoryType {
    /// Local file system repository
    LocalFs,
}

impl RepositoryType {
    /// Transfer enum to repository instance
    pub fn to_repository(
        &self,
        repo_desc: &Option<Value>,
    ) -> Result<Arc<RwLock<dyn Repository + Send + Sync>>> {
        match self {
            RepositoryType::LocalFs => {
                let desc = match repo_desc {
                    Some(d) => serde_json::from_value::<LocalFsRepoDesc>(d.clone())?,
                    None => local_fs::LocalFsRepoDesc::default(),
                };

                // Create repository dir.
                if !Path::new(&desc.dir_path).exists() {
                    fs::create_dir_all(&desc.dir_path)?;
                }
                // Create default repo.
                if !Path::new(&format!("{}/default", &desc.dir_path)).exists() {
                    fs::create_dir_all(format!("{}/default", &desc.dir_path))?;
                }

                Ok(Arc::new(RwLock::new(LocalFs::new(desc)?))
                    as Arc<RwLock<dyn Repository + Send + Sync>>)
            }
        }
    }
}

/// Set secret resource
pub async fn set_secret_resource(
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
