// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{Repository, ResourceDesc};
use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

const DEFAULT_REPO_DIR_PATH: &str = "/opt/confidential-containers/kbs/repository/";

#[derive(Deserialize, Clone)]
pub struct LocalFsRepoDesc {
    pub dir_path: String,
}

impl Default for LocalFsRepoDesc {
    fn default() -> Self {
        Self {
            dir_path: DEFAULT_REPO_DIR_PATH.to_string(),
        }
    }
}

pub struct LocalFs {
    pub repo_dir_path: String,
}

impl Repository for LocalFs {
    fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let mut resource_path = PathBuf::from(&self.repo_dir_path);

        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );
        resource_path.push(ref_resource_path);

        let resource_byte = ::std::fs::read(&resource_path)?;
        Ok(resource_byte)
    }
}

impl LocalFs {
    pub fn new(repo_desc: LocalFsRepoDesc) -> Result<Self> {
        Ok(Self {
            repo_dir_path: repo_desc.dir_path,
        })
    }
}
