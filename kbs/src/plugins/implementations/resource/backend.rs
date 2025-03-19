// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context, Error, Result};
use regex::Regex;
use serde::Deserialize;
use std::fmt;

use super::local_fs;

type RepositoryInstance = Arc<dyn StorageBackend>;

/// Interface of a `Repository`.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Read secret resource from repository.
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>>;

    /// Write secret resource into repository
    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
}

static CELL: OnceLock<Regex> = OnceLock::new();

impl TryFrom<&str> for ResourceDesc {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let regex = CELL.get_or_init(|| {
            Regex::new(
                r"^(?<repo>[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*)\/(?<type>[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*)\/(?<tag>[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*)$",
            )
            .unwrap()
        });
        let Some(captures) = regex.captures(value) else {
            bail!("illegal ResourceDesc format.");
        };

        Ok(Self {
            repository_name: captures["repo"].into(),
            resource_type: captures["type"].into(),
            resource_tag: captures["tag"].into(),
        })
    }
}

impl fmt::Display for ResourceDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.repository_name, self.resource_type, self.resource_tag
        )
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
                    .context("Failed to initialize Resource Storage")?;
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::ResourceDesc;

    #[rstest]
    #[case("default/1/2", Some(ResourceDesc {
        repository_name: "default".into(),
        resource_type: "1".into(),
        resource_tag: "2".into(),
    }))]
    #[case("/1/2", None)]
    #[case("/repo/type/tag", None)]
    #[case("repo/type/tag", Some(ResourceDesc {
        repository_name: "repo".into(),
        resource_type: "type".into(),
        resource_tag: "tag".into(),
    }))]
    #[case("1/2", None)]
    #[case("123--_default/1Abff-_/___-afds44BC", Some(ResourceDesc {
        repository_name: "123--_default".into(),
        resource_type: "1Abff-_".into(),
        resource_tag: "___-afds44BC".into(),
    }))]
    #[case("1.ok/2ok./3...", Some(ResourceDesc {
        repository_name: "1.ok".into(),
        resource_type: "2ok.".into(),
        resource_tag: "3...".into(),
    }))]
    #[case(".1.ok/2ok./3...", None)]
    #[case("1.ok/.2ok./3...", None)]
    #[case("1.ok/2ok./.3...", None)]
    fn parse_resource_desc(#[case] desc: &str, #[case] expected: Option<ResourceDesc>) {
        let parsed = ResourceDesc::try_from(desc);
        if expected.is_none() {
            assert!(parsed.is_err());
        } else {
            assert_eq!(parsed.unwrap(), expected.unwrap());
        }
    }
}
