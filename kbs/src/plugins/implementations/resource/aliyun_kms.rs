// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{Context, Result};
use kms::{plugins::aliyun::AliyunKmsClient, Annotations, Getter};
use log::info;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct AliyunKmsBackendConfig {
    client_key: String,
    kms_instance_id: String,
    password: String,
    cert_pem: String,
}

pub struct AliyunKmsBackend {
    client: AliyunKmsClient,
}

#[async_trait::async_trait]
impl StorageBackend for AliyunKmsBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        info!(
            "Use aliyun KMS backend. Ignore {}/{}",
            resource_desc.repository_name, resource_desc.resource_type
        );
        let name = resource_desc.resource_tag;
        let resource_bytes = self
            .client
            .get_secret(&name, &Annotations::default())
            .await
            .context("failed to get resource from aliyun KMS")?;
        Ok(resource_bytes)
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        todo!("Does not support!")
    }
}

impl AliyunKmsBackend {
    pub fn new(repo_desc: &AliyunKmsBackendConfig) -> Result<Self> {
        let client = AliyunKmsClient::new(
            &repo_desc.client_key,
            &repo_desc.kms_instance_id,
            &repo_desc.password,
            &repo_desc.cert_pem,
        )
        .context("create aliyun KMS backend")?;
        Ok(Self { client })
    }
}
