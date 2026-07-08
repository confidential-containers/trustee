// Copyright (c) 2026 Confidential Containers Contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// GCP resource backend. Fetches secret material from Google Cloud Secret
// Manager. This is the closest analog to AWS Secrets Manager (`aws_kms.rs`)
// and the Aliyun KMS Instance secrets API that backs `aliyun_kms.rs`.

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{anyhow, bail, Context, Result};
use google_cloud_secretmanager_v1::client::SecretManagerService;
use serde::Deserialize;
use tracing::info;

fn default_version() -> String {
    "latest".to_string()
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct GcpSmBackendConfig {
    /// GCP project id (or number) that owns the secrets. Required: Secret
    /// Manager resource names are `projects/<project>/secrets/<name>/versions/<version>`.
    pub project_id: String,

    /// Secret version to access. Either a version number or the alias `latest`.
    /// Defaults to `latest`.
    #[serde(default = "default_version")]
    pub version: String,

    /// Optional endpoint override. Useful for a fake server in tests or a
    /// private service endpoint. Defaults to `https://secretmanager.googleapis.com`.
    #[serde(default)]
    pub endpoint_url: Option<String>,
}

pub struct GcpSmBackend {
    client: SecretManagerService,
    project_id: String,
    version: String,
}

/// Build the fully-qualified Secret Manager version resource name that
/// `AccessSecretVersion` expects. Kept pure so it can be unit tested without a
/// client or credentials.
fn secret_version_name(project_id: &str, secret: &str, version: &str) -> String {
    format!("projects/{project_id}/secrets/{secret}/versions/{version}")
}

#[async_trait::async_trait]
impl StorageBackend for GcpSmBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        info!(
            "Use GCP Secret Manager backend. Ignore {}/{}",
            resource_desc.repository_name, resource_desc.resource_type
        );
        let name = secret_version_name(
            &self.project_id,
            &resource_desc.resource_tag,
            &self.version,
        );

        let response = self
            .client
            .access_secret_version()
            .set_name(name.clone())
            .send()
            .await
            .with_context(|| format!("failed to access secret '{name}' from GCP Secret Manager"))?;

        let payload = response
            .payload
            .ok_or_else(|| anyhow!("GCP Secret Manager returned no payload for secret '{name}'"))?;

        Ok(payload.data.to_vec())
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        bail!("GCP Secret Manager backend does not support write operations; provision secrets via GCP APIs")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        bail!("GCP Secret Manager backend does not support delete operations; manage secret lifecycle via GCP APIs")
    }
}

impl GcpSmBackend {
    pub async fn new(config: &GcpSmBackendConfig) -> Result<Self> {
        let mut builder = SecretManagerService::builder();
        if let Some(endpoint) = &config.endpoint_url {
            builder = builder.with_endpoint(endpoint.clone());
        }
        // Credentials are resolved via Application Default Credentials (ADC):
        // `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default
        // login`, or the GCE/GKE/Cloud Run metadata server.
        let client = builder
            .build()
            .await
            .context("failed to build GCP Secret Manager client")?;
        Ok(Self {
            client,
            project_id: config.project_id.clone(),
            version: config.version.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::minimal(
        r#"project_id = "my-project""#,
        GcpSmBackendConfig {
            project_id: "my-project".to_string(),
            version: "latest".to_string(),
            endpoint_url: None,
        },
    )]
    #[case::full(
        r#"
            project_id = "my-project"
            version = "3"
            endpoint_url = "http://localhost:8080"
        "#,
        GcpSmBackendConfig {
            project_id: "my-project".to_string(),
            version: "3".to_string(),
            endpoint_url: Some("http://localhost:8080".to_string()),
        },
    )]
    fn deserialize_config(#[case] input: &str, #[case] expected: GcpSmBackendConfig) {
        let cfg: GcpSmBackendConfig = toml::from_str(input).unwrap();
        assert_eq!(cfg, expected);
    }

    #[rstest]
    #[case(
        "my-project",
        "my-secret",
        "latest",
        "projects/my-project/secrets/my-secret/versions/latest"
    )]
    #[case(
        "123456789",
        "db-password",
        "3",
        "projects/123456789/secrets/db-password/versions/3"
    )]
    fn build_secret_version_name(
        #[case] project_id: &str,
        #[case] secret: &str,
        #[case] version: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(secret_version_name(project_id, secret, version), expected);
    }
}
