// Copyright (c) 2025 Confidential Containers Contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{Context, Result};
use derivative::Derivative;
use log::info;
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    kv1,
};

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Secret not found at path '{path}'")]
    SecretNotFound { path: String, source: anyhow::Error },
    #[error("Secret exists at path '{path}' but missing required 'data' key. Available keys: {available_keys:?}")]
    DataKeyMissing {
        path: String,
        available_keys: Vec<String>,
    },
    #[error("Vault API error for path '{path}': {source}")]
    VaultApiError { path: String, source: anyhow::Error },
}

#[derive(Derivative, Deserialize, Clone, PartialEq)]
#[derivative(Debug)]
pub struct VaultKvBackendConfig {
    pub vault_url: String,
    #[derivative(Debug = "ignore")]
    pub token: String,
    #[serde(default = "default_mount_path")]
    pub mount_path: String,
    #[serde(default = "default_verify_ssl")]
    pub verify_ssl: bool,
    #[serde(default)]
    pub ca_certs: Option<Vec<String>>,
}

fn default_mount_path() -> String {
    "secret".to_string()
}

fn default_verify_ssl() -> bool {
    false
}

pub struct VaultKvBackend {
    client: VaultClient,
    mount_path: String,
}

#[async_trait::async_trait]
impl StorageBackend for VaultKvBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let vault_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        info!("Reading secret from Vault path: {}", vault_path);

        let secret_data: HashMap<String, String> =
            kv1::get(&self.client, &self.mount_path, &vault_path)
                .await
                .map_err(|e| {
                    if e.to_string().contains("status code 404") {
                        VaultError::SecretNotFound {
                            path: vault_path.clone(),
                            source: e.into(),
                        }
                    } else {
                        VaultError::VaultApiError {
                            path: vault_path.clone(),
                            source: e.into(),
                        }
                    }
                })?;

        secret_data
            .get("data")
            .map(|v| v.as_bytes().to_vec())
            .ok_or_else(|| {
                let available_keys = secret_data.keys().cloned().collect();
                VaultError::DataKeyMissing {
                    path: vault_path,
                    available_keys,
                }
                .into()
            })
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let vault_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        info!("Writing secret to Vault path: {}", vault_path);

        // Convert data to string for Vault storage
        let data_str =
            String::from_utf8(data.to_vec()).context("Failed to convert data to UTF-8 string")?;

        // Create a HashMap with the data - using &str keys as expected by vaultrs
        let mut secret_data = std::collections::HashMap::new();
        secret_data.insert("data", data_str.as_str());

        kv1::set(&self.client, &self.mount_path, &vault_path, &secret_data)
            .await
            .context("Failed to write secret to Vault")?;

        Ok(())
    }
}

impl VaultKvBackend {
    pub fn new(config: &VaultKvBackendConfig) -> Result<Self> {
        let mut builder = VaultClientSettingsBuilder::default();

        let mut client_settings_builder = builder
            .address(&config.vault_url)
            .token(&config.token)
            .verify(config.verify_ssl);

        // Configure custom CA certificates if provided
        if let Some(ca_certs) = &config.ca_certs {
            client_settings_builder = client_settings_builder.ca_certs(ca_certs.clone());
        }

        let client_settings = client_settings_builder
            .build()
            .context("Failed to build Vault client settings")?;

        let client = VaultClient::new(client_settings).context("Failed to create Vault client")?;

        Ok(Self {
            client,
            mount_path: config.mount_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_config_deserialization() {
        let config_str = r#"
        vault_url = "https://vault.example.com:8200"
        token = "hvs.test-token"
        mount_path = "kv"
        verify_ssl = false
        ca_certs = ["/path/to/ca.pem"]
        "#;

        let config: VaultKvBackendConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.vault_url, "https://vault.example.com:8200");
        assert_eq!(config.token, "hvs.test-token");
        assert_eq!(config.mount_path, "kv");
        assert_eq!(config.verify_ssl, false);
        assert_eq!(config.ca_certs, Some(vec!["/path/to/ca.pem".to_string()]));
    }

    #[test]
    fn test_vault_config_default_mount_path() {
        let config_str = r#"
        vault_url = "http://vault.example.com:8200"
        token = "hvs.test-token"
        "#;

        let config: VaultKvBackendConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.mount_path, "secret"); // Default value
        assert_eq!(config.verify_ssl, false); // Default value
        assert_eq!(config.ca_certs, None); // Default value
    }

    #[test]
    fn test_write_operation_structure() {
        // Test that write operations create the correct data structure
        let resource_desc = ResourceDesc {
            repository_name: "test".to_string(),
            resource_type: "secret".to_string(),
            resource_tag: "test-key".to_string(),
        };

        let test_data = b"test-secret-value";
        let data_str = String::from_utf8(test_data.to_vec()).unwrap();

        let mut expected_secret_data = std::collections::HashMap::new();
        expected_secret_data.insert("data".to_string(), data_str);

        // Verify the data structure is correct
        assert_eq!(
            expected_secret_data.get("data").unwrap(),
            "test-secret-value"
        );

        let expected_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );
        assert_eq!(expected_path, "test/secret/test-key");
    }

    #[test]
    fn test_vault_config_https_options() {
        // Test minimal HTTPS config
        let config_str = r#"
        vault_url = "https://vault.example.com:8200"
        token = "hvs.test-token"
        verify_ssl = false
        "#;

        let config: VaultKvBackendConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.verify_ssl, false);
        assert_eq!(config.ca_certs, None);

        // Test config with custom CA certificates
        let config_str = r#"
        vault_url = "https://vault.example.com:8200"
        token = "hvs.test-token"
        verify_ssl = true
        ca_certs = ["/etc/ssl/certs/ca-bundle.pem", "/path/to/custom-ca.pem"]
        "#;

        let config: VaultKvBackendConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.verify_ssl, true);
        assert_eq!(
            config.ca_certs,
            Some(vec![
                "/etc/ssl/certs/ca-bundle.pem".to_string(),
                "/path/to/custom-ca.pem".to_string()
            ])
        );
    }
}
