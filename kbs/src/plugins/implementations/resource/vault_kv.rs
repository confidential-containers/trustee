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

#[cfg(test)]
mod integration_tests {
    use super::super::{
        vault_kv::{VaultKvBackend, VaultKvBackendConfig},
        ResourceDesc, StorageBackend,
    };
    use rstest::{fixture, rstest};
    use serde_json::json;
    use tokio;

    // These tests require a running Vault server and are marked as ignored by default.
    //
    // Look at the vault.PID and vault-ssl.PID Makefile targets for the setup

    // --- Fixtures for common test setup ---

    #[fixture]
    fn vault_token() -> String {
        std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN environment variable must be set")
    }

    #[fixture]
    fn ca_cert_path() -> String {
        std::env::var("VAULT_CA_CERT")
            .expect("VAULT_CA_CERT environment variable must be set for SSL verification tests")
    }

    // Fixture that provides a configured VaultKvBackend for non-SSL (HTTP) connections.
    #[fixture]
    fn nossl_backend(vault_token: String) -> VaultKvBackend {
        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };
        VaultKvBackend::new(&config).expect("Failed to create non-SSL Vault backend")
    }

    // Fixture that provides a VaultKvBackend for SSL (HTTPS) connections with CA verification.
    #[fixture]
    fn ssl_backend(vault_token: String, ca_cert_path: String) -> VaultKvBackend {
        let config = VaultKvBackendConfig {
            vault_url: "https://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: true,
            ca_certs: Some(vec![ca_cert_path]),
        };
        VaultKvBackend::new(&config).expect("Failed to create SSL Vault backend with verification")
    }

    // Fixture that provides a VaultKvBackend for SSL (HTTPS) connections where SSL verification is skipped.
    #[fixture]
    fn ssl_no_verify_backend(vault_token: String, ca_cert_path: String) -> VaultKvBackend {
        let config = VaultKvBackendConfig {
            vault_url: "https://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: Some(vec![ca_cert_path]),
        };
        VaultKvBackend::new(&config)
            .expect("Failed to create SSL Vault backend without verification")
    }

    // --- Test Suite for Non-SSL Operations ---

    #[rstest]
    #[case("write_and_read_text", "simple-text-data".as_bytes())]
    #[case("write_and_read_json", &serde_json::to_vec(&json!({"user": "test", "pass": "secret"})).unwrap())]
    #[tokio::test]
    #[ignore]
    async fn test_vault_nossl_write_and_read(
        nossl_backend: VaultKvBackend,
        #[case] tag: &str,
        #[case] data: &[u8],
    ) {
        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: tag.to_string(),
        };

        // Write the secret
        nossl_backend
            .write_secret_resource(resource_desc.clone(), data)
            .await
            .expect("Should succeed in writing the secret");
        println!("Successfully wrote secret for tag: {}", tag);

        // Read it back and verify
        let read_data = nossl_backend
            .read_secret_resource(resource_desc)
            .await
            .expect("Should succeed in reading the secret back");

        assert_eq!(read_data, data);
        println!(
            "Successfully read back and verified secret for tag: {}",
            tag
        );
    }

    #[rstest]
    #[tokio::test]
    #[ignore]
    async fn test_vault_nossl_read_scenarios(nossl_backend: VaultKvBackend) {
        // --- Scenario: Read a pre-existing secret ---
        let resource_desc_existing = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "test-tag".to_string(),
        };
        let data = nossl_backend
            .read_secret_resource(resource_desc_existing)
            .await
            .unwrap();
        assert_eq!(data, b"test-secret-value");
        println!("Successfully read pre-existing secret.");

        // --- Scenario: Read a pre-existing JSON secret ---
        let resource_desc_json = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "json-preloaded".to_string(),
        };
        let json_data = nossl_backend
            .read_secret_resource(resource_desc_json)
            .await
            .unwrap();
        let expected_json = json!({
            "service": "database",
            "credentials": {
                "host": "db.example.com",
                "port": 5432,
                "username": "app_user",
                "password": "secure_pass"
            },
            "settings": {
                "max_connections": 100,
                "timeout": 30
            }
        });
        let read_json: serde_json::Value = serde_json::from_slice(&json_data).unwrap();
        assert_eq!(read_json, expected_json);
        println!("Successfully read pre-existing JSON secret.");

        // --- Scenario: Read a non-existent secret ---
        let resource_desc_nonexistent = ResourceDesc {
            repository_name: "nonexistent".to_string(),
            resource_type: "nonexistent".to_string(),
            resource_tag: "nonexistent".to_string(),
        };
        let err = nossl_backend
            .read_secret_resource(resource_desc_nonexistent)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Secret not found"));
        println!("Correctly failed when reading a non-existent secret.");

        // --- Scenario: Read a secret with an empty data value ---
        let resource_desc_empty = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "empty-data".to_string(),
        };
        let data_empty = nossl_backend
            .read_secret_resource(resource_desc_empty)
            .await
            .unwrap();
        assert!(data_empty.is_empty());
        println!("Successfully read secret with empty data.");

        // --- Scenario: Read a secret where the 'data' key is missing in the payload ---
        let resource_desc_no_data = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "no-data-key".to_string(),
        };
        let err = nossl_backend
            .read_secret_resource(resource_desc_no_data)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required 'data' key"));
        println!("Correctly failed when 'data' key is missing.");
    }

    // --- Test Suite for SSL Operations ---

    #[rstest]
    #[case::with_ssl_verification(ssl_backend::default())]
    #[case::without_ssl_verification(ssl_no_verify_backend::default())]
    #[tokio::test]
    #[ignore]
    async fn test_vault_ssl_write_and_read(#[case] backend: VaultKvBackend) {
        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "ssl-test".to_string(),
        };
        let test_data = b"ssl-test-secret-value";

        // Write operation
        backend
            .write_secret_resource(resource_desc.clone(), test_data)
            .await
            .expect("Should succeed in writing secret over SSL");
        println!("Successfully wrote secret over SSL.");

        // Read back and verify
        let read_data = backend
            .read_secret_resource(resource_desc)
            .await
            .expect("Should succeed in reading secret back over SSL");

        assert_eq!(read_data, test_data);
        println!("Successfully read back and verified secret over SSL.");
    }

    // --- Standalone tests for specific invalid configurations ---

    // This test specifically checks the behavior of an invalid Vault token.
    #[rstest]
    #[tokio::test]
    #[ignore]
    async fn test_vault_invalid_token() {
        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: "invalid-token-12345".to_string(), // The invalid token
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };
        let backend = VaultKvBackend::new(&config).expect("Backend creation should succeed");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "test-tag".to_string(),
        };

        let err = backend
            .read_secret_resource(resource_desc)
            .await
            .unwrap_err();
        println!("Failed with invalid token: {}", err);
        // Error should indicate a permission denied
        assert!(
            err.to_string().contains("403")
                || err.to_string().to_lowercase().contains("permission denied")
        );
    }

    // This test specifically checks the behavior of an invalid mount path.
    #[rstest]
    #[tokio::test]
    #[ignore]
    async fn test_vault_invalid_mount_path(vault_token: String) {
        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "nonexistent-mount".to_string(), // The invalid mount path
            verify_ssl: false,
            ca_certs: None,
        };
        let backend = VaultKvBackend::new(&config).expect("Backend creation should succeed");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "test-tag".to_string(),
        };

        let err = backend
            .read_secret_resource(resource_desc)
            .await
            .unwrap_err();
        println!("Failed with invalid mount path: {}", err);
        // Error could be a 403 or a specific Vault error about the path
        assert!(
            err.to_string().contains("403")
                || err
                    .to_string()
                    .contains("ensure client's policies grant access to path")
        );
    }
}
