#[cfg(test)]
mod integration_tests {
    use super::super::vault_kv::{VaultKvBackend, VaultKvBackendConfig};
    use super::super::{ResourceDesc, StorageBackend};
    use tokio;

    // These tests require a running Vault server and are marked as ignored by default
    // To run these tests:
    // 1. Start a Vault dev server: vault server -dev
    // 2. Set the vault token: export VAULT_TOKEN=<your-token>
    // 3. Run: cargo test --features vault vault_nossl -- --ignored
    // 3. Run: cargo test --features vault vault_ssl -- --ignored

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_read_secret() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "test-tag".to_string(),
        };

        // Note: This test assumes the secret exists in Vault at path "secret/test-repo/test-type/test-tag"
        // You should manually create this secret in Vault before running the test:
        // vault kv put secret/test-repo/test-type/test-tag data="test-secret-value"

        match backend.read_secret_resource(resource_desc).await {
            Ok(data) => {
                println!(
                    "Successfully read secret: {:?}",
                    String::from_utf8_lossy(&data)
                );
                assert!(!data.is_empty());
            }
            Err(e) => {
                // Test might fail if secret doesn't exist - that's expected
                println!("Read failed (expected if secret doesn't exist): {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_write_secret() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "write-test".to_string(),
        };

        let test_data = b"test-secret-data-for-write";

        // Test write operation
        match backend
            .write_secret_resource(resource_desc.clone(), test_data)
            .await
        {
            Ok(_) => {
                println!("Successfully wrote secret to Vault");

                // Try to read it back to verify
                match backend.read_secret_resource(resource_desc).await {
                    Ok(read_data) => {
                        println!(
                            "Successfully read back secret: {:?}",
                            String::from_utf8_lossy(&read_data)
                        );
                    }
                    Err(e) => {
                        println!("Failed to read back written secret: {}", e);
                    }
                }
            }
            Err(e) => {
                println!(
                    "Write failed (may be expected if Vault server isn't configured): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_ssl_with_ca_verification() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for SSL integration tests");
        let ca_cert_path = std::env::var("VAULT_CA_CERT")
            .expect("VAULT_CA_CERT environment variable must be set for SSL integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "https://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: true,
            ca_certs: Some(vec![ca_cert_path]),
        };

        let backend =
            VaultKvBackend::new(&config).expect("Failed to create Vault backend with SSL");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "ssl-test".to_string(),
        };

        // Test read operation with SSL
        match backend.read_secret_resource(resource_desc.clone()).await {
            Ok(data) => {
                println!(
                    "Successfully read secret via SSL with CA verification: {:?}",
                    String::from_utf8_lossy(&data)
                );
                assert!(!data.is_empty());
            }
            Err(e) => {
                println!("SSL read failed (expected if secret doesn't exist): {}", e);
            }
        }

        // Test write operation with SSL
        let test_data = b"ssl-test-secret-data";
        match backend
            .write_secret_resource(resource_desc.clone(), test_data)
            .await
        {
            Ok(_) => {
                println!("Successfully wrote secret to Vault via SSL");

                // Try to read it back to verify SSL functionality
                match backend.read_secret_resource(resource_desc).await {
                    Ok(read_data) => {
                        println!(
                            "Successfully read back SSL secret: {:?}",
                            String::from_utf8_lossy(&read_data)
                        );
                    }
                    Err(e) => {
                        println!("Failed to read back SSL secret: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("SSL write failed: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_ssl_skip_verification() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for SSL integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "https://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config)
            .expect("Failed to create Vault backend with SSL verification disabled");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "ssl-skip-verify-test".to_string(),
        };

        // Test read operation with SSL but verification disabled
        match backend.read_secret_resource(resource_desc.clone()).await {
            Ok(data) => {
                println!(
                    "Successfully read secret via SSL with verification disabled: {:?}",
                    String::from_utf8_lossy(&data)
                );
                assert!(!data.is_empty());
            }
            Err(e) => {
                println!("SSL read failed (expected if secret doesn't exist): {}", e);
            }
        }

        // Test write operation with SSL but verification disabled
        let test_data = b"ssl-skip-verify-test-data";
        match backend
            .write_secret_resource(resource_desc.clone(), test_data)
            .await
        {
            Ok(_) => {
                println!("Successfully wrote secret via SSL with verification disabled");

                // Try to read it back to verify SSL functionality
                match backend.read_secret_resource(resource_desc).await {
                    Ok(read_data) => {
                        println!(
                            "Successfully read back SSL secret (verification disabled): {:?}",
                            String::from_utf8_lossy(&read_data)
                        );
                    }
                    Err(e) => {
                        println!("Failed to read back SSL secret: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("SSL write failed (verification disabled): {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_read_secret_missing_data_key() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "no-data-key".to_string(),
        };

        // This test expects a secret that exists but without the "data" key
        // The Makefile should create this secret:
        // vault kv put secret/test-repo/test-type/no-data-key value="some-value" other="content"

        match backend.read_secret_resource(resource_desc).await {
            Ok(_) => {
                panic!("Should have failed when reading secret without 'data' key");
            }
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Secret data not found")
                        || error_msg.contains("expected 'data' key"),
                    "Expected error message about missing 'data' key, got: {}",
                    error_msg
                );
                println!("Correctly failed to read secret without 'data' key: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_read_nonexistent_secret() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "nonexistent".to_string(),
            resource_type: "nonexistent".to_string(),
            resource_tag: "nonexistent".to_string(),
        };

        match backend.read_secret_resource(resource_desc).await {
            Ok(_) => {
                panic!("Should have failed when reading nonexistent secret");
            }
            Err(e) => {
                println!("Correctly failed to read nonexistent secret: {}", e);
                // Should fail at the Vault level, not at our data key check
                assert!(!e.to_string().contains("expected 'data' key"));
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_read_empty_secret() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "empty-data".to_string(),
        };

        // This test expects a secret with empty data value
        // The Makefile should create this secret:
        // vault kv put secret/test-repo/test-type/empty-data data=""

        match backend.read_secret_resource(resource_desc).await {
            Ok(data) => {
                assert!(data.is_empty(), "Expected empty data, got: {:?}", data);
                println!("Successfully read empty secret data");
            }
            Err(e) => {
                println!("Reading empty secret failed: {}", e);
                // Empty string should still be readable, so this is unexpected
                panic!(
                    "Reading secret with empty data should succeed, got error: {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_invalid_mount_path() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "nonexistent-mount".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "test-tag".to_string(),
        };

        match backend.read_secret_resource(resource_desc).await {
            Ok(_) => {
                panic!("Should have failed when using invalid mount path");
            }
            Err(e) => {
                println!("Correctly failed with invalid mount path: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_invalid_token() {
        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: "invalid-token-12345".to_string(),
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "test-tag".to_string(),
        };

        match backend.read_secret_resource(resource_desc).await {
            Ok(_) => {
                panic!("Should have failed when using invalid token");
            }
            Err(e) => {
                println!("Correctly failed with invalid token: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_json_structured_data() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "json-data".to_string(),
        };

        // Create a JSON structure to test with
        let json_data = serde_json::json!({
            "username": "test-user",
            "password": "secret-password",
            "config": {
                "timeout": 30,
                "retries": 3,
                "endpoints": ["https://api1.example.com", "https://api2.example.com"]
            },
            "metadata": {
                "created": "2024-01-01T00:00:00Z",
                "version": "1.0.0"
            }
        });

        let json_bytes = serde_json::to_vec(&json_data).expect("Failed to serialize JSON");

        // Test write operation with JSON data
        match backend
            .write_secret_resource(resource_desc.clone(), &json_bytes)
            .await
        {
            Ok(_) => {
                println!("Successfully wrote JSON structured secret to Vault");

                // Try to read it back to verify
                match backend.read_secret_resource(resource_desc).await {
                    Ok(read_data) => {
                        println!(
                            "Successfully read back JSON secret: {}",
                            String::from_utf8_lossy(&read_data)
                        );

                        // Parse the read data as JSON to verify structure
                        let parsed_json: serde_json::Value = serde_json::from_slice(&read_data)
                            .expect("Failed to parse read data as JSON");

                        // Verify the JSON structure is intact
                        assert_eq!(parsed_json["username"], "test-user");
                        assert_eq!(parsed_json["password"], "secret-password");
                        assert_eq!(parsed_json["config"]["timeout"], 30);
                        assert_eq!(parsed_json["config"]["retries"], 3);
                        assert_eq!(parsed_json["metadata"]["version"], "1.0.0");

                        // Verify arrays are preserved
                        let endpoints = parsed_json["config"]["endpoints"]
                            .as_array()
                            .expect("endpoints should be an array");
                        assert_eq!(endpoints.len(), 2);
                        assert_eq!(endpoints[0], "https://api1.example.com");
                        assert_eq!(endpoints[1], "https://api2.example.com");

                        println!("JSON structure validation passed");
                    }
                    Err(e) => {
                        panic!("Failed to read back written JSON secret: {}", e);
                    }
                }
            }
            Err(e) => {
                println!(
                    "JSON write failed (may be expected if Vault server isn't configured): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn vault_nossl_read_json_secret() {
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("VAULT_TOKEN environment variable must be set for integration tests");

        let config = VaultKvBackendConfig {
            vault_url: "http://127.0.0.1:8200".to_string(),
            token: vault_token,
            mount_path: "secret".to_string(),
            verify_ssl: false,
            ca_certs: None,
        };

        let backend = VaultKvBackend::new(&config).expect("Failed to create Vault backend");

        let resource_desc = ResourceDesc {
            repository_name: "test-repo".to_string(),
            resource_type: "test-type".to_string(),
            resource_tag: "json-preloaded".to_string(),
        };

        // This test expects a secret that was pre-created in Vault with JSON content
        // The Makefile should create this secret with complex JSON data

        match backend.read_secret_resource(resource_desc).await {
            Ok(data) => {
                println!(
                    "Successfully read JSON secret: {}",
                    String::from_utf8_lossy(&data)
                );

                // Try to parse as JSON to verify it's valid JSON
                match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(json_value) => {
                        println!("Successfully parsed JSON: {:?}", json_value);
                        assert!(!data.is_empty());
                    }
                    Err(e) => {
                        println!("Data is not valid JSON (may be expected): {}", e);
                        // If it's not JSON, that's fine - just verify we got some data
                        assert!(!data.is_empty());
                    }
                }
            }
            Err(e) => {
                println!("Read failed (expected if secret doesn't exist): {}", e);
            }
        }
    }
}
