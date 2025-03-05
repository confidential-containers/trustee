// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Error, Result};
use serde::Deserialize;
use std::sync::RwLock;
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};

use super::credential::{Credential, PKIVaultCertDetails};
use crate::plugins::plugin_manager::ClientPlugin;

const DEFAULT_PLUGIN_DIR: &str = "/opt/confidential-containers/kbs/plugin/pki_vault";
const DEFAULT_CREDENTIALS_BLOB_FILE: &str = "certificates.json";

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct PKIVaultPluginConfig {
    pub plugin_dir: String,
    pub cred_filename: String,
    pub pkivault_cert_details: PKIVaultCertDetails,
}

impl Default for PKIVaultPluginConfig {
    fn default() -> Self {
        PKIVaultPluginConfig {
            plugin_dir: DEFAULT_PLUGIN_DIR.into(),
            cred_filename: DEFAULT_CREDENTIALS_BLOB_FILE.into(),
            pkivault_cert_details: PKIVaultCertDetails::default(),
        }
    }
}

impl TryFrom<PKIVaultPluginConfig> for PKIVaultPlugin {
    type Error = Error;

    fn try_from(config: PKIVaultPluginConfig) -> Result<Self> {
        // Create the plugin dir if it does not exist
        let plugin_dir = PathBuf::from(&config.plugin_dir);
        if !plugin_dir.exists() {
            fs::create_dir_all(&plugin_dir)?;
            log::info!("plugin dir created = {}", plugin_dir.display());
        }

        // Read the existing credentials from file
        let path = PathBuf::from(&config.plugin_dir)
            .as_path()
            .join(config.cred_filename);

        let credential: HashMap<String, Credential> = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_else(|_| HashMap::new()),
                Err(_) => {
                    log::warn!("Error reading the credential file.");
                    HashMap::new()
                }
            }
        } else {
            log::warn!("Credentail file does not exist.");
            HashMap::new()
        };

        // Initializing the PKI Vault plugin with existing credential data from file
        Ok(PKIVaultPlugin {
            plugin_dir: PathBuf::from(&config.plugin_dir),
            cert_details: config.pkivault_cert_details,
            credblob_file: path,
            cred_store: Arc::new(RwLock::new(credential)),
        })
    }
}

/// Parameters for the credential request
///
/// These parameters are provided in the request via URL query string.
/// Parameters taken by the "pki-vault" plugin to generate a unique key
/// for a sandbox store and retrieve credentials specific to the sandbox.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct SandboxParams {
    /// Required: ID of a sandbox or pod
    pub id: String,

    /// Required: IP of a sandbox or pod
    pub ip: String,

    /// Required: Name of a sandbox or pod
    pub name: String,
}

impl TryFrom<&str> for SandboxParams {
    type Error = Error;

    fn try_from(query: &str) -> Result<Self> {
        let params: SandboxParams = serde_qs::from_str(query)?;
        Ok(params)
    }
}

/// Credentials necessary for initiating a server inside sandbox
#[derive(Debug, serde::Serialize)]
pub struct ServerCredential {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

/// Manages the credentials generation, handling requests
/// from backend, and credentials persistence storage
pub struct PKIVaultPlugin {
    pub plugin_dir: PathBuf,
    pub cert_details: PKIVaultCertDetails,
    pub credblob_file: PathBuf,
    pub cred_store: Arc<RwLock<HashMap<String, Credential>>>,
}

impl PKIVaultPlugin {
    fn get_credential(&self, key: &str) -> Option<Credential> {
        let cred_store = self.cred_store.read().unwrap();
        cred_store.get(key).cloned()
    }

    fn store_credential(&self, key: &str, credential: Credential) {
        let mut cred_store = self.cred_store.write().unwrap();
        cred_store.insert(key.to_string(), credential);
    }

    // Generate the credential (keys and certs for ca, server, and client)
    fn generate_credential(&self, key: &str) -> Result<Vec<u8>> {
        let credential = Credential::new(&self.cert_details)?;

        // Store the credential into the hashmap
        self.store_credential(key, credential.clone());

        // Write the hashmap to file for a persistence copy
        if let Err(e) = self.save_hashmap(&self.credblob_file) {
            log::warn!("Failed to store credentials into file: {}", e);
        }

        log::info!("Returning newly generated credential!");
        let resource = ServerCredential {
            key: credential.server_key.clone(),
            cert: credential.server_cert.clone(),
            ca_cert: credential.ca_cert.clone(),
        };

        Ok(serde_json::to_vec(&resource)?)
    }

    fn save_hashmap(&self, path: &PathBuf) -> Result<()> {
        let cred_store = self.cred_store.read().unwrap();
        let serialized = serde_json::to_string(&*cred_store)?;
        fs::write(path, serialized)?;
        Ok(())
    }

    async fn get_server_credential(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        // Return the server credential if the credential presents in the hashmap
        let key = format!("{}_{}_{}", &params.name, &params.ip, &params.id);
        if let Some(credential) = self.get_credential(&key) {
            log::info!("Returning existing credential!");

            let resource = ServerCredential {
                key: credential.server_key,
                cert: credential.server_cert,
                ca_cert: credential.ca_cert,
            };

            return Ok(serde_json::to_vec(&resource)?);
        };

        // Otherwise return newly generated credential
        self.generate_credential(&key)
    }
}

#[async_trait::async_trait]
impl ClientPlugin for PKIVaultPlugin {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method. Only GET is supported");
        }

        match sub_path {
            "credential" => {
                let params = SandboxParams::try_from(query)?;
                let credential = self.get_server_credential(&params).await?;

                Ok(credential)
            }
            _ => Err(anyhow!("{} not supported", sub_path))?,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_handle() {
        let config = PKIVaultPluginConfig::default();
        let plugin = PKIVaultPlugin::try_from(config).unwrap();

        // Define sample inputs
        let body: &[u8] = b"";
        let query = "id=3367348&ip=60.11.12.43&name=pod7";
        let path = "/credential";
        let method = &Method::GET;

        // Act: call the handle method
        let result = plugin.handle(body, query, path, method).await;

        // Assert: check the result
        match result {
            Ok(response) => {
                // Expected results
                let key = String::from("pod7_60.11.12.43_3367348");

                if let Some(credential) = plugin.get_credential(&key) {
                    let resource = ServerCredential {
                        key: credential.server_key,
                        cert: credential.server_cert,
                        ca_cert: credential.ca_cert,
                    };

                    let expected_response = serde_json::to_vec(&resource).unwrap();
                    assert_eq!(response, expected_response);
                };
            }
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    }
}
