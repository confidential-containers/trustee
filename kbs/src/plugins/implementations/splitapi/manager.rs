// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};
use tempfile::tempdir_in;
use tokio::sync::RwLock;

use super::backend::{SandboxParams, SplitAPIBackend};
use super::generator::{CertificateDetails, CredentialGenerator};

/// Credentials (keys and certs for CA, server, and client)
/// ncessary for the SplitAPI work
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub ca_crt: Vec<u8>,
    pub client_key: Vec<u8>,
    pub client_crt: Vec<u8>,
    pub server_key: Vec<u8>,
    pub server_crt: Vec<u8>,
}

/// Credentials necessary for SplitAPI proxy server
#[derive(Debug, serde::Serialize)]
pub struct ServerCredentials {
    pub key: Vec<u8>,
    pub crt: Vec<u8>,
    pub ca_crt: Vec<u8>,
}

/// Manages the credentials generation, handling requests
/// from backend, and credentials persistence storage
pub struct CertManager {
    pub plugin_dir: PathBuf,
    pub certificate_details: CertificateDetails,
    pub credblob_file: PathBuf, //String,
    pub state: Arc<RwLock<HashMap<String, Credentials>>>,
    credential_loaded_from_file: AtomicBool,
}

impl CertManager {
    pub fn new(
        plugin_dir: PathBuf,
        blob_file: String,
        cert_details: &CertificateDetails,
    ) -> anyhow::Result<Self> {
        if !plugin_dir.exists() {
            fs::create_dir_all(&plugin_dir)?;
            log::info!("plugin dir created = {}", plugin_dir.display());
        }

        let cblob_file = plugin_dir.as_path().join(blob_file);

        // Initialize the credential manager
        Ok(Self {
            plugin_dir,
            certificate_details: cert_details.clone(),
            credblob_file: cblob_file,
            state: Arc::new(RwLock::new(HashMap::new())),
            credential_loaded_from_file: AtomicBool::new(false),
        })
    }

    async fn load_credentials(&self, key: &str) -> Option<Credentials> {
        // Check if the credential is not loaded. If not, load them
        if !self.credential_loaded_from_file.load(Ordering::SeqCst) {
            if let Err(e) = self.load_from_file(&self.credblob_file).await {
                log::warn!("Failed to load credentials from file: {}", e);
                return None;
            }

            // Update the flag, this is a one-time load until kbs restarts
            self.credential_loaded_from_file
                .store(true, Ordering::SeqCst);
        }

        // Return the item from hashmap
        let state = self.state.read().await;
        state.get(key).cloned()
    }

    async fn load_from_file(&self, path: &PathBuf) -> Result<()> {
        let data = tokio::fs::read_to_string(&path).await?;
        let deserialized: HashMap<String, Credentials> = serde_json::from_str(&data)?;
        let mut state = self.state.write().await;
        *state = deserialized;
        Ok(())
    }

    async fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let state = self.state.read().await;
        let serialized = serde_json::to_string(&*state)?;
        tokio::fs::write(path, serialized).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SplitAPIBackend for CertManager {
    async fn get_server_credential(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        // Return the server credential if the credential presents in the hashmap
        let key = format!("{}_{}_{}", &params.name, &params.ip, &params.id);
        if let Some(credentials) = self.load_credentials(&key).await {
            log::info!("Returning already existed credentials!");

            let resource = ServerCredentials {
                key: credentials.server_key,
                crt: credentials.server_crt,
                ca_crt: credentials.ca_crt,
            };

            return Ok(serde_json::to_vec(&resource)?);
        };

        // Generate the credentials (keys and certs for ca, server, and client)
        let credential_dir = tempdir_in(self.plugin_dir.as_path())?;
        let generator = CredentialGenerator::new(&credential_dir)?;
        let credentials = generator.generate(&self.certificate_details)?;

        log::info!("Credentials are generated!");

        // Aquire the write lock and write the credential into the hashmap
        {
            let mut state = self.state.write().await;
            state.insert(key, credentials.clone());
        }

        // Write the hashmap to file for a persistence copy
        self.save_to_file(&self.credblob_file).await?;

        // Return the server credentials to respond the request
        let resource = ServerCredentials {
            key: credentials.server_key.clone(),
            crt: credentials.server_crt.clone(),
            ca_crt: credentials.ca_crt.clone(),
        };

        Ok(serde_json::to_vec(&resource)?)
    }
}
