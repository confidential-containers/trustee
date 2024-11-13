// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use std::{sync::Arc};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};
use std::sync::Mutex;
use lazy_static::lazy_static;

use super::backend::{SplitAPIBackend, SandboxParams};
use super::mapper::{SandboxDirectoryMapper, SandboxDirectoryInfo};
use super::generator::{CredentialBundle, ServerCredential};


pub const DEFAULT_PLUGIN_DIR: &str = "/opt/confidential-containers/kbs/plugin/splitapi";
pub const SANDBOX_DIRECTORY_MAPPING_FILENAME: &str = "sandbox-credential-mapping.json";


// Use lazy_static to initialize the SANDBOX_DIRECTORY_MANAGER only once
lazy_static! {
    static ref SANDBOX_DIRECTORY_MAPPER: Arc<Mutex<Option<SandboxDirectoryMapper>>> = Arc::new(Mutex::new(None));
}

// Initialize the singleton with the provided file path
fn init_sandbox_directory_mapper(file_path: PathBuf) -> std::io::Result<()> {
    let mut mapper = SANDBOX_DIRECTORY_MAPPER.lock().unwrap();
    
    // Attempt to load the DirectoryManager from the file
    match SandboxDirectoryMapper::load_from_file(file_path) {
        Ok(loaded_mapper) => {
            *mapper = Some(loaded_mapper);
        }
        Err(_e) => {
            // Initialize a new manager
            *mapper = Some(SandboxDirectoryMapper::new());

            // TODO: check specific errors (file not found or something else) 
            // and handle those specific errors
            // bail if there's relevant condition
        }
    }

    Ok(())
}

// Get a reference to the singleton
fn get_sandbox_directory_mapper() -> Arc<Mutex<Option<SandboxDirectoryMapper>>> {
    Arc::clone(&SANDBOX_DIRECTORY_MAPPER)
}


#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SplitAPIRepoDesc {
    #[serde(default)]
    pub plugin_dir: String,
}

impl Default for SplitAPIRepoDesc {
    fn default() -> Self {
        Self {
            plugin_dir: DEFAULT_PLUGIN_DIR.into(),
        }
    }
}


pub struct CertManager {
    pub plugin_dir: String,
    pub mapping_filename: String,
    mapper: Arc<Mutex<Option<SandboxDirectoryMapper>>>,
}


impl CertManager {
    pub fn new(repo_desc: &SplitAPIRepoDesc) -> anyhow::Result<Self> {
        // Create splitapi_res work dir.
        if !Path::new(&repo_desc.plugin_dir).exists() {
            fs::create_dir_all(&repo_desc.plugin_dir)?;

            log::info!("Splitapi plugin directory created = {}", repo_desc.plugin_dir);
        }

        // Initialize directory manager with the content from a file
        let mapping_file: PathBuf = PathBuf::from(&repo_desc.plugin_dir)
            .as_path()
            .join(SANDBOX_DIRECTORY_MAPPING_FILENAME
        );
        init_sandbox_directory_mapper(mapping_file.clone())?;
        log::info!("Directory manager loaded the data from file: {}", mapping_file.display());

        // Initialize the manager
        Ok(Self {
            plugin_dir: repo_desc.plugin_dir.clone(),
            mapping_filename: SANDBOX_DIRECTORY_MAPPING_FILENAME.into(),
            mapper: get_sandbox_directory_mapper(),
        })
    }
}

#[async_trait::async_trait]
impl SplitAPIBackend for CertManager {
    async fn get_server_credential(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        // Try locking the sandbox directory mapper
        let mut mapper_guard = self.mapper.lock().map_err(|e| {
            anyhow!("Failed to lock sandbox directory mapper: {}", e)
        })?;

        if let Some(mapper) = mapper_guard.as_mut() {
            let sandbox_dir_info: SandboxDirectoryInfo;

            if let Some(existing_dir) = mapper.get_directory(&params.name) {
            
                log::info!("Found existing directory: {:?}", existing_dir.sandbox_dir());
                sandbox_dir_info = existing_dir.clone();

                //TODO: check if the credentails are already in there
                // send the existing credentials if they are not expired
            } else {
                let new_dir_info = mapper.create_directory(
                    Path::new(&self.plugin_dir), 
                    &params
                )?;
                log::info!("New directory created: {:?}", new_dir_info);
                
                let mapping_file = PathBuf::from(&self.plugin_dir)
                    .as_path()
                    .join(&self.mapping_filename);

                mapper.write_to_file(
                    &new_dir_info, 
                    &mapping_file
                )?;
            
                sandbox_dir_info = new_dir_info;
            }

            // Generate the credentials (keys and certs for ca, server, and client)
            let cred_bundle = CredentialBundle::new(sandbox_dir_info.sandbox_dir())?;
            cred_bundle.generate(params)?;

            // Return the server specific credentials
            let resource = ServerCredential {
                key: fs::read(cred_bundle.server_key().as_path())
                    .with_context(|| format!("read {}", cred_bundle.server_key().display()))?,
                crt: fs::read(cred_bundle.server_crt().as_path())
                    .with_context(|| format!("read {}", cred_bundle.server_crt().display()))?,
                ca_crt: fs::read(cred_bundle.ca_crt().as_path())
                    .with_context(|| format!("read {}", cred_bundle.ca_crt().display()))?,
            };
    
            Ok(serde_json::to_vec(&resource)?)

        } else {
            // Handle the case where the manager is None
            Err(anyhow!("Directory manager is uninitialized"))
        }
    }
}