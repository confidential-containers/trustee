// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};

use super::generator::CertificateDetails;
use super::manager;

pub const CREDENTIALS_BLOB_FILE: &str = "certificates.json";

/// Services supported by the SplitAPI plugin
#[async_trait::async_trait]
pub trait SplitAPIBackend: Send + Sync {
    /// Returns credentials for API Proxy server, generates if not exist
    async fn get_server_credential(&self, params: &SandboxParams) -> Result<Vec<u8>>;
}

pub struct SplitAPI {
    pub backend: Arc<dyn SplitAPIBackend>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub struct SplitAPIConfig {
    pub plugin_dir: String,
    #[serde(default)]
    pub credential_blob_filename: String,
    #[serde(default)]
    pub certificate_details: CertificateDetails,
}

impl Default for SplitAPIConfig {
    fn default() -> Self {
        Self {
            plugin_dir: String::from(""),
            credential_blob_filename: CREDENTIALS_BLOB_FILE.into(),
            certificate_details: CertificateDetails::default(),
        }
    }
}

impl TryFrom<SplitAPIConfig> for SplitAPI {
    type Error = anyhow::Error;

    fn try_from(config: SplitAPIConfig) -> anyhow::Result<Self> {
        let backend = manager::CertManager::new(
            PathBuf::from(&config.plugin_dir),
            config.credential_blob_filename,
            &config.certificate_details,
        )?;

        Ok(Self {
            backend: Arc::new(backend),
        })
    }
}

/// Parameters for the credential request
///
/// These parameters are provided in the request via URL query string.
/// Parameters taken by the "splitapi" plugin to generate a unique key
/// for a sandbox store and retrieve credentials specific to the sandbox.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct SandboxParams {
    /// Required: ID of a sandbox or pod
    pub id: String,
    // Required: IP of a sandbox or pod
    pub ip: String,
    // Required: name of a sandbox or pod
    pub name: String,
}

impl TryFrom<&str> for SandboxParams {
    type Error = anyhow::Error;

    fn try_from(query: &str) -> Result<Self> {
        let params: SandboxParams = serde_qs::from_str(query)?;
        Ok(params)
    }
}
