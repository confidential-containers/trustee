// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::{ffi::OsString, sync::Arc};
use serde::Deserialize;

use super::manager;


pub const PLUGIN_NAME: &str = "splitapi";


/// Services supported by the SplitAPI plugin
#[async_trait::async_trait]
pub trait SplitAPIBackend: Send + Sync {
    /// Generate and obtain the credential for API Proxy server
    async fn get_server_credential(&self, params: &SandboxParams) -> Result<Vec<u8>>;
}

pub struct SplitAPI {
    pub backend: Arc<dyn SplitAPIBackend>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum SplitAPIConfig {
    CertManager(manager::SplitAPIRepoDesc),
}

impl Default for SplitAPIConfig {
    fn default() -> Self {
        Self::CertManager(manager::SplitAPIRepoDesc::default())
    }
}

impl TryFrom<SplitAPIConfig> for SplitAPI {
    type Error = anyhow::Error;

    fn try_from(config: SplitAPIConfig) -> anyhow::Result<Self> {
        match config {
            SplitAPIConfig::CertManager(desc) => {
                let backend = manager::CertManager::new(&desc)
                    .context("Failed to initialize Resource Storage")?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
        }
    }
}

/// Parameters taken by the "splitapi" plugin to store the certificates
/// generated for the sandbox by combining the IP address, sandbox name,
/// sandbox ID to create an unique directory for the sandbox
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct SandboxParams {
    pub id: String,
    pub ip: String,
    pub name: String,
}

impl From<&SandboxParams> for Vec<OsString> {
    fn from(params: &SandboxParams) -> Self {
        let mut v: Vec<OsString> = Vec::new();

        v.push("-id".into());
        v.push((&params.id).into());
        v.push("-name".into());
        v.push((&params.name).into());
        v.push("-ip".into());
        v.push((&params.ip.to_string()).into());

        v
    }
}
