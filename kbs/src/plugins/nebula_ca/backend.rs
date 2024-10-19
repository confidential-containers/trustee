// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::anyhow;
use std::{ffi::OsString, fmt, sync::Arc};

use crate::plugins::{error::Error, plugin_manager::ClientPlugin, ResourceError, Result};

use super::self_signed::{SelfSignedNebulaCa, SelfSignedNebulaCaConfig};

pub const PLUGIN_NAME: &str = "nebula_ca";

/// Services supported by the Nebula CA plugin
#[async_trait::async_trait]
pub trait NebulaCaBackend: Send + Sync {
    /// Generate a credential for nodes to join a nebula overlay network
    async fn generate_credential(&self, params: &NebulaCredentialParams) -> Result<Vec<u8>>;
}

pub struct NebulaCa {
    backend: Arc<dyn NebulaCaBackend>,
}

#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct Ipv4CidrList {
    list: Vec<Ipv4Cidr>,
}

impl fmt::Display for Ipv4CidrList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.list.iter().take(1) {
            write!(f, "{v}")?;
        }
        for v in self.list.iter().skip(1) {
            write!(f, ",{v}")?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, serde::Deserialize)]
struct Ipv4Cidr {
    ip: String,
    netbits: String,
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.netbits)
    }
}

/// "nebula-cert sign" parameters.
///
/// The sign command creates a credential for the node to join
/// a given Nebula overlay network. These parameters are
/// received as a query string in the URI
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct NebulaCredentialParams {
    /// Required: IPv4 address and network in CIDR notation to assign the cert
    ip: Ipv4Cidr,
    /// Required: name of the cert, usually hostname or podname
    name: String,
    /// Optional: how long the cert should be valid for.
    /// The default is 1 second before the signing cert expires.
    /// Valid time units are seconds: "s", minutes: "m", hours: "h".
    duration: Option<String>,
    /// Optional: comma separated list of groups.
    groups: Option<String>,
    /// Optional: comma separated list of ipv4 address and network in CIDR notation.
    /// Subnets this cert can serve for
    subnets: Option<Ipv4CidrList>,
}

impl From<&NebulaCredentialParams> for Vec<OsString> {
    fn from(params: &NebulaCredentialParams) -> Self {
        let mut args: Vec<OsString> = vec![
            "sign".into(),
            "-name".into(),
            params.name.as_str().into(),
            "-ip".into(),
            params.ip.to_string().into(),
        ];

        if let Some(value) = &params.duration {
            args.extend_from_slice(&["-duration".into(), value.into()]);
        }
        if let Some(value) = &params.groups {
            args.extend_from_slice(&["-groups".into(), value.into()]);
        }
        if let Some(value) = &params.subnets {
            args.extend_from_slice(&["-subnets".into(), value.to_string().into()]);
        }

        args
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub struct SelfSignedConfigPath {
    config_path: String,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(tag = "type")]
pub enum NebulaCaConfig {
    SelfSigned(SelfSignedConfigPath),
}

impl TryFrom<NebulaCaConfig> for NebulaCa {
    type Error = Error;

    fn try_from(config: NebulaCaConfig) -> Result<Self> {
        match config {
            NebulaCaConfig::SelfSigned(config_path) => {
                let self_signed_ca_config = SelfSignedNebulaCaConfig::try_from(
                    config_path.config_path.as_str(),
                )
                .map_err(|e| Error::InitializePluginFailed {
                    source: e.into(),
                    name: PLUGIN_NAME,
                })?;
                let backend = SelfSignedNebulaCa::try_from(self_signed_ca_config).map_err(|e| {
                    Error::InitializePluginFailed {
                        source: e.into(),
                        name: "nebula_ca",
                    }
                })?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
        }
    }
}

#[async_trait::async_trait]
impl ClientPlugin for NebulaCa {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        if method.as_str() != "GET" {
            return Err(Error::PluginHandlerError {
                source: ResourceError::IllegalHttpMethod.into(),
                plugin_name: "nebula_ca".to_string(),
            })?;
        }
        match path {
            "credential" => {
                let params: NebulaCredentialParams =
                    serde_qs::from_str(query).map_err(|e| Error::PluginHandlerError {
                        source: e.into(),
                        plugin_name: "nebula_ca".into(),
                    })?;
                let credential = self.backend.generate_credential(&params).await?;

                Ok(credential)
            }
            _ => Err(Error::PluginHandlerError {
                source: anyhow!("{} not supported", path),
                plugin_name: "nebula_ca".into(),
            })?,
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
