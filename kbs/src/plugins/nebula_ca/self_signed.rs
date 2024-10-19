// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::plugins::{error::Error, Result};
use anyhow::{anyhow, Context};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir_in;

use super::backend::{NebulaCaBackend, NebulaCredentialParams, PLUGIN_NAME};

#[derive(Debug, serde::Deserialize)]
pub struct SelfSignedNebulaCaConfig {
    nebula_cert_bin_path: String,
    work_dir: String,
    settings: SelfSignedCaSettings,
}

impl TryFrom<SelfSignedNebulaCaConfig> for SelfSignedNebulaCa {
    type Error = Error;

    fn try_from(config: SelfSignedNebulaCaConfig) -> Result<Self> {
        let work_dir = PathBuf::from(config.work_dir);
        let crt = work_dir.join("ca/ca.crt");
        let key = work_dir.join("ca/ca.key");
        let binary = NebulaCertBin::try_from(config.nebula_cert_bin_path.as_str())?;

        let ca = SelfSignedNebulaCa {
            binary,
            crt,
            key,
            work_dir,
        };

        if let Some(parent) = ca.crt.as_path().parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Create {} dir", parent.display()))
                .map_err(|e| Error::InitializePluginFailed {
                    source: e,
                    name: PLUGIN_NAME,
                })?;
        }

        if !ca.crt.exists() && !ca.key.exists() {
            let mut args: Vec<OsString> = Vec::from(&config.settings);
            args.extend_from_slice(&[
                "-out-crt".into(),
                ca.crt.as_path().into(),
                "-out-key".into(),
                ca.key.as_path().into(),
            ]);
            ca.binary.do_ca(&args)?;
            log::info!("Nebula CA credential generated");
        }

        if !ca.crt.exists() || !ca.key.exists() {
            return Err(Error::InitializePluginFailed {
                source: anyhow!("Nebula CA can't be (re)used: certificate/key is missing"),
                name: PLUGIN_NAME,
            });
        }

        Ok(ca)
    }
}

impl TryFrom<&str> for SelfSignedNebulaCaConfig {
    type Error = Error;

    fn try_from(config_path: &str) -> Result<Self> {
        log::info!("Loading plugin config file {}", config_path);
        let config = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()
            .map_err(|e| Error::InitializePluginFailed {
                source: e.into(),
                name: PLUGIN_NAME,
            })?;
        let self_signed_ca_config =
            config
                .try_deserialize()
                .map_err(|e| Error::InitializePluginFailed {
                    source: e.into(),
                    name: PLUGIN_NAME,
                })?;

        Ok(self_signed_ca_config)
    }
}

/// "nebula-cert" binary parameters to generate a self signed CA.
/// Documentation: https://github.com/slackhq/nebula or "./nebula-cert ca --help"
#[derive(Debug, serde::Deserialize)]
struct SelfSignedCaSettings {
    name: String,
    argon_iterations: Option<u32>,
    argon_memory: Option<u32>,
    argon_parallelism: Option<u32>,
    curve: Option<String>,
    duration: Option<String>,
    groups: Option<String>,
    ips: Option<String>,
    out_qr: Option<String>,
    subnets: Option<String>,
}

impl From<&SelfSignedCaSettings> for Vec<OsString> {
    fn from(settings: &SelfSignedCaSettings) -> Self {
        let mut args: Vec<OsString> = vec!["-name".into(), settings.name.as_str().into()];
        if let Some(value) = &settings.argon_iterations {
            args.extend_from_slice(&["-argon-iterations".into(), value.to_string().into()]);
        }
        if let Some(value) = &settings.argon_memory {
            args.extend_from_slice(&["-argon-memory".into(), value.to_string().into()]);
        }
        if let Some(value) = &settings.argon_parallelism {
            args.extend_from_slice(&["-argon-parallelism".into(), value.to_string().into()]);
        }
        if let Some(value) = &settings.curve {
            args.extend_from_slice(&["-curve".into(), value.into()]);
        }
        if let Some(value) = &settings.duration {
            args.extend_from_slice(&["-duration".into(), value.into()]);
        }
        if let Some(value) = &settings.groups {
            args.extend_from_slice(&["-groups".into(), value.into()]);
        }
        if let Some(value) = &settings.ips {
            args.extend_from_slice(&["-ips".into(), value.into()]);
        }
        if let Some(value) = &settings.out_qr {
            args.extend_from_slice(&["-out-qr".into(), value.into()]);
        }
        if let Some(value) = &settings.subnets {
            args.extend_from_slice(&["-subnets".into(), value.into()]);
        }

        args
    }
}

#[derive(Debug)]
struct NebulaCertBin {
    path: PathBuf,
}

impl TryFrom<&str> for NebulaCertBin {
    type Error = Error;

    fn try_from(bin_path: &str) -> Result<Self> {
        let binary = NebulaCertBin {
            path: PathBuf::from(bin_path),
        };

        // Print version. It can also work as a simple test.
        log::info!("nebula-cert binary: {}", binary.do_version()?.trim());

        Ok(binary)
    }
}

impl NebulaCertBin {
    pub fn do_sign(&self, params: &Vec<OsString>) -> Result<()> {
        let status = Command::new(self.path.as_path())
            .arg("sign")
            .args(params)
            .status()
            .context(format!("'{} sign' failed to run", self.path.display()))
            .map_err(|e| Error::PluginHandlerError {
                source: e,
                plugin_name: PLUGIN_NAME.into(),
            })?;

        if !status.success() {
            Err(Error::PluginHandlerError {
                source: anyhow!("'{} sign' failed to complete", self.path.display()),
                plugin_name: PLUGIN_NAME.into(),
            })?;
        }

        Ok(())
    }

    pub fn do_ca(&self, params: &Vec<OsString>) -> Result<()> {
        let status = Command::new(self.path.as_path())
            .arg("ca")
            .args(params)
            .status()
            .context(format!("'{} ca' failed to run", self.path.display()))
            .map_err(|e| Error::InitializePluginFailed {
                source: e,
                name: PLUGIN_NAME,
            })?;

        if !status.success() {
            Err(Error::PluginHandlerError {
                source: anyhow!("'{} ca' failed to complete", self.path.display()),
                plugin_name: PLUGIN_NAME.into(),
            })?;
        }

        Ok(())
    }

    pub fn do_version(&self) -> Result<String> {
        let output = Command::new(self.path.as_path())
            .arg("--version")
            .output()
            .context(format!("'{} --version' failed to run", self.path.display()))
            .map_err(|e| Error::InitializePluginFailed {
                source: e,
                name: PLUGIN_NAME,
            })?;

        if !output.status.success() {
            Err(Error::PluginHandlerError {
                source: anyhow!("'{} --version' failed to complete", self.path.display()),
                plugin_name: PLUGIN_NAME.into(),
            })?;
        }

        let version_string =
            String::from_utf8(output.stdout).map_err(|e| Error::PluginHandlerError {
                source: e.into(),
                plugin_name: PLUGIN_NAME.into(),
            })?;

        Ok(version_string)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct Credential {
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
    pub ca_crt: Vec<u8>,
}

/// Nebula Certificate Authority
#[derive(Debug)]
pub struct SelfSignedNebulaCa {
    binary: NebulaCertBin,
    key: PathBuf,
    crt: PathBuf,
    work_dir: PathBuf,
}

impl SelfSignedNebulaCa {
    async fn load_credential_from_file(
        &self,
        node_key: &Path,
        node_crt: &Path,
    ) -> Result<Credential> {
        if !node_key.exists() {
            return Err(Error::PluginHandlerError {
                source: anyhow!("{} not found", node_key.display()),
                plugin_name: PLUGIN_NAME.into(),
            });
        }
        if !node_crt.exists() {
            return Err(Error::PluginHandlerError {
                source: anyhow!("{} not found", node_crt.display()),
                plugin_name: PLUGIN_NAME.into(),
            });
        }

        let read_file_as_bytes = |x: &Path| -> Result<Vec<u8>> {
            fs::read(x)
                .with_context(|| format!("read {}", x.display()))
                .map_err(|e| Error::PluginHandlerError {
                    source: e,
                    plugin_name: PLUGIN_NAME.into(),
                })
        };

        Ok(Credential {
            node_crt: read_file_as_bytes(node_crt)?,
            node_key: read_file_as_bytes(node_key)?,
            ca_crt: read_file_as_bytes(self.crt.as_path())?,
        })
    }
}

#[async_trait::async_trait]
impl NebulaCaBackend for SelfSignedNebulaCa {
    async fn generate_credential(&self, params: &NebulaCredentialParams) -> Result<Vec<u8>> {
        let temp_dir =
            tempdir_in(self.work_dir.as_path()).map_err(|e| Error::PluginHandlerError {
                source: e.into(),
                plugin_name: PLUGIN_NAME.into(),
            })?;
        let node_key: PathBuf = temp_dir.path().to_owned().join("node.key");
        let node_crt: PathBuf = temp_dir.path().to_owned().join("node.crt");

        let mut args: Vec<OsString> = Vec::from(params);
        args.extend_from_slice(&[
            "-ca-key".into(),
            self.key.as_path().into(),
            "-ca-crt".into(),
            self.crt.as_path().into(),
            "-out-key".into(),
            node_key.as_path().into(),
            "-out-crt".into(),
            node_crt.as_path().into(),
        ]);
        self.binary.do_sign(&args)?;

        let credential = self
            .load_credential_from_file(node_key.as_path(), node_crt.as_path())
            .await?;
        let credential_json =
            serde_json::to_vec(&credential).map_err(|e| Error::PluginHandlerError {
                source: e.into(),
                plugin_name: PLUGIN_NAME.into(),
            })?;

        Ok(credential_json)
    }
}
