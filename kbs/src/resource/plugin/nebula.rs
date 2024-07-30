// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2024 by IBM Inc.

//! The nebula plugin allows the KBS to deliver resources required to create
//! an encrypted overlay network between nodes using [Nebula](https://github.com/slackhq/nebula),
//!
//! Within the Nebula overlay network, all communications between nodes are
//! automatically encrypted.

use anyhow::{anyhow, bail, Context, Result};
use serde_qs;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::{tempdir_in, TempDir};
use tokio::sync::RwLock;

use super::{Plugin, PluginBuild};

pub const PLUGIN_NAME: &str = "nebula";

const NEBULA_CONFIG_PATH: &str = "/etc/kbs/plugin/nebula-config.toml";
const CRT_FILENAME: &str = "node.crt";
const KEY_FILENAME: &str = "node.key";

// Required binaries must be in PATH
const NEBULA_CERT_BIN: &str = "nebula-cert";

/// Policies that define when a Nebula CA must be generated.
/// They are documented in the nebula plugin config toml file
#[repr(u32)]
pub enum CaGenerationPolicy {
    GenerateIfNotFound = 1,
    NeverGenerate = 2,
}

/// Plugin configuration
/// It is documented in the nebula plugin config toml file
#[derive(Debug, Default, serde::Deserialize)]
pub struct NebulaPluginConfig {
    crt_path: String,
    key_path: String,
    ca_generation_policy: u32,
    self_signed_ca_config: Option<SelfSignedCaConfig>,
}

impl PluginBuild for NebulaPluginConfig {
    fn get_plugin_name(&self) -> &str {
        PLUGIN_NAME
    }

    fn create_plugin(&self, work_dir: &str) -> Result<Arc<RwLock<dyn Plugin + Send + Sync>>> {
        let config = Self::try_from(Path::new(NEBULA_CONFIG_PATH))?;

        let ca = NebulaCa {
            crt: PathBuf::from(config.crt_path),
            key: PathBuf::from(config.key_path),
            work_dir: PathBuf::from(work_dir),
        };

        if let Some(parent) = ca.work_dir.as_path().parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Create {} dir", parent.display()))?;
        }

        match config.ca_generation_policy {
            x if x == CaGenerationPolicy::GenerateIfNotFound as u32 => {
                if !ca.crt.exists() || !ca.key.exists() {
                    // Clean-up in case the CA failed to generate last time
                    if ca.crt.exists() {
                        fs::remove_file(ca.crt.as_path())
                            .with_context(|| format!("Remove {} file", ca.crt.display()))?;
                    }
                    if ca.key.exists() {
                        fs::remove_file(ca.crt.as_path())
                            .with_context(|| format!("Remove {} file", ca.key.display()))?;
                    }
                    // Create directories if the CA is being created for the first time
                    if let Some(parent) = ca.crt.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("Create {} dir", parent.display()))?;
                    }
                    if let Some(parent) = ca.key.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("Create {} dir", parent.display()))?;
                    }

                    let ca_config = config.self_signed_ca_config.ok_or(anyhow!(
                        "self_signed_ca_config not found in {}",
                        NEBULA_CONFIG_PATH
                    ))?;

                    let mut params: Vec<OsString> = Vec::from(&ca_config);
                    params.push("-out-crt".into());
                    params.push(ca.crt.as_path().into());
                    params.push("-out-key".into());
                    params.push(ca.key.as_path().into());

                    let status = Command::new(NEBULA_CERT_BIN)
                        .args(params)
                        .status()
                        .context("nebula-cert ca run")?;

                    if !status.success() {
                        bail!("nebula-cert ca status");
                    }
                    log::info!("Nebula CA generated");
                } else {
                    log::info!("Nebula CA already exists, loading it")
                }
            }
            x if x == CaGenerationPolicy::NeverGenerate as u32 => {
                if !ca.crt.exists() || !ca.key.exists() {
                    bail!("Nebula CA not found");
                } else {
                    log::info!("Nebula CA found, loading it")
                }
            }
            x => {
                bail!("CaGenerationPolicy {x} not supported");
            }
        };

        log::info!("nebula-cert binary: {}", ca.get_version()?.trim());
        ca.test_all()?;

        Ok(Arc::new(RwLock::new(NebulaPlugin { ca })) as Arc<RwLock<dyn Plugin + Send + Sync>>)
    }
}

impl TryFrom<&Path> for NebulaPluginConfig {
    type Error = anyhow::Error;

    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        log::info!("Loading plugin config file {}", config_path.display());
        let config = config::Config::builder()
            .add_source(config::File::with_name(
                config_path
                    .to_str()
                    .expect("Nebula config path is not valid unicode"),
            ))
            .build()?;
        config
            .try_deserialize()
            .map_err(|e| anyhow!("invalid config: {}", e.to_string()))
    }
}

/// Configuration to generate a Nebula self signed CA. Further information
/// on these fields can be found running "nebula-cert ca --help", or
/// just looking at nebula plugin toml file.
#[derive(Debug, serde::Deserialize)]
struct SelfSignedCaConfig {
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

impl From<&SelfSignedCaConfig> for Vec<OsString> {
    fn from(config: &SelfSignedCaConfig) -> Self {
        let mut params: Vec<OsString> = Vec::new();

        params.push("ca".into());
        params.push("-name".into());
        params.push((&config.name).into());

        if let Some(value) = &config.argon_iterations {
            params.push("-argon-iterations".into());
            params.push(value.to_string().into());
        }
        if let Some(value) = &config.argon_memory {
            params.push("-argon-memory".into());
            params.push(value.to_string().into());
        }
        if let Some(value) = &config.argon_parallelism {
            params.push("-argon-parallelism".into());
            params.push(value.to_string().into());
        }
        if let Some(value) = &config.curve {
            params.push("-curve".into());
            params.push(value.into());
        }
        if let Some(value) = &config.duration {
            params.push("-duration".into());
            params.push(value.into());
        }
        if let Some(value) = &config.groups {
            params.push("-groups".into());
            params.push(value.into());
        }
        if let Some(value) = &config.ips {
            params.push("-ips".into());
            params.push(format!("{}", value).into());
        }
        if let Some(value) = &config.out_qr {
            params.push("-out-qr".into());
            params.push(value.into());
        }
        if let Some(value) = &config.subnets {
            params.push("-subnets".into());
            params.push(format!("{}", value).into());
        }

        params
    }
}

#[derive(Debug, PartialEq, serde::Deserialize)]
struct Ipv4CidrList {
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

/// Parameters taken by "nebula-cert sign" to create a credential
/// for a node to join a Nebula overlay network. These fields are
/// received as a query string in the get-resource URI
#[derive(Debug, PartialEq, serde::Deserialize)]
struct NebulaCredentialParams {
    /// Required: ipv4 address and network in CIDR notation to assign the cert
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
        let mut v: Vec<OsString> = Vec::new();

        v.push("sign".into());
        v.push("-name".into());
        v.push((&params.name).into());
        v.push("-ip".into());
        v.push((&params.ip.to_string()).into());

        if let Some(value) = &params.duration {
            v.push("-duration".into());
            v.push(value.into());
        }
        if let Some(value) = &params.groups {
            v.push("-groups".into());
            v.push(value.into());
        }
        if let Some(value) = &params.subnets {
            v.push("-subnets".into());
            v.push(value.to_string().into());
        }

        v
    }
}

#[derive(Debug, serde::Serialize)]
pub struct CredentialResource {
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
    pub ca_crt: Vec<u8>,
}

/// Credential for a Nebula overlay network
/// It is created in a temporary directory to prevent
/// the same file from being accessed by multiple threads
#[derive(Debug)]
struct Credential {
    _temp_dir: TempDir,
    crt: PathBuf,
    key: PathBuf,
}

impl Credential {
    pub fn new(work_dir: &Path) -> Result<Self> {
        let temp_dir = tempdir_in(work_dir)?;

        let crt: PathBuf = temp_dir.path().join(CRT_FILENAME);
        let key: PathBuf = temp_dir.path().join(KEY_FILENAME);

        Ok(Self {
            _temp_dir: temp_dir,
            crt,
            key,
        })
    }

    /// Run "nebula-cert sign" to generate a credential
    pub fn generate(
        &self,
        ca_key: &Path,
        ca_crt: &Path,
        params: &NebulaCredentialParams,
    ) -> Result<&Self> {
        let mut args: Vec<OsString> = Vec::from(params);

        args.push("-ca-key".into());
        args.push(ca_key.into());
        args.push("-ca-crt".into());
        args.push(ca_crt.into());
        args.push("-out-key".into());
        args.push(self.key.as_path().into());
        args.push("-out-crt".into());
        args.push(self.crt.as_path().into());

        let status = Command::new(NEBULA_CERT_BIN)
            .args(args)
            .status()
            .context("nebula-cert sign run")?;

        if !status.success() {
            bail!("nebula-cert sign status");
        }

        Ok(self)
    }
}

/// The temp_dir is auto-deleted when it goes out-of-scope, but before that
/// we need to delete the generated credential
impl Drop for Credential {
    fn drop(&mut self) {
        if self.crt.exists() {
            if let Err(e) = fs::remove_file(self.crt.as_path())
                .with_context(|| format!("Remove {} file", self.crt.display()))
            {
                log::warn!("{}", e.to_string());
            }
        }
        if self.key.exists() {
            if let Err(e) = fs::remove_file(self.key.as_path())
                .with_context(|| format!("Remove {} file", self.key.display()))
            {
                log::warn!("{}", e.to_string());
            }
        }
    }
}

/// Nebula Certificate Authority
#[derive(Debug, Default)]
struct NebulaCa {
    key: PathBuf,
    crt: PathBuf,
    work_dir: PathBuf,
}

impl NebulaCa {
    pub fn get_credential_resource(&self, params: &NebulaCredentialParams) -> Result<Vec<u8>> {
        let cred = Credential::new(self.work_dir.as_path())?;

        cred.generate(self.key.as_path(), self.crt.as_path(), params)?;

        let resource = CredentialResource {
            node_crt: fs::read(cred.crt.as_path())
                .with_context(|| format!("read {}", cred.crt.display()))?,
            node_key: fs::read(cred.key.as_path())
                .with_context(|| format!("read {}", cred.key.display()))?,
            ca_crt: fs::read(self.crt.as_path())
                .with_context(|| format!("read {}", self.crt.display()))?,
        };

        Ok(serde_json::to_vec(&resource)?)
    }

    pub fn get_version(&self) -> Result<String> {
        let output = Command::new(NEBULA_CERT_BIN).arg("--version").output()?;
        Ok(String::from_utf8(output.stdout)?)
    }

    pub fn test_all(&self) -> Result<()> {
        self.test_nebula_cert_sign()
    }

    pub fn test_nebula_cert_sign(&self) -> Result<()> {
        let params = NebulaCredentialParams {
            ip: Ipv4Cidr {
                ip: "10.10.10.10".to_string(),
                netbits: "21".to_string(),
            },
            name: "node-test".to_string(),
            duration: None,
            groups: None,
            subnets: None,
        };

        let _ = Credential::new(self.work_dir.as_path())?.generate(
            self.key.as_path(),
            self.crt.as_path(),
            &params,
        )?;

        Ok(())
    }
}

/// Nebula plugin
#[derive(Default, Debug)]
pub struct NebulaPlugin {
    ca: NebulaCa,
}

#[async_trait::async_trait]
impl Plugin for NebulaPlugin {
    async fn get_name(&self) -> &str {
        PLUGIN_NAME
    }

    async fn get_resource(&self, resource: &str, query_string: &str) -> Result<Vec<u8>> {
        let response: Vec<u8> = match resource {
            // plugin/nebula/credential?{query_string}
            // e.g. plugin/nebula/credential?ip[ip]=10.11.12.13&ip[netbits]=21&name=node1
            // the query_string will be used to generate the credential
            "credential" => {
                let params: NebulaCredentialParams = serde_qs::from_str(query_string)?;
                self.ca.get_credential_resource(&params)?
            }
            // resource not supported
            e => bail!("Nebula plugin resource {e} not supported"),
        };

        Ok(response)
    }
}
