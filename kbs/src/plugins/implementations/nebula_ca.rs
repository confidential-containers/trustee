// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Nebula CA plugin.
//!
//! This plugin calls the `nebula-cert` binary to provide some of its CA
//! functionalities for nodes (e.g. CoCo PODs or confidential VMs) that
//! want join an encrypted Nebula overlay network. More information can
//! be found in the [plugin](#kbs/docs/plugins/nebula_ca.md) documentation.
use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Error, Result};
use semver::{Version, VersionReq};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::tempdir_in;

use crate::plugins::plugin_manager::ClientPlugin;

/// Default Nebula CA name
const DEFAULT_NEBULA_CA_NAME: &str = "Trustee Nebula CA plugin";
/// By default we search `nebula-cert` in the $PATH.
const DEFAULT_NEBULA_CERT_PATH: &str = "nebula-cert";
/// Default Nebula CA working directory.
/// It must have read-write permission.
const DEFAULT_WORK_DIR: &str = "kbs/nebula-ca";
/// Minimum nebula-cert version required.
const NEBULA_CERT_VERSION_REQUIREMENT: &str = ">=1.9.5";

macro_rules! add_option_string_arg {
    ($args_vec:ident, $arg_name:literal, $arg_value:expr) => {
        if let Some(v) = $arg_value {
            $args_vec.extend_from_slice(&[$arg_name.into(), v.into()])
        }
    };
}

macro_rules! add_option_u32_arg {
    ($args_vec:ident, $arg_name:literal, $arg_value:expr) => {
        if let Some(v) = $arg_value {
            $args_vec.extend_from_slice(&[$arg_name.into(), v.to_string().into()])
        }
    };
}

/// Credential service parameters
///
/// They are provided in the request via URL query string. Only name and ip are required.
/// They match the "./nebula-cert sign <...>" parameters.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct NebulaCredentialParams {
    /// Required: name of the cert, usually hostname or podname
    name: String,
    /// Required: IPv4 address and network in CIDR notation to assign the cert
    ip: String,
    /// Optional: how long the cert should be valid for.
    /// The default is 1 second before the signing cert expires.
    /// Valid time units are seconds: "s", minutes: "m", hours: "h".
    duration: Option<String>,
    /// Optional: comma separated list of groups.
    groups: Option<String>,
    /// Optional: comma separated list of ipv4 address and network in CIDR notation.
    /// Subnets this cert can serve for
    subnets: Option<String>,
}

impl TryFrom<&str> for NebulaCredentialParams {
    type Error = Error;

    fn try_from(query: &str) -> Result<Self> {
        let params: NebulaCredentialParams = serde_qs::from_str(query)?;
        Ok(params)
    }
}

impl From<&NebulaCredentialParams> for Vec<OsString> {
    fn from(params: &NebulaCredentialParams) -> Self {
        let mut args: Vec<OsString> = vec![
            "-name".into(),
            params.name.as_str().into(),
            "-ip".into(),
            params.ip.as_str().into(),
        ];

        add_option_string_arg!(args, "-duration", &params.duration);
        add_option_string_arg!(args, "-groups", &params.groups);
        add_option_string_arg!(args, "-subnets", &params.subnets);

        args
    }
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
pub struct NebulaCaPluginConfig {
    work_dir: Option<String>,
    nebula_cert_bin_path: Option<String>,
    ca_config: Option<SelfSignedNebulaCaConfig>,
}

impl TryFrom<NebulaCaPluginConfig> for NebulaCaPlugin {
    type Error = Error;

    fn try_from(config: NebulaCaPluginConfig) -> Result<Self> {
        let work_dir = if let Some(config_work_dir) = config.work_dir {
            PathBuf::from(config_work_dir)
        } else {
            default_base_path.join(DEFAULT_WORK_DIR)
        };
        let path = PathBuf::from(
            config
                .nebula_cert_bin_path
                .unwrap_or(DEFAULT_NEBULA_CERT_PATH.into()),
        );
        let crt: PathBuf = work_dir.join("ca/ca.crt");
        let key: PathBuf = work_dir.join("ca/ca.key");

        let nebula = NebulaCertBin { path };

        // Check minimum nebula-cert version requirement
        let version: String = nebula.version_checked()?;
        log::info!("nebula-cert version: {}", version);

        if let Some(parent) = crt.as_path().parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Create {} dir", parent.display()))?;
        }

        // Create self-signed certificate authority
        if !crt.exists() && !key.exists() {
            nebula.ca(
                &config.ca_config.unwrap_or_default(),
                crt.as_path(),
                key.as_path(),
            )?;
            log::info!("Self-signed Nebula CA created");
        }

        // Check the provided or created Nebula CA exists.
        if !crt.exists() || !key.exists() {
            bail!("Nebula CA not found");
        }

        log::info!("Nebula CA key: {}", key.display());
        log::info!(
            "Nebula CA certificate: {}\n{}",
            crt.display(),
            nebula.print(&crt)?
        );

        Ok(NebulaCaPlugin {
            nebula,
            crt,
            key,
            work_dir,
        })
    }
}

/// Nebula CA configuration
///
/// These properties can be provided in the KBS config
/// under [plugins.self_signed_ca]. They are optional
/// and match the `nebula-cert ca <...>` parameters.
#[derive(Clone, Debug, Default, serde::Deserialize, PartialEq)]
struct SelfSignedNebulaCaConfig {
    /// Name of the certificate authority
    name: Option<String>,
    /// Argon2 iterations parameter used for encrypted private key passphrase
    argon_iterations: Option<u32>,
    /// Argon2 memory parameter (in KiB) used for encrypted private key passphrase
    argon_memory: Option<u32>,
    /// Argon2 parallelism parameter used for encrypted private key passphrase
    argon_parallelism: Option<u32>,
    /// EdDSA/ECDSA Curve (25519, P256)
    curve: Option<String>,
    /// Amount of time the certificate should be valid for. Valid time units are: <hours>"h"<minutes>"m"<seconds>"s"
    duration: Option<String>,
    /// Comma separated list of groups. This will limit which groups subordinate certs can use
    groups: Option<String>,
    /// Comma separated list of ipv4 address and network in CIDR notation.
    /// This will limit which ipv4 addresses and networks subordinate certs can use for ip addresses
    ips: Option<String>,
    /// Output a QR code image (png) of the certificate
    out_qr: Option<String>,
    /// Comma separated list of ipv4 address and network in CIDR notation.
    /// This will limit which ipv4 addresses and networks subordinate certs can use in subnets
    subnets: Option<String>,
}

impl From<&SelfSignedNebulaCaConfig> for Vec<OsString> {
    fn from(ca: &SelfSignedNebulaCaConfig) -> Self {
        let mut args: Vec<OsString> = Vec::new();

        // "-name" is required in the cmdline
        let name: String = ca
            .name
            .clone()
            .unwrap_or(DEFAULT_NEBULA_CA_NAME.to_string());
        args.extend_from_slice(&["-name".into(), name.into()]);

        add_option_u32_arg!(args, "-argon-iterations", &ca.argon_iterations);
        add_option_u32_arg!(args, "-argon-memory", &ca.argon_memory);
        add_option_u32_arg!(args, "-argon-parallelism", &ca.argon_parallelism);
        add_option_string_arg!(args, "-curve", &ca.curve);
        add_option_string_arg!(args, "-duration", &ca.duration);
        add_option_string_arg!(args, "-groups", &ca.groups);
        add_option_string_arg!(args, "-ips", &ca.ips);
        add_option_string_arg!(args, "-out-qr", &ca.out_qr);
        add_option_string_arg!(args, "-subnets", &ca.subnets);

        args
    }
}

#[derive(Debug)]
struct NebulaCertBin {
    path: PathBuf,
}

impl NebulaCertBin {
    /// Create self-signed certificate authority
    pub fn ca(&self, config: &SelfSignedNebulaCaConfig, crt: &Path, key: &Path) -> Result<()> {
        let mut args: Vec<OsString> = Vec::from(config);
        args.extend_from_slice(&["-out-crt".into(), crt.into(), "-out-key".into(), key.into()]);
        let mut cmd = Command::new(self.path.as_path());
        cmd.arg("ca").args(&args);
        let status = cmd
            .status()
            .context(format!("{} ca {:?}", self.path.display(), &args))?;
        if !status.success() {
            bail!("{} ca {:?}", self.path.display(), &args);
        }
        Ok(())
    }

    /// Print details about provided certificate
    pub fn print(&self, crt: &Path) -> Result<String> {
        let args: Vec<OsString> = vec!["-path".into(), crt.into()];
        let mut cmd = Command::new(self.path.as_path());
        cmd.arg("print").args(&args);
        let output = cmd
            .output()
            .context(format!("{} print {:?}", self.path.display(), &args))?;
        if !output.status.success() {
            bail!("{} print {:?}", self.path.display(), &args);
        }
        let cert_details = String::from_utf8(output.stdout)?;

        Ok(cert_details.trim_end().to_string())
    }

    /// Create and sign a certificate
    pub async fn sign(
        &self,
        params: &NebulaCredentialParams,
        ca_key: &Path,
        ca_crt: &Path,
        node_key: &Path,
        node_crt: &Path,
    ) -> Result<()> {
        let mut args: Vec<OsString> = Vec::from(params);
        args.extend_from_slice(&[
            "-ca-key".into(),
            ca_key.into(),
            "-ca-crt".into(),
            ca_crt.into(),
            "-out-key".into(),
            node_key.into(),
            "-out-crt".into(),
            node_crt.into(),
        ]);
        let mut cmd = tokio::process::Command::new(self.path.as_path());
        cmd.arg("sign").args(&args);
        let status =
            cmd.status()
                .await
                .context(format!("{} sign {:?}", self.path.display(), &args))?;
        if !status.success() {
            bail!("{} sign {:?}", self.path.display(), &args);
        }
        Ok(())
    }

    /// Verify if the node certificate isn't expired and was signed by the CA.
    pub async fn verify(&self, ca_crt: &Path, node_crt: &Path) -> Result<()> {
        let args: Vec<OsString> = vec!["-ca".into(), ca_crt.into(), "-crt".into(), node_crt.into()];
        let mut cmd = Command::new(self.path.as_path());
        cmd.arg("verify").args(&args);
        let status = cmd
            .status()
            .context(format!("{} verify {:?}", self.path.display(), &args))?;
        if !status.success() {
            bail!("{} verify {:?}", self.path.display(), &args);
        }
        Ok(())
    }

    // Get version
    pub fn version(&self) -> Result<String> {
        let output = Command::new(self.path.as_path())
            .arg("--version")
            .output()
            .context(format!("'{} --version' failed to run", self.path.display()))?;

        if !output.status.success() {
            bail!("'{} --version' failed to complete", self.path.display());
        }

        let version = String::from_utf8(output.stdout)?;

        Ok(version
            .strip_prefix("Version: ")
            .context("Failed to parse Nebula version")?
            .trim_end()
            .to_string())
    }

    /// Get version, but check if it satisfies the version requirements.
    pub fn version_checked(&self) -> Result<String> {
        let version = self.version()?;

        // Check if the version satisfies the requirements
        let version_req = VersionReq::parse(NEBULA_CERT_VERSION_REQUIREMENT)?;
        if !version_req.matches(&Version::parse(version.as_str())?) {
            bail!(
                "nebula-ca version requirement not satisfied: {} {}",
                version,
                NEBULA_CERT_VERSION_REQUIREMENT
            );
        }

        Ok(version)
    }
}

/// Credential service return type
#[derive(Debug, serde::Serialize)]
pub struct CredentialServiceOut {
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
    pub ca_crt: Vec<u8>,
}

/// Nebula CA plugin object
#[derive(Debug)]
pub struct NebulaCaPlugin {
    nebula: NebulaCertBin,
    key: PathBuf,
    crt: PathBuf,
    work_dir: PathBuf,
}

impl NebulaCaPlugin {
    pub async fn create_credential(
        &self,
        node_key: &Path,
        node_crt: &Path,
        params: &NebulaCredentialParams,
    ) -> Result<CredentialServiceOut> {
        // Create certificate and sign it
        self.nebula
            .sign(
                params,
                self.key.as_path(),
                self.crt.as_path(),
                node_key,
                node_crt,
            )
            .await
            .context("Failed to create credential")?;

        // Verify generated certificate
        self.nebula
            .verify(self.crt.as_path(), node_crt)
            .await
            .context("Failed to verify credential")?;

        let credential = CredentialServiceOut {
            node_crt: tokio::fs::read(node_crt)
                .await
                .context(format!("read {}", node_crt.display()))?,
            node_key: tokio::fs::read(node_key)
                .await
                .context(format!("read {}", node_key.display()))?,
            ca_crt: tokio::fs::read(self.crt.as_path())
                .await
                .context(format!("read {}", self.crt.display()))?,
        };

        Ok(credential)
    }
}

#[async_trait::async_trait]
impl ClientPlugin for NebulaCaPlugin {
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

        // The Nebula CA plugin is stateless, so none of request types below should
        // store state.
        match sub_path {
            // Create credential for the provided parameters.
            // The credential directory (and its files) is auto-deleted after the Credential is returned.
            "credential" => {
                let params = NebulaCredentialParams::try_from(query)?;

                let credential_dir = tempdir_in(self.work_dir.as_path())?;
                let node_key: PathBuf = credential_dir.path().to_owned().join("node.key");
                let node_crt: PathBuf = credential_dir.path().to_owned().join("node.crt");

                let credential = self
                    .create_credential(node_key.as_path(), node_crt.as_path(), &params)
                    .await?;

                Ok(serde_json::to_vec(&credential)?)
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
    use rstest::rstest;
    use std::ffi::OsString;

    use super::NebulaCredentialParams;

    #[rstest]
    #[case(
        "name=pod1&ip=1.2.3.4/21",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into()
        ])
    )]
    #[case(
        "name=pod1&ip=1.2.3.4",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4".into()
        ])
    )]
    #[case(
        "name=pod1&ip=1.2",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2".into()
        ])
    )]
    #[case("name=pod1", None)]
    #[case(
        "name=pod1&ip=1.2.3.4/21&duration=8760h10m10s",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into(),
            "-duration".into(),
            "8760h10m10s".into(),
        ])
    )]
    #[case(
        "name=pod1&ip=1.2.3.4/21&groups=server,ssh",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into(),
            "-groups".into(),
            "server,ssh".into(),
        ])
    )]
    #[case(
        "name=pod1&ip=1.2.3.4/21&subnets=1.2.3.5/21,1.2.3.6/21",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into(),
            "-subnets".into(),
            "1.2.3.5/21,1.2.3.6/21".into(),
        ])
    )]

    /// Take credential service parameters provided as a URL query string
    /// and convert them to parameters for `nebula-cert sign <params>`
    fn test_credential_service_params(
        #[case] query: &str,
        #[case] expected: Option<Vec<OsString>>,
    ) {
        let credential_params = NebulaCredentialParams::try_from(query);
        if expected.is_none() {
            assert!(credential_params.is_err())
        } else {
            let cmd_args: Vec<OsString> = Vec::from(&credential_params.unwrap());
            assert_eq!(cmd_args, expected.unwrap())
        }
    }
}
