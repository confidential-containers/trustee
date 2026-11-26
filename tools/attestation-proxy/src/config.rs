// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kbs::token::AttestationTokenVerifierConfig;
use serde::Deserialize;
use url::{Host, Url};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    pub upstream_url: String,
    #[serde(default = "default_upstream_timeout_seconds")]
    pub upstream_timeout_seconds: u64,
    #[serde(default = "default_max_token_bytes")]
    pub max_token_bytes: usize,
    pub tls: Option<TlsConfig>,
    pub attestation: AttestationTokenVerifierConfig,
    pub policy: PolicyConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Upstream {
    pub address: SocketAddr,
    pub tls: bool,
    pub sni: String,
    pub host_header: String,
}

impl ProxyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let config = ::config::Config::builder()
            .add_source(::config::File::from(path.to_path_buf()).required(true))
            .build()
            .with_context(|| format!("failed to load configuration from {}", path.display()))?
            .try_deserialize::<Self>()
            .with_context(|| format!("invalid configuration in {}", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    fn upstream_url(&self) -> Result<Url> {
        Url::parse(&self.upstream_url).context("invalid upstream_url")
    }

    pub fn resolve_upstream(&self) -> Result<Upstream> {
        let url = self.upstream_url()?;
        let host = url.host().context("upstream_url has no host")?;
        let port = url
            .port_or_known_default()
            .context("upstream_url has no usable port")?;
        let address = (host.to_string(), port)
            .to_socket_addrs()
            .with_context(|| format!("failed to resolve upstream host {host}"))?
            .next()
            .with_context(|| format!("upstream host {host} resolved to no addresses"))?;
        let formatted_host = match &host {
            Host::Ipv6(address) => format!("[{address}]"),
            _ => host.to_string(),
        };
        let host_header = if url.port().is_some() {
            format!("{formatted_host}:{port}")
        } else {
            formatted_host
        };

        Ok(Upstream {
            address,
            tls: url.scheme() == "https",
            sni: host.to_string(),
            host_header,
        })
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_seconds)
    }

    fn validate(&self) -> Result<()> {
        let upstream = self.upstream_url()?;
        if !matches!(upstream.scheme(), "http" | "https") {
            bail!("upstream_url must use http or https");
        }
        if upstream.cannot_be_a_base()
            || upstream.host_str().is_none()
            || !upstream.username().is_empty()
            || upstream.password().is_some()
            || upstream.query().is_some()
            || upstream.fragment().is_some()
            || upstream.path() != "/"
        {
            bail!("upstream_url must contain only a scheme, host, and optional port");
        }
        if self.upstream_timeout_seconds == 0 || self.max_token_bytes == 0 {
            bail!("upstream_timeout_seconds and max_token_bytes must be greater than zero");
        }
        if self.attestation.insecure_header_jwk {
            tracing::warn!(
                "insecure_header_jwk is enabled; tokens signed by attacker-controlled keys can be accepted"
            );
        }
        Ok(())
    }
}

fn default_listen_address() -> String {
    "127.0.0.1:8081".to_string()
}

fn default_upstream_timeout_seconds() -> u64 {
    30
}

fn default_max_token_bytes() -> usize {
    64 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_unknown_attestation_fields() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("proxy.toml");
        std::fs::write(
            &path,
            r#"
                upstream_url = "http://localhost"
                [attestation]
                expected_issuer = "legacy"
                trusted_certs_paths = ["issuer.pem"]
                [policy]
                path = "policy.rego"
            "#,
        )?;
        let config = ProxyConfig::load(&path)?;
        assert_eq!(config.attestation.trusted_certs_paths, ["issuer.pem"]);
        Ok(())
    }
}
