// Copyright (c) 2026 by Trustee Contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! External gRPC plugin — configuration and gateway implementation.
//!
//! A single `ExternalPlugin` instance (registered as the built-in `external`
//! plugin) owns a map of gRPC backends. Requests arriving at
//! `/kbs/v0/external/<sub-name>/...` are routed by stripping `path[0]` as
//! the backend name and forwarding `path[1..]` to the matching backend.

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Error, Result};
use backon::{ExponentialBuilder, Retryable};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tracing::{debug, info, warn};

use crate::plugins::plugin_manager::ClientPlugin;
use crate::prometheus::{
    PLUGIN_ERRORS_TOTAL, PLUGIN_REQUESTS_TOTAL, PLUGIN_REQUEST_DURATION_SECONDS,
};

mod plugin_api {
    tonic::include_proto!("kbs.plugin.v1");
}

use plugin_api::{
    kbs_plugin_client::KbsPluginClient, NeedsEncryptionRequest, PluginRequest, ValidateAuthRequest,
};

/// TLS mode for the gRPC connection from KBS to the external plugin.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum TlsMode {
    /// Server-only TLS: client verifies server cert, no client cert.
    Tls { ca_cert_path: PathBuf },
    /// Plaintext: no encryption (development only, requires explicit opt-in).
    #[default]
    Insecure,
}

#[derive(Deserialize)]
struct BackendConfigRaw {
    name: String,
    endpoint: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    ca_cert_path: Option<PathBuf>,
}

impl TryFrom<BackendConfigRaw> for BackendConfig {
    type Error = anyhow::Error;

    fn try_from(raw: BackendConfigRaw) -> Result<Self, Self::Error> {
        let tls_mode = if raw.endpoint.starts_with("https://") {
            let ca_cert_path = raw.ca_cert_path.ok_or(anyhow!(
                "`https://` endpoint requires `ca_cert_path` (PEM file for server certificate verification)"
            ))?;
            TlsMode::Tls { ca_cert_path }
        } else if raw.endpoint.starts_with("http://") {
            TlsMode::Insecure
        } else {
            bail!("endpoint must start with `http://` or `https://`");
        };

        Ok(BackendConfig {
            name: raw.name,
            endpoint: raw.endpoint,
            tls_mode,
            timeout_ms: raw.timeout_ms,
        })
    }
}

impl<'de> serde::Deserialize<'de> for BackendConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        BackendConfigRaw::deserialize(deserializer)
            .and_then(|raw| raw.try_into().map_err(serde::de::Error::custom))
    }
}

/// Configuration for a single external gRPC backend.
#[derive(Clone, Debug, PartialEq)]
pub struct BackendConfig {
    /// Sub-plugin name used in URL routing: `/kbs/v0/external/<name>/...`
    pub name: String,
    /// gRPC endpoint URL, e.g. `https://127.0.0.1:50051` or `http://127.0.0.1:50051`
    pub endpoint: String,
    pub tls_mode: TlsMode,
    /// Request timeout in milliseconds. None means no timeout.
    pub timeout_ms: Option<u64>,
}

/// Top-level config for the `external` built-in plugin.
///
/// In `kbs.toml`:
/// ```toml
/// [[plugins]]
/// name = "external"
/// backends = [
///   { name = "my-plugin", endpoint = "http://127.0.0.1:50051", timeout_ms = 5000 },
///   { name = "secure-plugin", endpoint = "https://127.0.0.1:50052", ca_cert_path = "/etc/kbs/plugin-ca.pem", timeout_ms = 5000 },
/// ]
/// ```
///
/// For each backend, if `tls_mode` is omitted, TLS is implied by an `https://` endpoint
/// (and `ca_cert_path` is then required) and plaintext by `http://`. The explicit
/// `tls_mode` + `ca_cert_path` form remains supported.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ExternalPluginConfig {
    pub backends: Vec<BackendConfig>,
}

impl ExternalPluginConfig {
    /// Validate the config without opening any connections.
    ///
    /// Checks that the backends list is non-empty and that all backend names
    /// are unique. Individual backend endpoint/TLS consistency is validated
    /// by [`BackendConfig::validate`].
    fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            bail!("External plugin configured with no backends");
        }
        let mut seen = std::collections::HashSet::new();
        for backend in &self.backends {
            if !seen.insert(backend.name.clone()) {
                bail!(
                    "Duplicate backend name '{}' in external plugin config",
                    backend.name
                );
            }
        }
        Ok(())
    }
}

/// Initial delay before first retry on connection failure.
const RETRY_INITIAL_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum delay between retries.
const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(5);
/// Total cumulative sleep time before giving up.
const RETRY_MAX_ELAPSED: Duration = Duration::from_secs(30);

async fn connect_with_retry(config: &BackendConfig) -> Result<Channel> {
    // Validate the URI and apply TLS config once — these are deterministic
    // and do not need to be retried.
    let mut endpoint =
        Channel::from_shared(config.endpoint.clone()).context("Invalid plugin endpoint URI")?;
    if let TlsMode::Tls { ca_cert_path } = &config.tls_mode {
        let ca_cert = tokio::fs::read(ca_cert_path)
            .await
            .context("Read CA certificate")?;
        let ca_cert = Certificate::from_pem(&ca_cert);
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().ca_certificate(ca_cert))
            .context("Invalid TLS config")?;
    }

    (|| async { endpoint.clone().connect().await.map_err(Error::from) })
        .retry(
            ExponentialBuilder::default()
                .with_min_delay(RETRY_INITIAL_INTERVAL)
                .with_max_delay(RETRY_MAX_INTERVAL)
                .with_total_delay(Some(RETRY_MAX_ELAPSED))
                .without_max_times()
                .with_jitter(),
        )
        .notify(|err, dur| {
            debug!("Plugin connection attempt failed: {err}, retrying in {dur:?}...");
        })
        .await
        .context("Failed to connect to plugin after retry window")
}

fn map_grpc_error(status: tonic::Status) -> Error {
    debug!(
        "Plugin gRPC error: code={:?}, message={}",
        status.code(),
        status.message()
    );
    anyhow!("gRPC error from plugin: {:?}", status.code())
}

/// Per-backend gRPC connection and dispatch logic.
pub(crate) struct GrpcBackend {
    client: KbsPluginClient<Channel>,
    timeout: Option<Duration>,
    name: String,
}

impl std::fmt::Debug for GrpcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcBackend")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GrpcBackend {
    async fn new(config: &BackendConfig) -> Result<Self> {
        let channel = connect_with_retry(config)
            .await
            .context("Failed to connect to external plugin")?;
        let client = KbsPluginClient::new(channel);
        info!(
            "Connected to external plugin backend '{}' at {}",
            config.name, config.endpoint
        );
        Ok(Self {
            client,
            timeout: config.timeout_ms.map(Duration::from_millis),
            name: config.name.clone(),
        })
    }

    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        PLUGIN_REQUESTS_TOTAL.with_label_values(&[&self.name]).inc();
        let timer = PLUGIN_REQUEST_DURATION_SECONDS
            .with_label_values(&[&self.name])
            .start_timer();

        let mut client = self.client.clone();
        let mut request = tonic::Request::new(PluginRequest {
            body: body.to_vec(),
            query: query.clone(),
            path: path.iter().map(|s| s.to_string()).collect(),
            method: method.to_string(),
        });
        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }

        let result = client
            .handle(request)
            .await
            .inspect_err(|_| {
                PLUGIN_ERRORS_TOTAL.with_label_values(&[&self.name]).inc();
            })
            .map_err(map_grpc_error);

        timer.observe_duration();

        let response = result?.into_inner();

        // Status 0 (proto default/unset) and 2xx are treated as success.
        // Non-2xx non-zero codes are treated as errors.
        // gRPC-level errors (network, timeout, etc.) are handled by map_grpc_error above.
        match response.status_code {
            0 | 200..=299 => Ok(response.body),
            code => {
                bail!(
                    "plugin '{}' returned HTTP status {}: {}",
                    self.name,
                    code,
                    String::from_utf8_lossy(&response.body)
                )
            }
        }
    }

    async fn validate_auth(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(ValidateAuthRequest {
            body: body.to_vec(),
            query: query.clone(),
            path: path.iter().map(|s| s.to_string()).collect(),
            method: method.to_string(),
        });
        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }
        let response = client
            .validate_auth(request)
            .await
            .inspect_err(|_| {
                PLUGIN_ERRORS_TOTAL.with_label_values(&[&self.name]).inc();
            })
            .map_err(map_grpc_error)?;
        Ok(response.into_inner().requires_admin_auth)
    }

    async fn encrypted(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(NeedsEncryptionRequest {
            body: body.to_vec(),
            query: query.clone(),
            path: path.iter().map(|s| s.to_string()).collect(),
            method: method.to_string(),
        });
        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }
        let response = client
            .needs_encryption(request)
            .await
            .inspect_err(|_| {
                PLUGIN_ERRORS_TOTAL.with_label_values(&[&self.name]).inc();
            })
            .map_err(map_grpc_error)?;
        Ok(response.into_inner().requires_payload_encryption)
    }
}

/// Built-in `external` plugin — gateway to all configured gRPC backends.
///
/// Requests arriving at `/kbs/v0/external/<sub-name>/...` are dispatched
/// by `path[0]` (backend name). `path[1..]` is forwarded to the backend.
pub struct ExternalPlugin {
    backends: HashMap<String, Arc<GrpcBackend>>,
}

impl std::fmt::Debug for ExternalPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalPlugin")
            .field("backends", &self.backends.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ExternalPlugin {
    pub async fn new(config: ExternalPluginConfig) -> Result<Self> {
        config.validate()?;

        let mut backends = HashMap::new();
        for backend_cfg in config.backends {
            if backend_cfg.tls_mode == TlsMode::Insecure {
                warn!(
                    "External plugin backend '{}' configured with insecure mode (plaintext). \
                     This is ONLY safe for development. Never use in production.",
                    backend_cfg.name
                );
            }

            let name = backend_cfg.name.clone();
            let backend = GrpcBackend::new(&backend_cfg)
                .await
                .with_context(|| format!("Failed to initialise backend '{}'", name))?;
            backends.insert(name, Arc::new(backend));
        }
        Ok(Self { backends })
    }

    /// Look up the backend for `path[0]`, returning an error if absent.
    fn backend_for<'a>(&self, path: &'a [&str]) -> Result<(&Arc<GrpcBackend>, &'a [&'a str])> {
        let sub_name = path
            .first()
            .ok_or_else(|| anyhow!("external plugin name missing from request path"))?;
        let backend = self
            .backends
            .get(*sub_name)
            .ok_or_else(|| anyhow!("external plugin '{}' not registered", sub_name))?;
        Ok((backend, &path[1..]))
    }
}

#[async_trait::async_trait]
impl ClientPlugin for ExternalPlugin {
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        let (backend, sub_path) = self.backend_for(path)?;
        backend.handle(body, query, sub_path, method).await
    }

    async fn validate_auth(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        let (backend, sub_path) = self.backend_for(path)?;
        backend.validate_auth(body, query, sub_path, method).await
    }

    async fn encrypted(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        let (backend, sub_path) = self.backend_for(path)?;
        backend.encrypted(body, query, sub_path, method).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend(name: &str, tls_mode: TlsMode, endpoint: &str) -> BackendConfig {
        BackendConfig {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            tls_mode,
            timeout_ms: None,
        }
    }
    // --- ExternalPluginConfig validation ---

    #[test]
    fn empty_backends_rejected() {
        let cfg = ExternalPluginConfig { backends: vec![] };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("no backends"), "unexpected: {err}");
    }

    #[test]
    fn duplicate_backend_name_rejected() {
        let backend = make_backend("alpha", TlsMode::Insecure, "http://127.0.0.1:1");
        let cfg = ExternalPluginConfig {
            backends: vec![backend.clone(), backend],
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("Duplicate"), "unexpected: {err}");
    }

    #[test]
    fn backend_config_parses_tls_mode_with_parallel_ca_cert_path() {
        let input = r#"
name = "test"
endpoint = "https://127.0.0.1:50052"
tls_mode = "tls"
ca_cert_path = "/tmp/ca.pem"
timeout_ms = 5000
"#;

        let cfg: BackendConfig = toml::from_str(input).expect("failed to parse BackendConfig");
        assert_eq!(cfg.name, "test");
        assert_eq!(cfg.endpoint, "https://127.0.0.1:50052");
        assert_eq!(
            cfg.tls_mode,
            TlsMode::Tls {
                ca_cert_path: "/tmp/ca.pem".into()
            }
        );
        assert_eq!(cfg.timeout_ms, Some(5000));
    }

    #[test]
    fn backend_config_https_infers_tls_from_endpoint() {
        let input = r#"
name = "test"
endpoint = "https://127.0.0.1:50052"
ca_cert_path = "/tmp/ca.pem"
timeout_ms = 10
"#;

        let cfg: BackendConfig = toml::from_str(input).expect("failed to parse BackendConfig");
        assert_eq!(
            cfg.tls_mode,
            TlsMode::Tls {
                ca_cert_path: "/tmp/ca.pem".into()
            }
        );
        assert_eq!(cfg.timeout_ms, Some(10));
    }

    #[test]
    fn backend_config_parses_insecure_mode_without_ca_cert_path() {
        let input = r#"
name = "test"
endpoint = "http://127.0.0.1:50051"
tls_mode = "insecure"
timeout_ms = 5000
"#;

        let cfg: BackendConfig = toml::from_str(input).expect("failed to parse BackendConfig");
        assert_eq!(cfg.tls_mode, TlsMode::Insecure);
        assert_eq!(cfg.timeout_ms, Some(5000));
    }

    #[test]
    fn backend_config_http_infers_insecure_without_tls_mode() {
        let input = r#"
name = "test"
endpoint = "http://127.0.0.1:50051"
timeout_ms = 5000
"#;

        let cfg: BackendConfig = toml::from_str(input).expect("failed to parse BackendConfig");
        assert_eq!(cfg.tls_mode, TlsMode::Insecure);
    }

    #[test]
    fn backend_config_https_without_ca_cert_path_is_rejected() {
        let input = r#"
name = "test"
endpoint = "https://127.0.0.1:50051"
timeout_ms = 5000
"#;

        let err = toml::from_str::<BackendConfig>(input).unwrap_err();
        assert!(
            err.to_string().contains("ca_cert_path"),
            "unexpected: {err}"
        );
    }

    // --- ExternalPlugin::backend_for routing ---

    fn make_plugin_with_fake_backends() -> ExternalPlugin {
        // Build an ExternalPlugin directly without gRPC connections by
        // constructing GrpcBackend via the channel-less path is not possible
        // (GrpcBackend::new is async and requires a live server). We test the
        // routing logic indirectly through the HashMap: an ExternalPlugin
        // with no backends exercises the "missing from path" and "not
        // registered" error arms.
        ExternalPlugin {
            backends: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn backend_for_empty_path_errors() {
        let plugin = make_plugin_with_fake_backends();
        let err = plugin.backend_for(&[]).unwrap_err();
        assert!(
            err.to_string().contains("missing from request path"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn backend_for_unknown_backend_errors() {
        let plugin = make_plugin_with_fake_backends();
        let err = plugin.backend_for(&["unknown"]).unwrap_err();
        assert!(
            err.to_string().contains("not registered"),
            "unexpected: {err}"
        );
    }
}
