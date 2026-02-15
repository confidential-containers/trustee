// Copyright (c) 2026 by Trustee Contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! External gRPC plugin — configuration and proxy implementation.
//!
//! This module contains the configuration types ([`TlsMode`], [`ExternalPluginConfig`])
//! and the gRPC forwarding proxy ([`GrpcPluginProxy`]) for external KBS plugins.

use actix_web::http::Method;
use anyhow::{Context, Result};
use async_trait::async_trait;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use mobc::{Manager, Pool};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;
use tracing::{debug, info, warn};

use crate::error::PluginCallError;
use crate::plugins::plugin_manager::{PluginContext, PluginOutput};
use plugin_api::{
    kbs_plugin_client::KbsPluginClient, GetCapabilitiesRequest, NeedsEncryptionRequest,
    PluginRequest, ValidateAuthRequest,
};

mod plugin_api {
    tonic::include_proto!("kbs.plugin.v1");
}
use crate::prometheus::{
    PLUGIN_ERRORS_TOTAL, PLUGIN_REQUESTS_TOTAL, PLUGIN_REQUEST_DURATION_SECONDS,
};

/// Built-in KBS route prefixes that external plugins must not shadow.
/// The `api_server.rs` match arms guard specific (name, method) pairs, but
/// other methods or unguarded combinations fall through to plugin lookup.
/// Rejecting these names at startup prevents silent misbehaviour.
pub(crate) const RESERVED_PLUGIN_NAMES: &[&str] = &[
    "auth",
    "attest",
    "attestation-policy",
    "reference-value",
    "resource-policy",
];

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Mutual TLS: both client and server authenticate with certificates
    Mtls,
    /// Server-only TLS: client verifies server cert, no client cert
    Tls,
    /// Plaintext: no encryption (development only, requires explicit opt-in)
    Insecure,
}

impl TlsMode {
    pub fn requires_client_cert(&self) -> bool {
        matches!(self, TlsMode::Mtls)
    }

    pub fn is_insecure(&self) -> bool {
        matches!(self, TlsMode::Insecure)
    }
}

impl Default for TlsMode {
    fn default() -> Self {
        // Secure-by-default: external plugins are a new feature with no existing
        // configs to preserve, so omitting tls_mode should require a CA cert
        // rather than silently falling back to plaintext.
        TlsMode::Tls
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ExternalPluginConfig {
    pub plugin_name: String,
    pub endpoint: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,

    // TLS configuration fields
    #[serde(default)]
    pub tls_mode: TlsMode,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,
}

impl ExternalPluginConfig {
    /// Validate TLS configuration at startup.
    /// Ensures endpoint scheme matches TLS mode and required cert paths are present.
    pub fn validate_tls_config(&self) -> anyhow::Result<()> {
        let is_https = self.endpoint.starts_with("https://");
        let is_http = self.endpoint.starts_with("http://");

        // Validate scheme matches TLS mode
        match (&self.tls_mode, is_https, is_http) {
            (TlsMode::Insecure, false, true) => Ok(()),
            (TlsMode::Insecure, true, false) => {
                anyhow::bail!(
                    "Plugin '{}': insecure mode requires http:// endpoint, got https://",
                    self.plugin_name
                )
            }
            (TlsMode::Tls | TlsMode::Mtls, true, false) => {
                self.validate_tls_paths()?;
                Ok(())
            }
            (TlsMode::Tls | TlsMode::Mtls, false, true) => {
                anyhow::bail!(
                    "Plugin '{}': TLS mode requires https:// endpoint, got http://",
                    self.plugin_name
                )
            }
            _ => anyhow::bail!(
                "Plugin '{}': endpoint must be http:// or https://",
                self.plugin_name
            ),
        }
    }

    fn validate_tls_paths(&self) -> anyhow::Result<()> {
        match &self.tls_mode {
            TlsMode::Mtls => {
                if self.ca_cert_path.is_none() {
                    anyhow::bail!(
                        "Plugin '{}': mtls mode requires ca_cert_path",
                        self.plugin_name
                    );
                }
                if self.client_cert_path.is_none() || self.client_key_path.is_none() {
                    anyhow::bail!(
                        "Plugin '{}': mtls mode requires client_cert_path and client_key_path",
                        self.plugin_name
                    );
                }
            }
            TlsMode::Tls => {
                if self.ca_cert_path.is_none() {
                    anyhow::bail!(
                        "Plugin '{}': tls mode requires ca_cert_path",
                        self.plugin_name
                    );
                }
            }
            TlsMode::Insecure => {}
        }
        Ok(())
    }
}

/// Maximum open gRPC connections to the plugin per KBS instance.
/// Sized to handle bursts of concurrent attestation requests without
/// creating per-request connection overhead.
const DEFAULT_POOL_SIZE: u64 = 100;

/// gRPC health check service name for the KBS plugin protocol.
/// Must match the service name registered by the plugin's health server.
const PLUGIN_HEALTH_SERVICE: &str = "kbs.plugin.v1.KbsPlugin";

/// Interval between background health check probes.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Timeout for health check RPCs (initial and periodic).
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Initial delay before first retry on connection failure.
const RETRY_INITIAL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum delay between retries.
const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(5);

/// Total time window for connection retries before giving up.
const RETRY_MAX_ELAPSED: Duration = Duration::from_secs(30);

/// Jitter factor (+/-) to prevent thundering herd on retries.
const RETRY_RANDOMIZATION_FACTOR: f64 = 0.1;

/// Plugin health state tracked via background health monitor.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PluginState {
    Healthy,
    Unavailable,
}

pub(crate) struct GrpcPluginProxy {
    pool: Pool<PluginGrpcManager>,
    timeout: Option<Duration>,
    config: ExternalPluginConfig,
    state: Arc<RwLock<PluginState>>,
    _health_task: JoinHandle<()>,
    supported_methods: Vec<String>,
}

impl std::fmt::Debug for GrpcPluginProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcPluginProxy")
            .field("plugin_name", &self.config.plugin_name)
            .field("endpoint", &self.config.endpoint)
            .field("timeout", &self.timeout)
            .field(
                "state",
                &*self.state.read().unwrap_or_else(|e| e.into_inner()),
            )
            .finish_non_exhaustive()
    }
}

impl GrpcPluginProxy {
    pub async fn new(config: ExternalPluginConfig) -> Result<Self> {
        // Create state before the pool manager so the manager can check it in
        // Manager::check() — discarding pooled connections when the plugin is
        // known-unavailable rather than opening a fresh channel to probe.
        let state = Arc::new(RwLock::new(PluginState::Healthy));

        let manager = PluginGrpcManager {
            endpoint: config.endpoint.clone(),
            tls_mode: config.tls_mode.clone(),
            ca_cert_path: config.ca_cert_path.clone(),
            client_cert_path: config.client_cert_path.clone(),
            client_key_path: config.client_key_path.clone(),
            state: state.clone(),
        };
        let pool = Pool::builder().max_open(DEFAULT_POOL_SIZE).build(manager);

        let mut client = pool
            .get()
            .await
            .context("Failed to connect to external plugin")?;

        let caps_request = tonic::Request::new(GetCapabilitiesRequest {});
        let caps_response = client
            .get_capabilities(caps_request)
            .await
            .context("Failed to get plugin capabilities")?
            .into_inner();

        let supported_methods = caps_response.supported_methods.clone();

        info!(
            "Connected to external plugin '{}' (version {}, endpoint {})",
            caps_response.name, caps_response.version, config.endpoint
        );

        if caps_response.name != config.plugin_name {
            warn!(
                "Plugin name mismatch: KBS config registers '{}' but plugin reports '{}'. \
                 Requests will be routed using the config name. Update the config or plugin \
                 binary to align the names.",
                config.plugin_name, caps_response.name
            );
        }

        if !supported_methods.is_empty() {
            info!(
                "Plugin '{}' supports HTTP methods: {:?}",
                caps_response.name, supported_methods
            );
        }

        // Initial health check
        let health_channel = create_channel(&config)
            .await
            .context("Failed to create channel for initial health check")?;
        check_health(health_channel, HEALTH_CHECK_TIMEOUT)
            .await
            .context("Plugin failed initial health check")?;

        // Start background health monitoring
        let health_task = tokio::spawn(Self::health_monitor(
            config.clone(),
            state.clone(),
            config.plugin_name.clone(),
        ));

        let timeout = config.timeout_ms.map(Duration::from_millis);

        Ok(Self {
            pool,
            timeout,
            config,
            state,
            _health_task: health_task,
            supported_methods,
        })
    }

    /// Background task that periodically checks plugin health and updates state.
    /// Runs every 10 seconds for the lifetime of the proxy.
    async fn health_monitor(
        config: ExternalPluginConfig,
        state: Arc<RwLock<PluginState>>,
        name: String,
    ) {
        let mut interval = interval(HEALTH_CHECK_INTERVAL);
        interval.tick().await; // First tick completes immediately

        loop {
            interval.tick().await;

            let health_ok = match create_channel(&config).await {
                Ok(channel) => check_health(channel, HEALTH_CHECK_TIMEOUT).await.is_ok(),
                Err(e) => {
                    debug!("Plugin '{}' channel error during health check: {}", name, e);
                    false
                }
            };

            let mut state_guard = state.write().expect("invariant: state lock not poisoned");
            match (&*state_guard, health_ok) {
                (PluginState::Healthy, false) => {
                    warn!("Plugin '{}' became unavailable", name);
                    *state_guard = PluginState::Unavailable;
                }
                (PluginState::Unavailable, true) => {
                    info!("Plugin '{}' recovered", name);
                    *state_guard = PluginState::Healthy;
                }
                _ => {} // No state change
            }
        }
    }
}

/// Build a `ClientTlsConfig` from the plugin's TLS settings.
/// Returns `None` for insecure mode, `Some(config)` for TLS/mTLS.
async fn build_tls_config(
    tls_mode: &TlsMode,
    ca_cert_path: &Option<PathBuf>,
    client_cert_path: &Option<PathBuf>,
    client_key_path: &Option<PathBuf>,
) -> Result<Option<ClientTlsConfig>> {
    match tls_mode {
        TlsMode::Mtls => {
            let ca_cert = tokio::fs::read(
                ca_cert_path
                    .as_ref()
                    .context("ca_cert_path required for mTLS")?,
            )
            .await
            .context("Read CA certificate")?;
            let client_cert = tokio::fs::read(
                client_cert_path
                    .as_ref()
                    .context("client_cert_path required for mTLS")?,
            )
            .await
            .context("Read client certificate")?;
            let client_key = tokio::fs::read(
                client_key_path
                    .as_ref()
                    .context("client_key_path required for mTLS")?,
            )
            .await
            .context("Read client key")?;

            let tls_config = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(&ca_cert))
                .identity(Identity::from_pem(&client_cert, &client_key));

            Ok(Some(tls_config))
        }
        TlsMode::Tls => {
            let ca_cert = tokio::fs::read(
                ca_cert_path
                    .as_ref()
                    .context("ca_cert_path required for TLS")?,
            )
            .await
            .context("Read CA certificate")?;

            let tls_config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_cert));

            Ok(Some(tls_config))
        }
        TlsMode::Insecure => Ok(None),
    }
}

/// Create a gRPC channel to the plugin endpoint with appropriate TLS configuration.
async fn create_channel(config: &ExternalPluginConfig) -> Result<Channel> {
    let mut channel = Channel::from_shared(config.endpoint.clone())?;

    if let Some(tls) = build_tls_config(
        &config.tls_mode,
        &config.ca_cert_path,
        &config.client_cert_path,
        &config.client_key_path,
    )
    .await?
    {
        channel = channel.tls_config(tls)?;
    }

    channel
        .connect()
        .await
        .context("Connect to plugin gRPC endpoint")
}

/// Check plugin health using grpc.health.v1.Health/Check RPC.
/// Returns Ok(()) if plugin is serving, Err otherwise.
async fn check_health(channel: Channel, timeout: Duration) -> Result<()> {
    let mut client = HealthClient::new(channel);
    let mut request = tonic::Request::new(HealthCheckRequest {
        service: PLUGIN_HEALTH_SERVICE.to_string(),
    });
    request.set_timeout(timeout);

    let response = client
        .check(request)
        .await
        .context("Health check RPC failed")?;

    if response.into_inner().status == ServingStatus::Serving as i32 {
        Ok(())
    } else {
        anyhow::bail!("Plugin not serving")
    }
}

#[derive(Debug)]
pub(crate) struct PluginGrpcManager {
    endpoint: String,
    tls_mode: TlsMode,
    ca_cert_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
    client_key_path: Option<PathBuf>,
    /// Shared health state from the background monitor. Used in `check()` to
    /// discard pooled connections immediately when the plugin is unavailable,
    /// without opening a new probe connection.
    state: Arc<RwLock<PluginState>>,
}

#[async_trait]
impl Manager for PluginGrpcManager {
    type Connection = KbsPluginClient<Channel>;
    type Error = anyhow::Error;

    async fn connect(&self) -> Result<Self::Connection> {
        let endpoint = self.endpoint.clone();
        let tls_mode = self.tls_mode.clone();
        let ca_cert_path = self.ca_cert_path.clone();
        let client_cert_path = self.client_cert_path.clone();
        let client_key_path = self.client_key_path.clone();

        let operation = || async {
            let mut channel = Channel::from_shared(endpoint.clone())
                .map_err(|e| BackoffError::Permanent(anyhow::Error::from(e)))?;

            // Apply TLS config (permanent errors - config issues don't retry)
            if let Some(tls) = build_tls_config(
                &tls_mode,
                &ca_cert_path,
                &client_cert_path,
                &client_key_path,
            )
            .await
            .map_err(|e| BackoffError::Permanent(e))?
            {
                channel = channel
                    .tls_config(tls)
                    .map_err(|e| BackoffError::Permanent(anyhow::Error::from(e)))?;
            }

            // Connection attempt - transient errors trigger retry
            channel.connect().await.map_err(|e| {
                debug!("Plugin connection attempt failed: {}, retrying...", e);
                BackoffError::transient(anyhow::Error::from(e))
            })
        };

        let backoff = ExponentialBackoff {
            initial_interval: RETRY_INITIAL_INTERVAL,
            max_interval: RETRY_MAX_INTERVAL,
            max_elapsed_time: Some(RETRY_MAX_ELAPSED),
            multiplier: 2.0,
            randomization_factor: RETRY_RANDOMIZATION_FACTOR,
            ..Default::default()
        };

        let channel = retry(backoff, operation)
            .await
            .context("Failed to connect to plugin after retry window")?;
        Ok(KbsPluginClient::new(channel))
    }

    async fn check(&self, conn: Self::Connection) -> Result<Self::Connection> {
        // Delegate availability to the background health monitor rather than
        // opening a fresh probe connection (which would validate a new channel,
        // not the pooled `conn` being returned). If the monitor has marked the
        // plugin unavailable, discard this connection so mobc creates a fresh
        // one when the plugin recovers; otherwise pass it through unchanged.
        let state = self
            .state
            .read()
            .expect("invariant: state lock not poisoned");
        if matches!(*state, PluginState::Unavailable) {
            anyhow::bail!("plugin unavailable, discarding pooled connection");
        }
        Ok(conn)
    }
}

impl GrpcPluginProxy {
    pub async fn handle_with_context(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        context: &PluginContext,
    ) -> Result<PluginOutput> {
        // Check plugin state before attempting request
        {
            let state = self
                .state
                .read()
                .expect("invariant: state lock not poisoned");
            if matches!(*state, PluginState::Unavailable) {
                anyhow::bail!(
                    "Plugin '{}' is unavailable (health check failing)",
                    self.config.plugin_name
                );
            }
        }

        // Enforce method allowlist from capabilities
        if !self.supported_methods.is_empty() {
            let m = method.to_string();
            if !self.supported_methods.contains(&m) {
                return Err(anyhow::Error::new(PluginCallError {
                    http_status: 405,
                    message: format!(
                        "Method {} not allowed (plugin supports: {:?})",
                        m, self.supported_methods
                    ),
                }));
            }
        }

        // Record per-plugin metrics
        PLUGIN_REQUESTS_TOTAL
            .with_label_values(&[&self.config.plugin_name])
            .inc();
        let timer = PLUGIN_REQUEST_DURATION_SECONDS
            .with_label_values(&[&self.config.plugin_name])
            .start_timer();

        let mut client = self.pool.get().await?;

        let mut request = tonic::Request::new(PluginRequest {
            body: body.to_vec(),
            query: query.clone(),
            path: path.iter().map(|s| s.to_string()).collect(),
            method: method.to_string(),
        });

        // Inject plugin context into gRPC request metadata.
        // gRPC metadata values must be valid ASCII. Session IDs (UUIDs), TEE
        // types, and booleans are always ASCII in practice; warn if that
        // assumption ever breaks rather than silently omitting the header.
        {
            let metadata = request.metadata_mut();
            if let Some(session_id) = &context.session_id {
                match session_id.parse() {
                    Ok(val) => {
                        metadata.insert("kbs-session-id", val);
                    }
                    Err(_) => warn!(
                        "Plugin '{}': kbs-session-id contains non-ASCII characters, \
                         omitting from gRPC metadata",
                        self.config.plugin_name
                    ),
                }
            }
            if let Some(tee_type) = &context.tee_type {
                match tee_type.parse() {
                    Ok(val) => {
                        metadata.insert("kbs-tee-type", val);
                    }
                    Err(_) => warn!(
                        "Plugin '{}': kbs-tee-type contains non-ASCII characters, \
                         omitting from gRPC metadata",
                        self.config.plugin_name
                    ),
                }
            }
            if let Ok(val) = context.is_attested.to_string().parse() {
                metadata.insert("kbs-attested", val);
            }
        }

        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }

        let result = client
            .handle(request)
            .await
            .inspect_err(|status| {
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                ) {
                    *self
                        .state
                        .write()
                        .expect("invariant: state lock not poisoned") = PluginState::Unavailable;
                }
                PLUGIN_ERRORS_TOTAL
                    .with_label_values(&[&self.config.plugin_name])
                    .inc();
            })
            .map_err(map_grpc_error);

        timer.observe_duration();

        let response = result?.into_inner();
        let status_code = match response.status_code {
            0 => None,
            code @ 100..=599 => Some(code as u16),
            code => {
                warn!(
                    "Plugin '{}': invalid HTTP status code {} from plugin, using default",
                    self.config.plugin_name, code
                );
                None
            }
        };
        let content_type = if response.content_type.is_empty() {
            None
        } else {
            Some(response.content_type)
        };
        Ok(PluginOutput {
            body: response.body,
            status_code,
            content_type,
        })
    }

    pub async fn validate_auth(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        {
            let state = self
                .state
                .read()
                .expect("invariant: state lock not poisoned");
            if matches!(*state, PluginState::Unavailable) {
                anyhow::bail!(
                    "Plugin '{}' is unavailable (health check failing)",
                    self.config.plugin_name
                );
            }
        }
        let mut client = self.pool.get().await?;
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
            .inspect_err(|status| {
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                ) {
                    *self
                        .state
                        .write()
                        .expect("invariant: state lock not poisoned") = PluginState::Unavailable;
                }
                PLUGIN_ERRORS_TOTAL
                    .with_label_values(&[&self.config.plugin_name])
                    .inc();
            })
            .map_err(map_grpc_error)?;
        Ok(response.into_inner().requires_admin_auth)
    }

    pub async fn encrypted(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        {
            let state = self
                .state
                .read()
                .expect("invariant: state lock not poisoned");
            if matches!(*state, PluginState::Unavailable) {
                anyhow::bail!(
                    "Plugin '{}' is unavailable (health check failing)",
                    self.config.plugin_name
                );
            }
        }
        let mut client = self.pool.get().await?;
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
            .inspect_err(|status| {
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                ) {
                    *self
                        .state
                        .write()
                        .expect("invariant: state lock not poisoned") = PluginState::Unavailable;
                }
                PLUGIN_ERRORS_TOTAL
                    .with_label_values(&[&self.config.plugin_name])
                    .inc();
            })
            .map_err(map_grpc_error)?;
        Ok(response.into_inner().encrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(
        tls_mode: TlsMode,
        endpoint: &str,
        ca: bool,
        client: bool,
    ) -> ExternalPluginConfig {
        ExternalPluginConfig {
            plugin_name: "test".to_string(),
            endpoint: endpoint.to_string(),
            timeout_ms: None,
            tls_mode,
            ca_cert_path: if ca { Some("/tmp/ca.pem".into()) } else { None },
            client_cert_path: if client {
                Some("/tmp/cert.pem".into())
            } else {
                None
            },
            client_key_path: if client {
                Some("/tmp/key.pem".into())
            } else {
                None
            },
        }
    }

    // --- Insecure mode ---

    #[test]
    fn insecure_http_ok() {
        let cfg = make_config(TlsMode::Insecure, "http://localhost:50051", false, false);
        assert!(cfg.validate_tls_config().is_ok());
    }

    #[test]
    fn insecure_https_err_wrong_scheme() {
        let cfg = make_config(TlsMode::Insecure, "https://localhost:50051", false, false);
        let err = cfg.validate_tls_config().unwrap_err();
        assert!(
            err.to_string().contains("insecure mode requires http://"),
            "unexpected error: {err}"
        );
    }

    // --- TLS mode ---

    #[test]
    fn tls_https_with_ca_ok() {
        let cfg = make_config(TlsMode::Tls, "https://localhost:50051", true, false);
        assert!(cfg.validate_tls_config().is_ok());
    }

    #[test]
    fn tls_https_missing_ca_err() {
        let cfg = make_config(TlsMode::Tls, "https://localhost:50051", false, false);
        let err = cfg.validate_tls_config().unwrap_err();
        assert!(
            err.to_string().contains("ca_cert_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tls_http_err_wrong_scheme() {
        let cfg = make_config(TlsMode::Tls, "http://localhost:50051", true, false);
        let err = cfg.validate_tls_config().unwrap_err();
        assert!(
            err.to_string().contains("TLS mode requires https://"),
            "unexpected error: {err}"
        );
    }

    // --- mTLS mode ---

    #[test]
    fn mtls_https_with_ca_and_client_ok() {
        let cfg = make_config(TlsMode::Mtls, "https://localhost:50051", true, true);
        assert!(cfg.validate_tls_config().is_ok());
    }

    #[test]
    fn mtls_https_missing_ca_err() {
        let cfg = make_config(TlsMode::Mtls, "https://localhost:50051", false, true);
        let err = cfg.validate_tls_config().unwrap_err();
        assert!(
            err.to_string().contains("ca_cert_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mtls_https_missing_client_cert_err() {
        let cfg = make_config(TlsMode::Mtls, "https://localhost:50051", true, false);
        let err = cfg.validate_tls_config().unwrap_err();
        assert!(
            err.to_string().contains("client_cert_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mtls_http_err_wrong_scheme() {
        let cfg = make_config(TlsMode::Mtls, "http://localhost:50051", true, true);
        let err = cfg.validate_tls_config().unwrap_err();
        assert!(
            err.to_string().contains("TLS mode requires https://"),
            "unexpected error: {err}"
        );
    }
}

/// Map tonic::Status codes to HTTP-aware PluginCallError wrapped in anyhow.
///
/// The resulting error is downcast in `api_server.rs` to produce the correct
/// HTTP status code rather than always returning 401 Unauthorized.
///
/// The full plugin error message (which may contain internal details such as
/// stack traces or file paths) is logged server-side at debug level.  Only a
/// sanitized, fixed string is returned to the HTTP client to avoid information
/// disclosure.
fn map_grpc_error(status: tonic::Status) -> anyhow::Error {
    use tonic::Code;

    // Log the full message server-side for debugging; do not forward it.
    debug!(
        "Plugin gRPC error: code={:?}, message={}",
        status.code(),
        status.message()
    );

    let (http_status, message) = match status.code() {
        Code::NotFound => (404, "Plugin resource not found".to_string()),
        Code::InvalidArgument => (400, "Invalid request to plugin".to_string()),
        Code::PermissionDenied => (403, "Plugin access denied".to_string()),
        Code::Unauthenticated => (401, "Plugin authentication required".to_string()),
        Code::Unavailable | Code::DeadlineExceeded => {
            (503, "Plugin service unavailable".to_string())
        }
        _ => (500, "Plugin internal error".to_string()),
    };
    anyhow::Error::new(PluginCallError {
        http_status,
        message,
    })
}
