// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use actix_web::http::Method;
use anyhow::{Context, Result};
use async_trait::async_trait;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use log::{debug, info, warn};
use mobc::{Manager, Pool};
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

use crate::error::PluginCallError;
use crate::plugins::external::plugin_api::{
    kbs_plugin_client::KbsPluginClient, GetCapabilitiesRequest, NeedsEncryptionRequest,
    PluginRequest, ValidateAuthRequest,
};
use crate::plugins::plugin_manager::{
    ClientPlugin, ExternalPluginConfig, PluginContext, PluginOutput, TlsMode,
};
use crate::prometheus::{
    PLUGIN_ERRORS_TOTAL, PLUGIN_REQUESTS_TOTAL, PLUGIN_REQUEST_DURATION_SECONDS,
};

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

/// Timeout for pool-level connection health validation.
const POOL_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(1);

/// Initial delay before first retry on connection failure.
const RETRY_INITIAL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum delay between retries.
const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(5);

/// Total time window for connection retries before giving up.
const RETRY_MAX_ELAPSED: Duration = Duration::from_secs(30);

/// Jitter factor (+/-) to prevent thundering herd on retries.
const RETRY_RANDOMIZATION_FACTOR: f64 = 0.1;

/// Plugin health state tracked via background health monitor.
#[derive(Clone, Debug)]
pub enum PluginState {
    Healthy,
    Unavailable,
}

pub struct GrpcPluginProxy {
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
        let manager = PluginGrpcManager {
            endpoint: config.endpoint.clone(),
            tls_mode: config.tls_mode.clone(),
            ca_cert_path: config.ca_cert_path.clone(),
            client_cert_path: config.client_cert_path.clone(),
            client_key_path: config.client_key_path.clone(),
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

        let state = Arc::new(RwLock::new(PluginState::Healthy));

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
pub struct PluginGrpcManager {
    endpoint: String,
    tls_mode: TlsMode,
    ca_cert_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
    client_key_path: Option<PathBuf>,
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
        // Validate connection health before returning from pool.
        // Create a lightweight channel for the health check probe.
        let mut channel = Channel::from_shared(self.endpoint.clone())?;

        if let Some(tls) = build_tls_config(
            &self.tls_mode,
            &self.ca_cert_path,
            &self.client_cert_path,
            &self.client_key_path,
        )
        .await?
        {
            channel = channel.tls_config(tls)?;
        }

        let health_channel = channel
            .connect()
            .await
            .context("Health check channel connect failed")?;

        check_health(health_channel, POOL_HEALTH_CHECK_TIMEOUT)
            .await
            .context("Connection health check failed, discarding from pool")?;

        Ok(conn)
    }
}

#[async_trait]
impl ClientPlugin for GrpcPluginProxy {
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        context: Option<&PluginContext>,
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
        if let Some(ctx) = context {
            let metadata = request.metadata_mut();
            if let Some(session_id) = &ctx.session_id {
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
            if let Some(tee_type) = &ctx.tee_type {
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
            if let Ok(val) = ctx.is_attested.to_string().parse() {
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
        let status_code = if response.status_code == 0 {
            None
        } else {
            Some(response.status_code as u16)
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

    async fn validate_auth(
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

    async fn encrypted(
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
