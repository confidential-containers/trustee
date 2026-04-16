//! Unified external plugin test server for e2e tests.
//!
//! A single binary configurable via environment variables to exercise all
//! external plugin code paths: basic forwarding, TLS, admin auth, attestation,
//! JWE encryption, and Prometheus metrics.
//!
//! # Environment variables
//!
//! | Variable | Default | Purpose |
//! |---|---|---|
//! | `PLUGIN_LISTEN_ADDR` | `127.0.0.1:50051` | gRPC listen address |
//! | `PLUGIN_TLS_CERT` | *(unset)* | Path to TLS certificate (enables TLS) |
//! | `PLUGIN_TLS_KEY` | *(unset)* | Path to TLS private key |
//! | `PLUGIN_STORE_DATA` | `false` | If `true`, POST stores data and GET returns it; otherwise both echo |
//! | `PLUGIN_ENCRYPT_GET` | `false` | If `true`, GET responses require JWE encryption |
//!
//! POST is always admin-gated (`validate_auth = true`). GET is always
//! attestation-gated (`validate_auth = false`). These match real plugin
//! semantics: admin credentials provision secrets, attestation retrieves them.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Code, Request, Response, Status};

pub mod plugin_api {
    tonic::include_proto!("kbs.plugin.v1");
}

use plugin_api::{
    kbs_plugin_server::{KbsPlugin, KbsPluginServer},
    NeedsEncryptionRequest, NeedsEncryptionResponse, PluginRequest, PluginResponse,
    ValidateAuthRequest, ValidateAuthResponse,
};

const ENV_LISTEN_ADDR: &str = "PLUGIN_LISTEN_ADDR";
const ENV_TLS_CERT: &str = "PLUGIN_TLS_CERT";
const ENV_TLS_KEY: &str = "PLUGIN_TLS_KEY";
const ENV_STORE_DATA: &str = "PLUGIN_STORE_DATA";
const ENV_ENCRYPT_GET: &str = "PLUGIN_ENCRYPT_GET";

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:50051";

struct Config {
    store_data: bool,
    encrypt_get: bool,
}

struct TestPlugin {
    config: Config,
    store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

#[tonic::async_trait]
impl KbsPlugin for TestPlugin {
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        let req = request.into_inner();
        let key = req.path.join("/");

        match req.method.as_str() {
            "POST" => {
                if self.config.store_data {
                    // Resource mode: store data, return empty acknowledgement
                    self.store
                        .write()
                        .expect("invariant: store lock not poisoned")
                        .insert(key.clone(), req.body);
                    tracing::info!(key, "handle: stored secret");
                    Ok(Response::new(PluginResponse {
                        body: vec![],
                        status_code: 200,
                        content_type: String::new(),
                    }))
                } else {
                    // Echo mode: reflect request details back to caller
                    let body = format!(
                        "Echo: method={}, path={:?}, query={:?}, body_len={}",
                        req.method,
                        req.path,
                        req.query,
                        req.body.len()
                    );
                    tracing::info!(key, "handle: echo POST");
                    Ok(Response::new(PluginResponse {
                        body: body.into_bytes(),
                        status_code: 200,
                        content_type: "text/plain".to_string(),
                    }))
                }
            }
            "GET" => {
                let store = self
                    .store
                    .read()
                    .expect("invariant: store lock not poisoned");
                match store.get(&key) {
                    Some(data) => {
                        // Resource mode: return previously stored secret
                        tracing::info!(key, data_len = data.len(), "handle: returning secret");
                        Ok(Response::new(PluginResponse {
                            body: data.clone(),
                            status_code: 200,
                            content_type: "application/octet-stream".to_string(),
                        }))
                    }
                    None => {
                        // Echo mode: reflect request details (no stored data)
                        let body = format!(
                            "Echo: method={}, path={:?}, query={:?}, body_len={}",
                            req.method,
                            req.path,
                            req.query,
                            req.body.len()
                        );
                        tracing::info!(key, "handle: echo GET");
                        Ok(Response::new(PluginResponse {
                            body: body.into_bytes(),
                            status_code: 200,
                            content_type: "text/plain".to_string(),
                        }))
                    }
                }
            }
            method => Err(Status::new(
                Code::InvalidArgument,
                format!("method not supported: {method}"),
            )),
        }
    }

    // POST is always admin-gated: provisioning secrets requires admin credentials.
    // GET is always attestation-gated: retrieval requires a valid attestation token.
    async fn validate_auth(
        &self,
        request: Request<ValidateAuthRequest>,
    ) -> Result<Response<ValidateAuthResponse>, Status> {
        let method = request.into_inner().method;
        let requires_admin_auth = method == "POST";
        tracing::info!(method, requires_admin_auth, "validate_auth");
        Ok(Response::new(ValidateAuthResponse {
            requires_admin_auth,
        }))
    }

    async fn needs_encryption(
        &self,
        request: Request<NeedsEncryptionRequest>,
    ) -> Result<Response<NeedsEncryptionResponse>, Status> {
        let method = request.into_inner().method;
        let encrypt = self.config.encrypt_get && method == "GET";
        tracing::info!(method, encrypt, "needs_encryption");
        Ok(Response::new(NeedsEncryptionResponse {
            requires_payload_encryption: encrypt,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Both ring and aws-lc-rs are compiled in; rustls requires an explicit
    // default crypto provider when multiple backends are present. Install ring.
    // .ok() ignores Err if a provider is already registered.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let addr = std::env::var(ENV_LISTEN_ADDR)
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string())
        .parse()?;

    let config = Config {
        store_data: std::env::var(ENV_STORE_DATA)
            .map(|v| v == "true")
            .unwrap_or(false),
        encrypt_get: std::env::var(ENV_ENCRYPT_GET)
            .map(|v| v == "true")
            .unwrap_or(false),
    };

    tracing::info!(
        %addr,
        store_data = config.store_data,
        encrypt_get = config.encrypt_get,
        "external plugin test server starting"
    );

    let plugin = TestPlugin {
        config,
        store: Arc::new(RwLock::new(HashMap::new())),
    };

    let tls_cert = std::env::var(ENV_TLS_CERT).ok();
    let tls_key = std::env::var(ENV_TLS_KEY).ok();

    let mut builder = Server::builder();

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        let identity = Identity::from_pem(cert, key);
        let tls_config = ServerTlsConfig::new().identity(identity);
        tracing::info!("TLS enabled");
        builder = builder.tls_config(tls_config)?;
    }

    builder
        .add_service(KbsPluginServer::new(plugin))
        .serve(addr)
        .await?;

    Ok(())
}
