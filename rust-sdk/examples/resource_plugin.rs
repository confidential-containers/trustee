// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! External resource plugin — mimics the built-in KBS resource plugin.
//!
//! Demonstrates how an external plugin can replicate the built-in resource
//! plugin's behaviour exactly using the KBS Plugin SDK:
//!
//! ```text
//! POST /kbs/v0/resource/<key>  — store secret data (admin-gated)
//! GET  /kbs/v0/resource/<key>  — retrieve secret data (attestation-gated,
//!                                JWE-encrypted with TEE public key)
//! ```
//!
//! Auth and encryption decisions mirror the built-in resource plugin:
//! - POST → admin credentials required (`validate_auth = true`)
//! - GET  → attestation token + policy required (`validate_auth = false`)
//! - GET responses are JWE-encrypted (`needs_encryption = true`)
//! - POST responses are not encrypted (`needs_encryption = false`)
//!
//! # Running
//!
//! ```bash
//! cargo run -p kbs-plugin-sdk --example resource_plugin
//! ```
//!
//! Listens on `127.0.0.1:50053` by default. Override with `RESOURCE_PLUGIN_LISTEN_ADDR`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use kbs_plugin_sdk::{CapabilitiesBuilder, PluginHandler, PluginServer};
use kbs_plugin_sdk::{
    NeedsEncryptionRequest, NeedsEncryptionResponse, PluginRequest, PluginResponse, Request,
    Response, Status, ValidateAuthRequest, ValidateAuthResponse,
};
use tonic::Code;

const LISTEN_ADDR_ENV: &str = "RESOURCE_PLUGIN_LISTEN_ADDR";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:50053";

/// External resource plugin: in-memory key-value store for confidential data.
#[derive(Default)]
struct ResourcePlugin {
    store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

#[tonic::async_trait]
impl PluginHandler for ResourcePlugin {
    /// POST (store) = admin-gated; GET (retrieve) = attestation-gated.
    /// Mirrors the built-in resource plugin exactly.
    async fn validate_auth(
        &self,
        request: Request<ValidateAuthRequest>,
    ) -> Result<Response<ValidateAuthResponse>, Status> {
        let req = request.into_inner();
        let requires_admin_auth = req.method == "POST";
        tracing::info!(method = %req.method, requires_admin_auth, "validate_auth");
        Ok(Response::new(ValidateAuthResponse {
            requires_admin_auth,
        }))
    }

    /// Store (POST) or retrieve (GET) a secret by its path key.
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        let req = request.into_inner();
        let key = req.path.join("/");

        match req.method.as_str() {
            "POST" => {
                tracing::info!(key, body_len = req.body.len(), "handle: storing secret");
                self.store
                    .write()
                    .expect("invariant: store lock not poisoned")
                    .insert(key, req.body);
                Ok(Response::new(PluginResponse {
                    body: vec![],
                    status_code: 200,
                    content_type: String::new(),
                }))
            }
            "GET" => {
                let store = self
                    .store
                    .read()
                    .expect("invariant: store lock not poisoned");
                match store.get(&key) {
                    Some(data) => {
                        tracing::info!(key, data_len = data.len(), "handle: returning secret");
                        Ok(Response::new(PluginResponse {
                            body: data.clone(),
                            status_code: 200,
                            content_type: "application/octet-stream".to_string(),
                        }))
                    }
                    None => {
                        tracing::warn!(key, "handle: resource not found");
                        Err(Status::new(
                            Code::NotFound,
                            format!("resource not found: {key}"),
                        ))
                    }
                }
            }
            method => {
                tracing::warn!(method, "handle: method not supported");
                Err(Status::new(
                    Code::InvalidArgument,
                    format!("method not supported: {method} (use GET or POST)"),
                ))
            }
        }
    }

    /// GET responses contain secret data — must be JWE-encrypted with the TEE's
    /// ephemeral public key. POST responses are empty acknowledgements.
    /// Mirrors the built-in resource plugin exactly.
    async fn needs_encryption(
        &self,
        request: Request<NeedsEncryptionRequest>,
    ) -> Result<Response<NeedsEncryptionResponse>, Status> {
        let req = request.into_inner();
        let encrypt = req.method == "GET";
        tracing::info!(method = %req.method, encrypt, "needs_encryption");
        Ok(Response::new(NeedsEncryptionResponse { encrypt }))
    }

    async fn capabilities(&self) -> CapabilitiesBuilder {
        CapabilitiesBuilder::new("resource", "1.0.0")
            .methods(["GET", "POST"])
            .attribute(
                "description",
                "In-memory key-value store — mirrors built-in resource plugin",
            )
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("resource_plugin=info".parse()?),
        )
        .init();

    let addr = std::env::var(LISTEN_ADDR_ENV).unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    tracing::info!(addr, "resource plugin starting");

    PluginServer::builder()
        .handler(ResourcePlugin::default())
        .bind(addr)
        .serve()
        .await?;

    Ok(())
}
