// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Echo plugin example demonstrating the full KBS Plugin SDK.
//!
//! This example implements all four operations in the KBS plugin gRPC protocol,
//! showing how KBS calls them in sequence for each HTTP request:
//!
//! ```text
//! KBS Request Flow
//! ────────────────
//! 1. validate_auth(method, path) → requires_admin_auth?
//!       true  → KBS checks admin credentials, then calls handle()
//!       false → KBS verifies attestation token + policy, then calls handle()
//! 2. handle(method, path, query, body) → response body + status + content-type
//! 3. needs_encryption(method, path) → encrypt?  [attestation path only]
//!       true  → KBS JWE-encrypts body with TEE public key
//!       false → KBS returns body as-is
//! ```
//!
//! This plugin uses the same auth-routing pattern as the built-in `resource`
//! and `pkcs11` plugins: POST (provision/write) requires admin credentials,
//! GET (retrieve) requires an attestation token. Responses are never encrypted
//! (matching the `sample` built-in plugin) since echo returns non-sensitive data.
//!
//! # Running
//!
//! ```bash
//! RUST_LOG=echo=debug cargo run -p kbs-plugin-sdk --example echo
//! ```
//!
//! # Testing with KBS
//!
//! 1. Start this example (Terminal 1):
//!    ```bash
//!    RUST_LOG=echo=debug cargo run -p kbs-plugin-sdk --example echo
//!    ```
//!
//! 2. Start KBS with external plugin config (Terminal 2):
//!    ```bash
//!    cargo run --bin kbs --features external-plugin,coco-as-builtin -- \
//!        --config-file kbs/test/test_data/configs/external-plugin-test.toml
//!    ```
//!
//! 3. Send requests (Terminal 3):
//!    ```bash
//!    # Admin-gated (POST): requires admin credentials
//!    curl -X POST http://127.0.0.1:8080/kbs/v0/echo-plugin/hello
//!
//!    # Attestation-gated (GET): requires attestation token
//!    curl http://127.0.0.1:8080/kbs/v0/echo-plugin/hello
//!    ```
//!
//! # Understanding the logs
//!
//! With `RUST_LOG=echo=debug` you will see one log line per KBS RPC call.
//! A GET request (attestation-gated) produces three log lines:
//!
//! ```text
//! validate_auth: method="GET" requires_admin_auth=false
//! handle: method="GET" path=["hello"] session_id="..." is_attested="true"
//! needs_encryption: method="GET" encrypt=false
//! ```

use kbs_plugin_sdk::{CapabilitiesBuilder, PluginHandler, PluginServer};
use kbs_plugin_sdk::{
    NeedsEncryptionRequest, NeedsEncryptionResponse, PluginRequest, PluginResponse, Request,
    Response, Status, ValidateAuthRequest, ValidateAuthResponse,
};

/// Echo plugin: reflects request details back to the caller.
///
/// Uses the same auth pattern as built-in plugins (resource, pkcs11):
/// POST = admin-gated, GET = attestation-gated, no encryption.
#[derive(Default)]
struct EchoPlugin;

#[tonic::async_trait]
impl PluginHandler for EchoPlugin {
    /// Step 1 of the KBS request flow: decide which auth path to use.
    ///
    /// POST (provision/write) requires admin credentials.
    /// GET (retrieve) requires an attestation token + policy.
    /// This mirrors the pattern used by the built-in resource and pkcs11 plugins.
    async fn validate_auth(
        &self,
        request: Request<ValidateAuthRequest>,
    ) -> Result<Response<ValidateAuthResponse>, Status> {
        let req = request.into_inner();

        // POST (write/provision) = admin auth; GET (read/retrieve) = attestation.
        let requires_admin_auth = req.method == "POST";

        tracing::info!(
            method = %req.method,
            requires_admin_auth,
            "validate_auth"
        );

        Ok(Response::new(ValidateAuthResponse {
            requires_admin_auth,
        }))
    }

    /// Step 2 of the KBS request flow: process the request and return a response.
    ///
    /// KBS calls this after authentication passes. The request carries the original
    /// HTTP method, path segments, query parameters, and body. KBS also injects
    /// session context into gRPC metadata headers — read them here for audit logging
    /// or per-session decisions.
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        // KBS injects session context as gRPC metadata headers:
        //   kbs-session-id  — client session ID (cookie-based auth only)
        //   kbs-tee-type    — TEE platform, e.g. "SevSnp", "Tdx" (cookie auth only)
        //   kbs-attested    — "true" if caller completed RCAR attestation
        let metadata = request.metadata().clone();
        let session_id = metadata
            .get("kbs-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none");
        let tee_type = metadata
            .get("kbs-tee-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none");
        let is_attested = metadata
            .get("kbs-attested")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("false");

        let req = request.into_inner();

        tracing::info!(
            method = %req.method,
            path = ?req.path,
            query = ?req.query,
            body_len = req.body.len(),
            session_id,
            tee_type,
            is_attested,
            "handle: processing request"
        );

        let body = format!(
            "Echo: method={}, path={:?}, query={:?}, body_len={}, \
             session_id={session_id}, tee_type={tee_type}, is_attested={is_attested}",
            req.method,
            req.path,
            req.query,
            req.body.len(),
        );

        Ok(Response::new(PluginResponse {
            body: body.into_bytes(),
            status_code: 200,
            content_type: "text/plain".to_string(),
        }))
    }

    /// Step 3 of the KBS request flow (attestation path only): decide whether to
    /// JWE-encrypt the response.
    ///
    /// KBS calls this after `handle` returns, but only on the attestation-gated
    /// path. Return `true` to encrypt the response body with the TEE's ephemeral
    /// public key (required for secret material). Return `false` for non-sensitive
    /// responses.
    ///
    /// This echo plugin returns non-sensitive strings, so encryption is never needed.
    async fn needs_encryption(
        &self,
        request: Request<NeedsEncryptionRequest>,
    ) -> Result<Response<NeedsEncryptionResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            method = %req.method,
            encrypt = false,
            "needs_encryption"
        );

        Ok(Response::new(NeedsEncryptionResponse { encrypt: false }))
    }

    /// Declare plugin capabilities to KBS.
    ///
    /// KBS calls this once at startup to learn the plugin name (used for routing),
    /// version, and supported HTTP methods. The `name` here should match the
    /// `plugin_name` in the KBS config entry.
    async fn capabilities(&self) -> CapabilitiesBuilder {
        CapabilitiesBuilder::new("echo-plugin", "1.0.0")
            .methods(["GET", "POST"])
            .attribute(
                "description",
                "Echoes request details — full 4-RPC SDK example",
            )
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured logging.
    // Set RUST_LOG=echo=debug to see per-request logs for all four KBS operations.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("echo=info".parse()?),
        )
        .init();

    let addr = "127.0.0.1:50051";
    tracing::info!(addr, "echo plugin starting — listening for KBS connections");

    PluginServer::builder()
        .handler(EchoPlugin)
        .bind(addr)
        .serve()
        .await?;

    Ok(())
}
