// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Echo plugin example demonstrating the KBS Plugin SDK.
//!
//! This example implements a minimal plugin that echoes back request details
//! in the response body. It shows how to:
//!
//! - Implement the [`PluginHandler`] trait with `handle()` and `capabilities()`
//! - Use [`PluginServer::builder()`] for zero-boilerplate server setup
//! - Construct capabilities metadata with [`CapabilitiesBuilder`]
//!
//! # Running
//!
//! ```bash
//! cargo run -p kbs-plugin-sdk --example echo
//! ```
//!
//! The server starts on `127.0.0.1:50051` with automatic gRPC health service.
//!
//! # Testing with KBS
//!
//! 1. Start this example (Terminal 1):
//!    ```bash
//!    cargo run -p kbs-plugin-sdk --example echo
//!    ```
//!
//! 2. Start KBS with external plugin config (Terminal 2):
//!    ```bash
//!    cargo run --bin kbs --features external-plugin,as -- \
//!        --config-file kbs/test/test_data/configs/external-plugin-test.toml
//!    ```
//!
//! 3. Send a request (Terminal 3):
//!    ```bash
//!    curl http://127.0.0.1:8080/kbs/v0/external/test/path
//!    ```
//!
//!    Response: `Echo: method=GET, path=["test", "path"], query={}, body_len=0`

use kbs_plugin_sdk::{CapabilitiesBuilder, PluginHandler, PluginServer};
use kbs_plugin_sdk::{PluginRequest, PluginResponse, Request, Response, Status};

/// A simple echo plugin that reflects request details back to the caller.
///
/// This demonstrates the minimal implementation needed for a working KBS plugin.
/// Real plugins would contain domain-specific logic (key management, policy
/// evaluation, secret injection, etc.) in the `handle()` method.
#[derive(Default)]
struct EchoPlugin;

#[tonic::async_trait]
impl PluginHandler for EchoPlugin {
    /// Handle an incoming request by echoing its details.
    ///
    /// Returns a plain-text response containing the HTTP method, path segments,
    /// query parameters, and body length from the original request.
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        let req = request.into_inner();

        // Format request details for the echo response
        let response_body = format!(
            "Echo: method={}, path={:?}, query={:?}, body_len={}",
            req.method,
            req.path,
            req.query,
            req.body.len()
        );

        Ok(Response::new(PluginResponse {
            body: response_body.into_bytes(),
            status_code: 200,
            content_type: "text/plain".to_string(),
        }))
    }

    /// Advertise plugin capabilities to KBS.
    ///
    /// KBS calls this once at startup to learn the plugin's name, version,
    /// and supported HTTP methods. The name is used for request routing.
    async fn capabilities(&self) -> CapabilitiesBuilder {
        CapabilitiesBuilder::new("echo-plugin", "1.0.0")
            .methods(["GET", "POST"])
            .attribute("description", "Echoes request details back to caller")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = EchoPlugin;

    // PluginServer::builder() handles all gRPC boilerplate:
    // - Wraps EchoPlugin in the generated KbsPlugin service adapter
    // - Registers grpc.health.v1.Health service automatically
    // - Configures tonic server and starts serving
    PluginServer::builder()
        .handler(plugin)
        .bind("127.0.0.1:50051")
        .serve()
        .await?;

    Ok(())
}
