// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Plugin server builder with automatic health service registration.
//!
//! Provides a [`PluginServer`] with a fluent builder API that configures a
//! tonic gRPC server with KBS-specific defaults: automatic health service
//! registration, optional TLS, and handler adapter bridging.
//!
//! # Example
//!
//! ```rust,no_run
//! use kbs_plugin_sdk::{CapabilitiesBuilder, PluginHandler, PluginServer};
//! use kbs_plugin_sdk::{PluginRequest, PluginResponse, Request, Response, Status};
//!
//! #[derive(Default)]
//! struct MyPlugin;
//!
//! #[tonic::async_trait]
//! impl PluginHandler for MyPlugin {
//!     async fn handle(
//!         &self,
//!         request: Request<PluginRequest>,
//!     ) -> Result<Response<PluginResponse>, Status> {
//!         Ok(Response::new(PluginResponse {
//!             body: b"hello".to_vec(),
//!             status_code: 200,
//!             content_type: "text/plain".to_string(),
//!         }))
//!     }
//!
//!     async fn capabilities(&self) -> CapabilitiesBuilder {
//!         CapabilitiesBuilder::new("my-plugin", "1.0.0")
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     PluginServer::builder()
//!         .handler(MyPlugin)
//!         .bind("127.0.0.1:50051")
//!         .serve()
//!         .await
//! }
//! ```

use anyhow::Result;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::health::{health_reporter, ServingStatus, PLUGIN_SERVICE_NAME};
use crate::plugin::kbs_plugin_server::{KbsPlugin, KbsPluginServer};
use crate::tls::TlsConfig;
use crate::{
    GetCapabilitiesRequest, GetCapabilitiesResponse, PluginHandler, PluginRequest, PluginResponse,
};

/// Encoded file descriptor set for the plugin proto, generated at build time.
const PLUGIN_FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/plugin_descriptor.bin"));

/// Marker struct for the KBS plugin server.
///
/// Use [`PluginServer::builder()`] to create a [`PluginServerBuilder`]
/// for configuring and running a plugin server.
#[derive(Debug)]
pub struct PluginServer;

impl PluginServer {
    /// Create a new [`PluginServerBuilder`] with default settings.
    ///
    /// Defaults:
    /// - Health service enabled
    /// - No TLS
    /// - Handler and bind address must be set before calling [`PluginServerBuilder::serve`]
    pub fn builder<H: PluginHandler>() -> PluginServerBuilder<H> {
        PluginServerBuilder {
            handler: None,
            addr: None,
            tls_config: None,
            health_enabled: true,
        }
    }
}

/// Builder for KBS plugin servers.
///
/// Configures a tonic gRPC server with automatic health service registration,
/// optional TLS, and plugin-specific settings.
pub struct PluginServerBuilder<H> {
    handler: Option<H>,
    addr: Option<String>,
    tls_config: Option<TlsConfig>,
    health_enabled: bool,
}

impl<H> std::fmt::Debug for PluginServerBuilder<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginServerBuilder")
            .field("addr", &self.addr)
            .field("tls_config", &self.tls_config)
            .field("health_enabled", &self.health_enabled)
            .finish_non_exhaustive()
    }
}

impl<H: PluginHandler> PluginServerBuilder<H> {
    /// Set the plugin handler implementation.
    pub fn handler(mut self, handler: H) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Bind to address (e.g., `"127.0.0.1:50051"`).
    pub fn bind(mut self, addr: impl Into<String>) -> Self {
        self.addr = Some(addr.into());
        self
    }

    /// Configure TLS settings (mutual TLS or server-only TLS).
    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Disable automatic health service registration.
    ///
    /// By default, the SDK registers `grpc.health.v1.Health` service so that
    /// KBS health checks succeed. Call this to disable if you need manual
    /// control over health reporting.
    pub fn disable_health_service(mut self) -> Self {
        self.health_enabled = false;
        self
    }

    /// Build and serve the plugin server.
    ///
    /// This method:
    /// 1. Validates configuration (handler and address are required)
    /// 2. Registers health service (if enabled)
    /// 3. Wraps handler in KbsPlugin trait adapter
    /// 4. Configures TLS (if provided)
    /// 5. Starts tonic Server and serves until shutdown
    pub async fn serve(self) -> Result<()> {
        let handler = self
            .handler
            .ok_or_else(|| anyhow::anyhow!("handler is required"))?;
        let addr_str = self
            .addr
            .ok_or_else(|| anyhow::anyhow!("bind address is required"))?;

        // Wrap user's handler in generated KbsPlugin trait adapter
        let adapter = PluginHandlerAdapter::new(handler);
        let plugin_server = KbsPluginServer::new(adapter);

        // Build tonic server, optionally with TLS
        let mut server_builder = if let Some(tls) = self.tls_config {
            let tls_config = tls.into_server_tls_config()?;
            Server::builder().tls_config(tls_config)?
        } else {
            Server::builder()
        };

        // Build gRPC reflection service so tools like grpcurl work without proto files
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(PLUGIN_FILE_DESCRIPTOR_SET)
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()?;

        // Add plugin service, reflection, and optional health service
        let router = if self.health_enabled {
            // Set up health service reporting our plugin as SERVING
            let (reporter, health_service) = health_reporter();
            reporter
                .set_service_status(PLUGIN_SERVICE_NAME, ServingStatus::Serving)
                .await;
            // Keep reporter alive for the lifetime of the server
            let _reporter = reporter;
            server_builder
                .add_service(plugin_server)
                .add_service(health_service)
                .add_service(reflection_service)
        } else {
            server_builder
                .add_service(plugin_server)
                .add_service(reflection_service)
        };

        // Parse address and serve
        let addr = addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid bind address '{}': {}", addr_str, e))?;

        println!("KBS plugin server listening on {}", addr);
        router.serve(addr).await?;

        Ok(())
    }
}

/// Adapter bridging user's [`PluginHandler`] to the generated [`KbsPlugin`] trait.
///
/// This is an internal type -- users interact with [`PluginHandler`] and
/// [`PluginServer`] instead.
struct PluginHandlerAdapter<H> {
    handler: H,
}

impl<H: PluginHandler> PluginHandlerAdapter<H> {
    fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[tonic::async_trait]
impl<H: PluginHandler> KbsPlugin for PluginHandlerAdapter<H> {
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        self.handler.handle(request).await
    }

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        let caps = self.handler.capabilities().await;
        Ok(Response::new(caps.build()))
    }
}
