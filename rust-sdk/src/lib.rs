//! Rust SDK for building KBS external plugins.
//!
//! This crate provides a high-level API for implementing KBS plugins as gRPC
//! services. It abstracts away tonic server configuration, health service
//! registration, and TLS setup so plugin developers can focus on business logic.
//!
//! # Quick Start
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
//!         let req = request.into_inner();
//!         Ok(Response::new(PluginResponse {
//!             body: req.body,
//!             status_code: 200,
//!             content_type: "application/octet-stream".to_string(),
//!         }))
//!     }
//!
//!     async fn capabilities(&self) -> CapabilitiesBuilder {
//!         CapabilitiesBuilder::new("my-plugin", "1.0.0").methods(["GET", "POST"])
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     PluginServer::builder()
//!         .handler(MyPlugin)
//!         .bind("127.0.0.1:50051")
//!         .serve()
//!         .await?;
//!     Ok(())
//! }
//! ```

pub mod health;
pub mod server;
pub mod tls;

/// Generated protobuf types and gRPC service trait.
///
/// This module contains the `KbsPlugin` service trait and message types
/// (`PluginRequest`, `PluginResponse`, etc.) generated from `plugin.proto`.
///
/// Plugin authors typically import types from the crate root re-exports
/// rather than from this module directly.
pub mod plugin {
    tonic::include_proto!("kbs.plugin.v1");
}

// Re-export commonly used proto types at crate root for convenience
pub use plugin::{GetCapabilitiesRequest, GetCapabilitiesResponse, PluginRequest, PluginResponse};

// Re-export tonic types so users don't need tonic as a direct dependency
pub use tonic::{Request, Response, Status};

// Re-export SDK types
pub use server::PluginServer;
pub use tls::TlsConfig;

/// Trait for implementing KBS plugin logic.
///
/// Plugin authors implement this trait to handle incoming requests.
/// The SDK wraps this trait in the generated `KbsPlugin` gRPC service
/// automatically when using [`PluginServer`].
///
/// # Example
///
/// ```rust,no_run
/// use kbs_plugin_sdk::{CapabilitiesBuilder, PluginHandler, PluginRequest, PluginResponse};
/// use tonic::{Request, Response, Status};
///
/// #[derive(Default)]
/// struct EchoPlugin;
///
/// #[tonic::async_trait]
/// impl PluginHandler for EchoPlugin {
///     async fn handle(
///         &self,
///         request: Request<PluginRequest>,
///     ) -> Result<Response<PluginResponse>, Status> {
///         let req = request.into_inner();
///         let body = format!("Echo: method={}", req.method);
///         Ok(Response::new(PluginResponse {
///             body: body.into_bytes(),
///             status_code: 200,
///             content_type: "text/plain".to_string(),
///         }))
///     }
///
///     async fn capabilities(&self) -> CapabilitiesBuilder {
///         CapabilitiesBuilder::new("echo", "1.0.0")
///     }
/// }
/// ```
#[tonic::async_trait]
pub trait PluginHandler: Send + Sync + 'static {
    /// Handle an incoming plugin request.
    ///
    /// Receives the HTTP request details (method, path, query, body) forwarded
    /// from KBS and returns an HTTP response (body, status code, content type).
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status>;

    /// Return plugin capabilities metadata.
    ///
    /// Called once at startup by KBS to register the plugin. Use
    /// [`CapabilitiesBuilder`] for ergonomic construction.
    async fn capabilities(&self) -> CapabilitiesBuilder;
}

/// Builder for plugin capabilities metadata.
///
/// Provides an ergonomic API for constructing [`GetCapabilitiesResponse`].
///
/// # Example
///
/// ```
/// use kbs_plugin_sdk::CapabilitiesBuilder;
///
/// let caps = CapabilitiesBuilder::new("my-plugin", "1.0.0")
///     .method("GET")
///     .method("POST")
///     .attribute("author", "Acme Corp")
///     .build();
///
/// assert_eq!(caps.name, "my-plugin");
/// assert_eq!(caps.supported_methods.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct CapabilitiesBuilder {
    name: String,
    version: String,
    supported_methods: Vec<String>,
    attributes: std::collections::HashMap<String, String>,
}

impl CapabilitiesBuilder {
    /// Create new capabilities with required name and version.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            supported_methods: Vec::new(),
            attributes: std::collections::HashMap::new(),
        }
    }

    /// Add a supported HTTP method (e.g., "GET", "POST").
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.supported_methods.push(method.into());
        self
    }

    /// Add multiple supported HTTP methods.
    pub fn methods<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.supported_methods
            .extend(methods.into_iter().map(Into::into));
        self
    }

    /// Add a custom attribute (key-value metadata).
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Build the final [`GetCapabilitiesResponse`].
    pub fn build(self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            name: self.name,
            version: self.version,
            supported_methods: self.supported_methods,
            attributes: self.attributes,
        }
    }
}
