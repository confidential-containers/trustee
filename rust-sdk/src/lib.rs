//! Rust SDK for building KBS external plugins.
//!
//! This crate provides a high-level API for implementing KBS plugins as gRPC
//! services. It abstracts away tonic server configuration, health service
//! registration, and TLS setup so plugin developers can focus on business logic.
//!
//! # Key Features
//!
//! - **Zero protoc dependency** -- Proto stubs are compiled at build time and
//!   re-exported from this crate. Plugin authors never need protoc installed.
//! - **Automatic health service** -- The [`PluginServer`] registers a
//!   `grpc.health.v1.Health` service so KBS health checks work out of the box.
//! - **Type-safe TLS** -- Configure mutual TLS or server-only TLS via the
//!   [`TlsConfig`] enum with fail-fast certificate validation at startup.
//! - **Minimal boilerplate** -- Implement [`PluginHandler`] with two methods
//!   (`handle` and `capabilities`) and call
//!   [`PluginServer::builder()`](PluginServer::builder) to run.
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
//!
//! See `examples/echo.rs` for a complete working example with integration test
//! instructions.
//!
//! # Architecture
//!
//! ```text
//! Plugin Author Code              SDK Internals
//! ==================              =============
//!
//! impl PluginHandler   -->   PluginHandlerAdapter   -->   tonic KbsPlugin trait
//!   handle()                   (internal bridge)          (generated from proto)
//!   capabilities()
//!
//! PluginServer::builder()
//!   .handler(impl)     -->   tonic::transport::Server
//!   .bind(addr)              + health service
//!   .tls(config)             + TLS config
//!   .serve()                 + plugin service
//! ```
//!
//! # TLS Configuration
//!
//! By default, the server runs without TLS. For production use, configure
//! mutual TLS or server-only TLS:
//!
//! ```rust,no_run
//! # use kbs_plugin_sdk::{PluginServer, PluginHandler, CapabilitiesBuilder, TlsConfig};
//! # use kbs_plugin_sdk::{PluginRequest, PluginResponse, Request, Response, Status};
//! # #[derive(Default)]
//! # struct MyPlugin;
//! # #[tonic::async_trait]
//! # impl PluginHandler for MyPlugin {
//! #     async fn handle(&self, request: Request<PluginRequest>)
//! #         -> Result<Response<PluginResponse>, Status> { todo!() }
//! #     async fn capabilities(&self) -> CapabilitiesBuilder { todo!() }
//! # }
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let tls = TlsConfig::mtls(
//!     "/etc/plugin/server.pem",
//!     "/etc/plugin/server.key",
//!     "/etc/plugin/client-ca.pem",
//! );
//!
//! PluginServer::builder()
//!     .handler(MyPlugin)
//!     .bind("0.0.0.0:50051")
//!     .tls(tls)
//!     .serve()
//!     .await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

/// Health service setup for KBS plugin servers.
///
/// Integrates with `tonic-health` to provide automatic
/// `grpc.health.v1.Health` service registration. KBS uses the standard gRPC
/// health checking protocol to verify plugins are serving before routing
/// requests to them.
pub mod health;

/// Plugin server builder with automatic health service registration.
///
/// Provides [`PluginServer`] with a fluent builder API that configures a
/// tonic gRPC server with automatic health service registration, optional
/// TLS, and handler adapter bridging. See [`PluginServer::builder()`] to
/// get started.
pub mod server;

/// TLS configuration helpers for plugin servers.
///
/// Provides [`TlsConfig`] with mutual TLS and server-only TLS modes.
/// Certificate files are validated at startup for fail-fast error reporting.
pub mod tls;

/// Generated protobuf types and gRPC service trait.
///
/// This module contains the `KbsPlugin` service trait and message types
/// ([`PluginRequest`], [`PluginResponse`], etc.) generated from `plugin.proto`.
///
/// Plugin authors typically import types from the crate root re-exports
/// rather than from this module directly:
///
/// ```rust
/// // Preferred: import from crate root
/// use kbs_plugin_sdk::{PluginRequest, PluginResponse};
/// ```
///
/// The same types are also available via the module path:
///
/// ```rust
/// // Alternative: import from plugin module directly
/// use kbs_plugin_sdk::plugin::{PluginRequest, PluginResponse};
/// ```
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
/// Plugin authors implement this trait to handle incoming requests from KBS.
/// The SDK wraps implementations in the generated `KbsPlugin` gRPC service
/// automatically when using [`PluginServer`].
///
/// # Required Methods
///
/// - [`handle`](PluginHandler::handle) -- Process an incoming HTTP request
///   forwarded from KBS. Receives method, path, query parameters, and body.
///   Returns a response with body, status code, and content type.
///
/// - [`capabilities`](PluginHandler::capabilities) -- Return plugin metadata.
///   Called once at startup by KBS to register the plugin. Use
///   [`CapabilitiesBuilder`] for ergonomic construction.
///
/// # Requirements
///
/// Implementations must use the `#[tonic::async_trait]` attribute macro:
///
/// ```rust,no_run
/// use kbs_plugin_sdk::{CapabilitiesBuilder, PluginHandler, PluginRequest, PluginResponse};
/// use kbs_plugin_sdk::{Request, Response, Status};
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
///         let body = format!(
///             "Echo: method={}, path={:?}, query={:?}, body_len={}",
///             req.method,
///             req.path,
///             req.query,
///             req.body.len()
///         );
///         Ok(Response::new(PluginResponse {
///             body: body.into_bytes(),
///             status_code: 200,
///             content_type: "text/plain".to_string(),
///         }))
///     }
///
///     async fn capabilities(&self) -> CapabilitiesBuilder {
///         CapabilitiesBuilder::new("echo", "1.0.0")
///             .methods(["GET", "POST"])
///             .attribute("description", "Echoes request details")
///     }
/// }
/// ```
///
/// # Running
///
/// After implementing `PluginHandler`, use [`PluginServer::builder()`] to
/// start the gRPC server:
///
/// ```rust,no_run
/// # use kbs_plugin_sdk::{PluginHandler, PluginServer, CapabilitiesBuilder};
/// # use kbs_plugin_sdk::{PluginRequest, PluginResponse, Request, Response, Status};
/// # #[derive(Default)]
/// # struct EchoPlugin;
/// # #[tonic::async_trait]
/// # impl PluginHandler for EchoPlugin {
/// #     async fn handle(&self, request: Request<PluginRequest>)
/// #         -> Result<Response<PluginResponse>, Status> { todo!() }
/// #     async fn capabilities(&self) -> CapabilitiesBuilder { todo!() }
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// PluginServer::builder()
///     .handler(EchoPlugin)
///     .bind("127.0.0.1:50051")
///     .serve()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[tonic::async_trait]
pub trait PluginHandler: Send + Sync + 'static {
    /// Handle an incoming plugin request.
    ///
    /// Receives the HTTP request details (method, path, query, body) forwarded
    /// from KBS and returns an HTTP response (body, status code, content type).
    ///
    /// # Arguments
    ///
    /// * `request` -- A tonic [`Request`] wrapping [`PluginRequest`] with:
    ///   - `method`: HTTP method string (`"GET"`, `"POST"`, etc.)
    ///   - `path`: Path segments after the plugin name (e.g., `["foo", "bar"]`)
    ///   - `query`: Query parameter map
    ///   - `body`: Raw request body bytes
    ///
    /// # Returns
    ///
    /// A [`PluginResponse`] with:
    /// - `body`: Response body bytes
    /// - `status_code`: HTTP status code (e.g., `200`)
    /// - `content_type`: MIME type string (e.g., `"application/json"`)
    ///
    /// Return `Err(Status)` for gRPC-level errors (e.g., `Status::internal("db error")`).
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status>;

    /// Return plugin capabilities metadata.
    ///
    /// Called once at startup by KBS to register the plugin. The returned
    /// capabilities tell KBS the plugin's name (used for routing), version,
    /// supported HTTP methods, and optional attributes.
    ///
    /// Use [`CapabilitiesBuilder`] for ergonomic construction:
    ///
    /// ```rust
    /// # use kbs_plugin_sdk::CapabilitiesBuilder;
    /// let caps = CapabilitiesBuilder::new("my-plugin", "1.0.0")
    ///     .methods(["GET", "POST"])
    ///     .attribute("author", "Acme Corp");
    /// ```
    async fn capabilities(&self) -> CapabilitiesBuilder;
}

/// Builder for plugin capabilities metadata.
///
/// Provides an ergonomic API for constructing [`GetCapabilitiesResponse`].
/// Used in [`PluginHandler::capabilities()`] to declare plugin metadata.
///
/// # Fields
///
/// | Field | Description | Required |
/// |-------|-------------|----------|
/// | `name` | Plugin name for routing (e.g., `"my-plugin"` for `/kbs/v0/my-plugin/...`) | Yes |
/// | `version` | Semantic version string | Yes |
/// | `methods` | Supported HTTP methods (`GET`, `POST`, etc.). Empty = all methods. | No |
/// | `attributes` | Open-ended key-value metadata for operational visibility | No |
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
///     .attribute("description", "JWT token validator")
///     .build();
///
/// assert_eq!(caps.name, "my-plugin");
/// assert_eq!(caps.version, "1.0.0");
/// assert_eq!(caps.supported_methods.len(), 2);
/// assert_eq!(caps.attributes["author"], "Acme Corp");
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
    ///
    /// The `name` is used by KBS for request routing. For example, a plugin
    /// named `"my-plugin"` receives requests at `/kbs/v0/my-plugin/...`.
    ///
    /// ```
    /// use kbs_plugin_sdk::CapabilitiesBuilder;
    ///
    /// let caps = CapabilitiesBuilder::new("token-validator", "2.1.0");
    /// let response = caps.build();
    /// assert_eq!(response.name, "token-validator");
    /// assert_eq!(response.version, "2.1.0");
    /// ```
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            supported_methods: Vec::new(),
            attributes: std::collections::HashMap::new(),
        }
    }

    /// Add a supported HTTP method (e.g., `"GET"`, `"POST"`).
    ///
    /// Call multiple times to add several methods:
    ///
    /// ```
    /// # use kbs_plugin_sdk::CapabilitiesBuilder;
    /// let caps = CapabilitiesBuilder::new("p", "1.0.0")
    ///     .method("GET")
    ///     .method("POST")
    ///     .build();
    /// assert_eq!(caps.supported_methods, vec!["GET", "POST"]);
    /// ```
    ///
    /// Or use [`methods`](Self::methods) to add multiple at once.
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.supported_methods.push(method.into());
        self
    }

    /// Add multiple supported HTTP methods at once.
    ///
    /// ```
    /// # use kbs_plugin_sdk::CapabilitiesBuilder;
    /// let caps = CapabilitiesBuilder::new("p", "1.0.0")
    ///     .methods(["GET", "POST", "PUT"])
    ///     .build();
    /// assert_eq!(caps.supported_methods.len(), 3);
    /// ```
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
    ///
    /// Attributes are open-ended metadata for operational visibility.
    /// Common attributes include `"author"`, `"description"`,
    /// `"min_kbs_version"`, and `"requires_attestation"`.
    ///
    /// ```
    /// # use kbs_plugin_sdk::CapabilitiesBuilder;
    /// let caps = CapabilitiesBuilder::new("p", "1.0.0")
    ///     .attribute("author", "Acme Corp")
    ///     .attribute("requires_attestation", "true")
    ///     .build();
    /// assert_eq!(caps.attributes["author"], "Acme Corp");
    /// ```
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Build the final [`GetCapabilitiesResponse`].
    ///
    /// Consumes the builder and returns the protobuf response message.
    /// This is called internally by the SDK when KBS sends a
    /// `GetCapabilities` RPC; plugin authors rarely need to call it directly.
    pub fn build(self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            name: self.name,
            version: self.version,
            supported_methods: self.supported_methods,
            attributes: self.attributes,
        }
    }
}
