# KBS Plugin SDK for Rust

Rust SDK for writing Key Broker Service (KBS) external plugins with gRPC.

## Features

- Zero protoc dependency -- proto stubs compiled at build time and re-exported
- `PluginHandler` trait for plugin logic (two methods: `handle` + `capabilities`)
- `PluginServer` builder with automatic health service registration
- `TlsConfig` for mutual TLS and server-only TLS with fail-fast validation
- Minimal boilerplate -- focus on business logic, not gRPC setup

## Quick Start

Add the SDK as a dependency:

```toml
[dependencies]
kbs-plugin-sdk = { path = "../rust-sdk" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Implement a plugin:

```rust
use kbs_plugin_sdk::{PluginHandler, PluginServer, CapabilitiesBuilder};
use kbs_plugin_sdk::{PluginRequest, PluginResponse, Request, Response, Status};

#[derive(Default)]
struct MyPlugin;

#[tonic::async_trait]
impl PluginHandler for MyPlugin {
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(PluginResponse {
            body: req.body,
            status_code: 200,
            content_type: "application/octet-stream".to_string(),
        }))
    }

    async fn capabilities(&self) -> CapabilitiesBuilder {
        CapabilitiesBuilder::new("my-plugin", "1.0.0")
            .methods(["GET", "POST"])
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    PluginServer::builder()
        .handler(MyPlugin)
        .bind("127.0.0.1:50051")
        .serve()
        .await?;
    Ok(())
}
```

## Building

```bash
# Build the SDK
cargo build -p kbs-plugin-sdk

# Run the echo example
cargo run -p kbs-plugin-sdk --example echo

# Generate API documentation
cargo doc -p kbs-plugin-sdk --no-deps --open
```

## TLS Configuration

```rust
use kbs_plugin_sdk::TlsConfig;

// Mutual TLS (both sides authenticate)
let tls = TlsConfig::mtls(
    "ca.pem",
    "server.pem",
    "server.key",
);

// Server-only TLS (clients verify server)
let tls = TlsConfig::tls("server.pem", "server.key");

PluginServer::builder()
    .handler(MyPlugin)
    .bind("0.0.0.0:50051")
    .tls(tls)
    .serve()
    .await?;
```

## Example

See [`examples/echo.rs`](examples/echo.rs) for a complete working plugin.

## API Documentation

Full API docs are available via rustdoc:

```bash
cargo doc -p kbs-plugin-sdk --no-deps --open
```

## Related

- [Plugin Author Guide](../kbs/docs/PLUGIN_GUIDE.md) -- full lifecycle documentation
- [Go SDK](../go-sdk/README.md)
- [Python SDK](../python-sdk/README.md)
