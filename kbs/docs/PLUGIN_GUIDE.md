# KBS External Plugin Author Guide

This guide covers the full lifecycle of building, deploying, and operating
external KBS plugins: from writing your first handler to monitoring it in
production.

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Writing a Plugin](#writing-a-plugin)
4. [Building and Packaging](#building-and-packaging)
5. [Configuring KBS](#configuring-kbs)
6. [Deploying](#deploying)
7. [Monitoring](#monitoring)
8. [Reference](#reference)

---

## Introduction

### What Are External Plugins?

KBS (Key Broker Service) external plugins are standalone gRPC services that
extend KBS with custom endpoints. When a client sends a request to
`/kbs/v0/<plugin-name>/...`, KBS forwards it to the corresponding external
plugin over gRPC, and returns the plugin's response to the client.

This architecture lets you add new capabilities -- secret injection, policy
evaluation, certificate issuance, custom key management -- without modifying
the KBS codebase. Each plugin runs as an independent process or container,
communicating with KBS via the `kbs.plugin.v1.KbsPlugin` gRPC service
defined in [`protos/plugin.proto`](../../protos/plugin.proto).

### How Authentication Works for Plugins

KBS gates every plugin request through one of two authentication paths.
Before forwarding a request, KBS calls the plugin's `ValidateAuth` RPC to
ask which path to use for that specific request:

```
                    plugin.ValidateAuth(request)
                            │
               ┌────────────┴────────────────┐
               │ requires_admin_auth=true     │ requires_admin_auth=false
               ▼                             ▼
      Admin auth check            Attestation token check
                                  + policy evaluation
               │                             │
               ▼                             ▼
        plugin.Handle()               plugin.Handle()
               │                             │
               ▼                             ▼
        Return response           plugin.NeedsEncryption()
                                             │
                                  ├── true → JWE response
                                  └── false → raw response
```

- **`requires_admin_auth = true`** -- KBS checks admin credentials before
  forwarding the request. Use this for management or provisioning
  endpoints where the caller is an operator, not a TEE workload.

- **`requires_admin_auth = false`** -- KBS requires a valid attestation
  token and evaluates the configured resource policy before forwarding the
  request. This is the standard path for TEE workloads retrieving secrets.

- **`NeedsEncryption`** -- after `Handle` returns, KBS calls `NeedsEncryption`
  to ask whether the response should be JWE-encrypted with the TEE's ephemeral
  public key. Return `true` for any response containing secret material; return
  `false` for non-sensitive data (status, metrics, public certificates).
  JWE encryption ensures only the TEE that completed the RCAR handshake can
  decrypt the response — HTTPS alone is not sufficient for secrets.

  > **Note**: `NeedsEncryption` is only called on the attestation-gated path
  > (`requires_admin_auth = false`). JWE encryption requires the TEE's public
  > key from the attestation token, which is not available on the admin path.
  > Your `NeedsEncryption` implementation will never be invoked for requests
  > that `ValidateAuth` routes to admin auth.

Because both decisions are made per-request via gRPC, a single plugin binary
can implement the full pattern used by built-in plugins — for example,
`GET` (read secret) uses attestation + encryption while `POST` (provision
secret) uses admin auth, differentiated by inspecting `method` or `path`.

### Who Is This For?

Developers who want to extend KBS with custom endpoints. You should be
comfortable with Rust and have a basic understanding of gRPC concepts
(services, messages, metadata).

### Prerequisites

- Rust 1.70+
- A running KBS instance (for integration testing)
- Familiarity with gRPC (helpful but not required -- the SDK abstracts it)

### SDK Availability

| Language | Package | Documentation |
|----------|---------|---------------|
| Rust | [`rust-sdk`](../../rust-sdk/) | Crate-level rustdoc in `src/lib.rs` |

The SDK provides pre-generated protobuf stubs, a handler abstraction,
automatic health service registration, and TLS configuration helpers.

---

## Quick Start

Every plugin implements four operations:

1. **Handle** -- process an HTTP request forwarded from KBS
2. **GetCapabilities** -- return plugin metadata (name, version, supported methods)
3. **ValidateAuth** -- decide per-request whether to require admin or attestation auth
4. **NeedsEncryption** -- decide per-request whether to JWE-encrypt the response

Below is a minimal working example. For a complete runnable example see the
echo plugin linked below.

### Rust

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
            body: b"Hello from Rust plugin".to_vec(),
            status_code: 200,
            content_type: "text/plain".to_string(),
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

Full example: [`rust-sdk/examples/echo.rs`](../../rust-sdk/examples/echo.rs)

---

## Writing a Plugin

### Implementing the Handler

Each SDK provides a handler abstraction. You implement two methods:

| Method | Purpose | Called When |
|--------|---------|------------|
| `handle` | Process an HTTP request | Every request to your plugin |
| `capabilities` | Return plugin metadata | Once at KBS startup |
| `validate_auth` | Decide admin vs attestation auth for this request | Before every `handle` call |
| `needs_encryption` | Decide whether to JWE-encrypt the response | After every `handle` call |

**Request fields** (from `PluginRequest`):

| Field | Type | Description |
|-------|------|-------------|
| `body` | bytes | Raw HTTP request body |
| `query` | map<string, string> | URL query parameters |
| `path` | repeated string | Path segments after plugin name (`/kbs/v0/my-plugin/a/b` -> `["a", "b"]`) |
| `method` | string | HTTP method (`GET`, `POST`, `PUT`, `DELETE`) |

**Response fields** (from `PluginResponse`):

| Field | Type | Description |
|-------|------|-------------|
| `body` | bytes | Response body |
| `status_code` | int32 | HTTP status code (0 = use default 200) |
| `content_type` | string | Content type (empty = use default) |

### Declaring Capabilities

The `GetCapabilities` RPC returns metadata that KBS uses for routing and
operational visibility. KBS calls it once at plugin startup.

**Required fields:**

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Plugin name for routing (`/kbs/v0/<name>/...`) | `"secret-store"` |
| `version` | Semantic version string | `"1.2.0"` |
| `supported_methods` | HTTP methods the plugin handles (empty = all) | `["GET", "POST"]` |

**Optional fields:**

| Field | Description | Example |
|-------|-------------|---------|
| `attributes` | Key-value metadata for operational visibility | `{"author": "Acme Corp"}` |

If a request arrives with an HTTP method not in `supported_methods`, KBS
returns 405 Method Not Allowed without forwarding it to the plugin.

### Accessing Request Context via gRPC Metadata

KBS forwards session and attestation context to plugins via gRPC metadata
headers on every `Handle` RPC. Plugins can read these to make authorization
decisions:

| Header | Type | Description |
|--------|------|-------------|
| `kbs-session-id` | string | Client session identifier (cookie-based auth only) |
| `kbs-tee-type` | string | TEE type from attestation (e.g., `"SevSnp"`, `"Tdx"`); cookie-based auth only |
| `kbs-attested` | string | Whether the caller is attested (`"true"` / `"false"`) |

> **Note on `kbs-tee-type`**: This header is populated for session-cookie authentication
> (the standard RCAR handshake). For Bearer token authentication it will be empty.
> If your plugin needs to gate on TEE type, ensure clients use the session-cookie flow.
>
> **Important**: These metadata headers are for operational visibility and logging.
> KBS enforces all authentication and policy checks before your plugin is called — do not
> use these headers as the sole gate for authorization decisions.

Access via `request.metadata()` in the `handle` implementation:

```rust
async fn handle(&self, request: Request<PluginRequest>) -> Result<Response<PluginResponse>, Status> {
    let metadata = request.metadata();

    if let Some(session_id) = metadata.get("kbs-session-id") {
        let session = session_id.to_str().map_err(|_| Status::internal("bad metadata"))?;
        // Use session context...
    }

    let is_attested = metadata.get("kbs-attested")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "true")
        .unwrap_or(false);

    // Process request...
}
```

### Error Handling

Return errors as gRPC status codes. KBS maps them to HTTP status codes:

| gRPC Status | HTTP Status | When to Use |
|-------------|-------------|-------------|
| `OK` | 200 | Success |
| `INVALID_ARGUMENT` | 400 | Bad request data |
| `UNAUTHENTICATED` | 401 | Missing/invalid credentials |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `UNAVAILABLE` / `DEADLINE_EXCEEDED` | 503 | Plugin service unavailable |
| `INTERNAL` and others | 500 | Unexpected server error |

Note: KBS returns 405 Method Not Allowed automatically (without calling the
plugin) when the request method is not in `supported_methods`.

Alternatively, set `status_code` and `content_type` in `PluginResponse`
directly. KBS propagates both fields to the HTTP response on success. Note:
these fields are ignored when `encrypted = true` (the response format is
fixed by the KBS protocol in that case).

---

## Building and Packaging

### Local Development

Run the echo plugin directly during development:

```bash
cargo run -p kbs-plugin-sdk --example echo
```

The example starts a server on `127.0.0.1:50051` with automatic gRPC health
service registration. Test with grpcurl:

```bash
# Check health
grpcurl -plaintext -d '{"service":"kbs.plugin.v1.KbsPlugin"}' \
  127.0.0.1:50051 grpc.health.v1.Health/Check

# Call Handle directly
grpcurl -plaintext -d '{"method":"GET","path":["test"]}' \
  127.0.0.1:50051 kbs.plugin.v1.KbsPlugin/Handle
```

### Docker Containerization

The Rust SDK ships a Dockerfile example in `rust-sdk/examples/echo/` using
a multi-stage build for a minimal image. Use it as a template for your own
plugin container.

### CI/CD Integration

General pattern for building plugin containers in CI:

```yaml
# GitHub Actions example
steps:
  - uses: actions/checkout@v4
  - name: Build plugin image
    run: |
      docker build -t my-plugin:${{ github.sha }} \
        -f path/to/Dockerfile .
  - name: Push to registry
    run: |
      docker push my-plugin:${{ github.sha }}
```

Adapt the build context and Dockerfile path for your SDK and project
structure.

---

## Configuring KBS

### Plugin Registration

Register external plugins in your KBS configuration file (`kbs-config.toml`)
using the `[[plugins]]` array with `name = "external"`:

```toml
[[plugins]]
name = "external"
plugin_name = "my-plugin"
endpoint = "http://localhost:50051"
tls_mode = "insecure"
```

The `plugin_name` field determines the URL path for routing. With the config
above, requests to `/kbs/v0/my-plugin/...` are forwarded to the plugin.

**Multiple plugins** -- add additional `[[plugins]]` entries:

```toml
[[plugins]]
name = "external"
plugin_name = "secret-store"
endpoint = "http://secret-svc:50051"
tls_mode = "insecure"

[[plugins]]
name = "external"
plugin_name = "policy-engine"
endpoint = "https://policy-svc:50052"
tls_mode = "mtls"
ca_cert_path = "/etc/kbs/certs/ca.pem"
client_cert_path = "/etc/kbs/certs/client.pem"
client_key_path = "/etc/kbs/certs/client.key"
```

**Name collisions:** If `plugin_name` matches a compiled-in plugin or another
external plugin entry, KBS fails startup with a fatal error. Each `plugin_name`
must be unique across all `[[plugins]]` entries.

### TLS Configuration

Three TLS modes control the connection between KBS (client) and the plugin
(server):

| Mode | Value | Description | Use Case |
|------|-------|-------------|----------|
| Mutual TLS | `"mtls"` | Both sides authenticate with certificates | Production |
| Server TLS | `"tls"` | KBS verifies plugin certificate, no client cert | Internal network |
| Insecure | `"insecure"` | No TLS (plaintext gRPC) | Local development only |

**Mutual TLS** (recommended for production):

```toml
[[plugins]]
name = "external"
plugin_name = "my-plugin"
endpoint = "https://plugin-host:50051"
tls_mode = "mtls"
ca_cert_path = "/etc/kbs/certs/ca.pem"
client_cert_path = "/etc/kbs/certs/client.pem"
client_key_path = "/etc/kbs/certs/client.key"
```

**Server TLS:**

```toml
[[plugins]]
name = "external"
plugin_name = "my-plugin"
endpoint = "https://plugin-host:50051"
tls_mode = "tls"
ca_cert_path = "/etc/kbs/certs/ca.pem"
```

**Important:** KBS validates TLS configuration at startup (fail-fast). If
certificate files are missing, the endpoint scheme mismatches the TLS mode,
or required paths are absent, KBS exits with a clear error message.

> **Warning:** Never use `tls_mode = "insecure"` in production. Plaintext
> gRPC exposes secrets and attestation data to network observers.

### Timeout and Retry Settings

Configure per-plugin timeouts:

```toml
[[plugins]]
name = "external"
plugin_name = "my-plugin"
endpoint = "http://localhost:50051"
timeout_ms = 5000  # 5 second timeout per request
```

If `timeout_ms` is not set, KBS uses no explicit timeout (the gRPC default
applies). KBS maintains a connection pool to each plugin and uses exponential
backoff for transient connection failures.

---

## Deploying

### Standalone Deployment

Run the plugin as a separate process or container alongside KBS:

```
+--------+         gRPC          +--------+
|  KBS   | --------------------> | Plugin |
| :8080  |   (localhost:50051)   | :50051 |
+--------+         (TCP)         +--------+
```

For local development, start the plugin and KBS in separate terminals:

```bash
# Terminal 1: Start plugin
./my-plugin

# Terminal 2: Start KBS with external plugin config
cargo run --bin kbs --features external-plugin -- \
    --config-file kbs-config.toml

# Terminal 3: Test
curl http://127.0.0.1:8080/kbs/v0/my-plugin/test
```

Here is a concrete example using the Rust echo plugin and the test config
at [`kbs/test/config/external-plugin.toml`](../test/config/external-plugin.toml):

```bash
# Terminal 1: Start the echo plugin
cargo run -p kbs-plugin-sdk --example echo

# Terminal 2: Start KBS with the external plugin test config
cd kbs
cargo run --bin kbs --features external-plugin -- \
    --config-file test/config/external-plugin.toml

# Terminal 3: Test (port 8085 and plugin name "echo-test" match the test config)
curl http://127.0.0.1:8085/kbs/v0/echo-test/test
```

Expected response:

```
Echo: method=GET, path=["test"], query={}, body_len=0
```

For containerized deployments, ensure the plugin container is network-
accessible from the KBS container (same Docker network, pod, or host).

### Kubernetes Deployment

Deploy the plugin as a separate Deployment and Service, then configure KBS
to connect via the Service DNS name:

```yaml
# plugin-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-plugin
spec:
  replicas: 2
  selector:
    matchLabels:
      app: my-plugin
  template:
    metadata:
      labels:
        app: my-plugin
    spec:
      containers:
        - name: my-plugin
          image: my-plugin:latest
          ports:
            - containerPort: 50051
              protocol: TCP
          livenessProbe:
            grpc:
              port: 50051
              service: kbs.plugin.v1.KbsPlugin
            periodSeconds: 10
          readinessProbe:
            grpc:
              port: 50051
              service: kbs.plugin.v1.KbsPlugin
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: my-plugin
spec:
  selector:
    app: my-plugin
  ports:
    - port: 50051
      targetPort: 50051
      protocol: TCP
```

In the KBS config, point to the Kubernetes Service:

```toml
[[plugins]]
name = "external"
plugin_name = "my-plugin"
endpoint = "http://my-plugin.default.svc.cluster.local:50051"
tls_mode = "insecure"  # or use mTLS with cert-manager
```

### Health Checks

All three SDKs automatically register a `grpc.health.v1.Health` service
that reports `SERVING` status for `kbs.plugin.v1.KbsPlugin`. KBS uses this
for:

- **Startup probes:** Verifying the plugin is ready before routing requests
- **Periodic monitoring:** Background health checks every 10 seconds
- **State tracking:** Marking plugins as Healthy or Unavailable

Test health manually:

```bash
grpcurl -plaintext -d '{"service":"kbs.plugin.v1.KbsPlugin"}' \
  127.0.0.1:50051 grpc.health.v1.Health/Check
```

Expected response:

```json
{"status": "SERVING"}
```

### End-to-End Tests

The Makefile in `kbs/test/` includes integration tests that exercise the
full KBS-to-plugin flow. These tests build the echo plugin and KBS, start
them as background processes, run curl-based assertions, and clean up
afterwards.

**Available test targets:**

| Target | Description |
|--------|-------------|
| `test-ext-plugin` | Plaintext plugin on `:50051`, KBS on `:8085` |
| `test-ext-plugin-metrics` | Verify `/metrics` endpoint has plugin counters |
| `test-ext-plugin-tls` | TLS plugin on `:50052`, KBS on `:8086` |
| `test-ext-plugin-attest` | Attestation-gated access on `:8087` |
| `e2e-ext-plugin` | Run all four tests with automatic cleanup |
| `stop-ext-plugins` | Stop all external plugin processes |

**Run all external plugin e2e tests:**

```bash
cd kbs/test
make e2e-ext-plugin
```

**Run a single test (manual cleanup):**

```bash
cd kbs/test
make test-ext-plugin
# ... inspect results ...
make stop-ext-plugins
```

**Stop all processes if a test left them running:**

```bash
cd kbs/test
make stop-ext-plugins
```

---

## Monitoring

### Metrics Exposed by KBS

KBS exposes per-plugin Prometheus metrics at the `/metrics` endpoint.
These metrics are labeled with `plugin_name` to distinguish between plugins:

| Metric | Type | Description |
|--------|------|-------------|
| `kbs_plugin_requests_total{plugin_name="..."}` | Counter | Total requests forwarded to the plugin |
| `kbs_plugin_request_duration_seconds{plugin_name="..."}` | Histogram | Request latency distribution (seconds) |
| `kbs_plugin_errors_total{plugin_name="..."}` | Counter | Total failed requests (gRPC errors) |

Access metrics:

```bash
curl http://127.0.0.1:8080/metrics | grep kbs_plugin
```

Example output:

```
kbs_plugin_requests_total{plugin_name="my-plugin"} 142
kbs_plugin_request_duration_seconds_bucket{plugin_name="my-plugin",le="0.01"} 130
kbs_plugin_request_duration_seconds_bucket{plugin_name="my-plugin",le="0.1"} 140
kbs_plugin_errors_total{plugin_name="my-plugin"} 2
```

Use these metrics in Grafana dashboards or Prometheus alerting rules to
monitor plugin health and performance.

### Plugin-Side Logging

Emit structured logs from your plugin for debugging and audit trails.
Include the session ID from gRPC metadata for request correlation:

```rust
tracing::info!(
    session_id = %session_id,
    method = %req.method,
    "handling plugin request"
);
```

### Troubleshooting Common Issues

**Connection refused**

At startup:
```
Failed to create channel for initial health check
Plugin failed initial health check
```

At runtime (logged as warnings, and subsequent requests are rejected):
```
Plugin 'my-plugin' became unavailable
Plugin 'my-plugin' is unavailable (health check failing)
```

Cause: Plugin is not running or not listening on the configured endpoint.
Fix: Verify the plugin process is running and the endpoint in `kbs-config.toml`
matches the plugin's bind address. Check firewall rules and network
connectivity between KBS and the plugin.

**TLS certificate errors**

```
Plugin 'my-plugin': TLS mode requires https:// endpoint, got http://
Plugin 'my-plugin': mtls mode requires ca_cert_path
Plugin 'my-plugin': mtls mode requires client_cert_path and client_key_path
Plugin 'my-plugin': tls mode requires ca_cert_path
```

Cause: Mismatch between `tls_mode` and endpoint scheme, or missing
certificate paths.
Fix: Use `http://` with `tls_mode = "insecure"` or `https://` with
`tls_mode = "tls"` / `"mtls"`. Verify certificate paths exist and
certificates are valid (not expired, correct CA chain).

**Request timeout**

A timeout surfaces as a gRPC `DeadlineExceeded` status. KBS marks the plugin
as unavailable and subsequent requests are rejected until the health check
recovers:

```
Plugin 'my-plugin' became unavailable
Plugin 'my-plugin' is unavailable (health check failing)
```

Cause: Plugin took too long to respond.
Fix: Increase `timeout_ms` in the plugin configuration, or optimize the
plugin's request handling. Check for blocking operations in async handlers.

**Name collision**

```
Plugin name collision detected: 'my-plugin' is already registered. Each plugin must have a unique name.
```

Cause: `plugin_name` matches another plugin (built-in or external).
Fix: Choose a unique `plugin_name` that does not conflict with built-in
plugins (`resource`, `attestation`, etc.) or other external plugins.

**Plugin not found (404)**

```
GET /kbs/v0/my-plugin/test -> 404 Not Found
```

Cause: No plugin registered with `plugin_name = "my-plugin"`.
Fix: Check `kbs-config.toml` for the `[[plugins]]` entry. Ensure KBS was
started with the `--features external-plugin` flag and the plugin passed
its `GetCapabilities` check at startup.

---

## Reference

### Complete API Documentation

The plugin gRPC API is defined in
[`protos/plugin.proto`](../../protos/plugin.proto). This proto file defines
the `KbsPlugin` service with two RPCs:

```protobuf
service KbsPlugin {
    rpc Handle(PluginRequest) returns (PluginResponse) {};
    rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse) {};
    rpc ValidateAuth(PluginRequest) returns (ValidateAuthResponse) {};
    rpc NeedsEncryption(PluginRequest) returns (NeedsEncryptionResponse) {};
}
```

API documentation: crate docs in
[`rust-sdk/src/lib.rs`](../../rust-sdk/src/lib.rs)
(run `cargo doc -p kbs-plugin-sdk --open`)

### Example Plugin

The Rust SDK ships an echo plugin that demonstrates the full API:

[`rust-sdk/examples/echo.rs`](../../rust-sdk/examples/echo.rs) — run with
`cargo run -p kbs-plugin-sdk --example echo`

### Configuration Reference

**ExternalPluginConfig fields:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | -- | Must be `"external"` |
| `plugin_name` | string | Yes | -- | Plugin name for routing |
| `endpoint` | string | Yes | -- | Plugin gRPC endpoint URL |
| `tls_mode` | string | No | `"tls"` | TLS mode: `"insecure"`, `"tls"`, `"mtls"` |
| `ca_cert_path` | string | No | -- | CA certificate (required for `tls`/`mtls`) |
| `client_cert_path` | string | No | -- | Client certificate (required for `mtls`) |
| `client_key_path` | string | No | -- | Client key (required for `mtls`) |
| `timeout_ms` | integer | No | -- | Request timeout in milliseconds |

**TlsMode values:**

| Value | KBS Side | Plugin Side | Certificate Requirements |
|-------|----------|-------------|--------------------------|
| `insecure` | No TLS | No TLS | None |
| `tls` | Verifies server cert | Presents server cert | `ca_cert_path` on KBS; server cert/key on plugin |
| `mtls` | Verifies server cert + presents client cert | Verifies client cert + presents server cert | All cert paths on both sides |

---

*This guide covers the KBS external plugin system built on the
`kbs.plugin.v1.KbsPlugin` gRPC service. For KBS core documentation, see
[`kbs/docs/`](.).*
