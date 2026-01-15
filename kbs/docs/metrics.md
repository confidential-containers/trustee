# KBS Prometheus Metrics

The Key Broker Service (KBS) exposes Prometheus metrics on the `/metrics` HTTP endpoint served at the same port as KBS itself (see the `sockets` item in the `http_server` section of your KBS configuration file, 8080 by default).


The `/metrics` endpoint itself is excluded from request metrics collection to
avoid skewing the data with monitoring traffic.

## Available Metrics

### Build Information

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kbs_build_info` | Gauge | `version`, `git_hash`, `build_date` | KBS binary build information. Value is dummy (always `1`).  Build information is in label values.|

### HTTP Server Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kbs_http_requests_total` | Counter | Total count of HTTP requests to KBS protocol endpoints. |
| `kbs_http_request_duration_seconds` | Histogram | Distribution of request handling duration in seconds. Buckets: 0.5ms, 1ms, 5ms, 10ms, 50ms, 500ms, 1s. |
| `kbs_http_request_size_bytes` | Histogram | Distribution of request body sizes in bytes. Exponential buckets 32, 128, 512, 2048 and 8192 bytes. |
| `kbs_http_response_size_bytes` | Histogram | Distribution of response body sizes in bytes. Same buckets as request size. |
| `kbs_http_active_connections` | Gauge | Count of HTTP connections currently being processed. |

### Resource Access Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kbs_resource_reads_total` | Counter | `resource_path` | Count of resource read operations. The `resource_path` label contains the full resource path (e.g., `repository/type/tag`). |
| `kbs_resource_writes_total` | Counter | `resource_path` | Count of resource write operations. The `resource_path` label contains the full resource path. |

### Policy Evaluation Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kbs_policy_evaluations_total` | Counter | Total count of KBS policy evaluations. |
| `kbs_policy_approvals_total` | Counter | Total count of requests approved by KBS policy. |
| `kbs_policy_violations_total` | Counter | Total count of requests denied by KBS policy. |
| `kbs_policy_errors_total` | Counter | Total count of errors during KBS policy evaluation. |

### Attestation Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kbs_attestation_requests_total` | Counter | - | Total count of attestation requests. |
| `kbs_attestation_successes_total` | Counter | `tee_type` | Total count of successful attestations partitioned by TEE type |
| `kbs_attestation_failures_total` | Counter | `tee_type` | Total count of failed attestations. |
| `kbs_attestation_errors_total` | Counter | - | Total count of errors during attestation processing (e.g. malformed requests). |

### Authentication Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kbs_auth_requests_total` | Counter | Total count of authentication (RCAR handshake) requests. |
| `kbs_auth_successes_total` | Counter | Total count of successful authentication requests. |
| `kbs_auth_errors_total` | Counter | Total count of errors during authentication processing. |

## Example Prometheus Configuration

To scrape metrics from KBS, add a job to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'kbs'
    static_configs:
      - targets: ['kbs-host:8080'] # replace with host:port matching your KBS HTTP server socket config
    scheme: https  # or http if using insecure_http
    tls_config:
      insecure_skip_verify: true  # only if using self-signed certificates
```

## Kubernetes Deployment

When deploying KBS in Kubernetes, you can configure a `ServiceMonitor` for Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kbs
  labels:
    app: kbs
spec:
  selector:
    matchLabels:
      app: kbs
  endpoints:
    - port: 8080 # replace with port matching your KBS HTTP server socket config
      path: /metrics
      interval: 30s
```
