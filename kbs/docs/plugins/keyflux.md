# KeyFlux Plugin

The KeyFlux plugin dynamically generates cryptographic credentials (keys and certificates) for confidential VMs (pod VMs/sandboxes) and workload owners. It enables secure mutual authentication between servers running in confidential VMs and their clients (workload owners), supporting use cases like SplitAPI and peer-pods architectures.

## Overview

KeyFlux creates a separate Certificate Authority (CA) for each pod VM, providing independent roots of trust that isolate security domains. If one pod's CA is compromised, others remain secure. The plugin supports multiple secret types:

- **TLS credentials**: X.509 certificates and private keys for mutual TLS authentication
- **Symmetric keys**: Shared secrets for symmetric encryption
- **Ed25519 keys**: Elliptic curve keys for signing and encryption
- **RSA keys**: RSA key pairs for asymmetric cryptography

Credentials are stored in non-persistent memory and are automatically cleaned up when the service restarts, enhancing security at the cost of requiring re-attestation after restarts.

## Architecture

The plugin operates in two phases:

1. **Server Phase**: When a pod VM requests credentials via `get-resource`, KeyFlux:
   - Creates a unique CA for the pod (if not exists)
   - Generates server-side credentials (private keys, certificates)
   - Stores client-side credentials for later retrieval

2. **Client Phase**: When a workload owner requests credentials via authenticated APIs:
   - Retrieves previously generated client-side credentials
   - Returns matching secrets for the specified pod

## Setup

### 1. Build KBS with KeyFlux Plugin

Build KBS with the `keyflux` cargo feature enabled:

```bash
cd kbs
make background-check-kbs POLICY_ENGINE=opa KEYFLUX_PLUGIN=true
```

### 2. Configure the Plugin

Add the KeyFlux plugin configuration to your KBS config file (e.g., `kbs/config/kbs-config.toml`):

```toml
[[plugins]]
name = "keyflux"

[plugins.keyflux.ca]
country = "US"
state = "California"
locality = "San Francisco"
organization = "My Organization"
org_unit = "Security Team"
common_name = "KeyFlux CA"
validity_days = 3650

[plugins.keyflux.query]
required = ["id"]

[plugins.keyflux.query.spec]
required = true

[plugins.keyflux.limits]
symmetric_key_size = 32
rsa_bits = 2048
allow_types = ["tls", "symmetric", "ed25519", "rsa"]
```

#### Configuration Options

**CA Configuration** (`plugins.keyflux.ca`):
- `country`: Two-letter country code (default: "AA")
- `state`: State or province name (default: "Default State")
- `locality`: City or locality (default: "Default City")
- `organization`: Organization name (default: "Default Organization")
- `org_unit`: Organizational unit (default: "Default Unit")
- `common_name`: CA common name (default: "KeyFluxCA")
- `validity_days`: Certificate validity period in days (default: 3650)

**Query Configuration** (`plugins.keyflux.query`):
- `required`: List of required query parameters (default: `["id"]`)
- `spec.required`: Whether the `spec` parameter is mandatory (default: `true`)

**Limits Configuration** (`plugins.keyflux.limits`):
- `symmetric_key_size`: Size of symmetric keys in bytes (default: 32)
- `rsa_bits`: RSA key size in bits (default: 2048)
- `allow_types`: Allowed secret types (default: `["tls", "symmetric", "ed25519", "rsa"]`)

### 3. Start KBS

```bash
../target/release/kbs --config-file ./config/kbs-config.toml
```

### 4. Configure Resource Policy

Update your KBS resource policy to allow the keyflux plugin. Example policy (`sample_policies/allow_all.rego`):

```rego
package policy

default allow = false

plugin = data.plugin

allow if {
    plugin in ["resource", "keyflux"]
}
```

Set the policy using kbs-client:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    set-resource-policy --policy-file sample_policies/allow_all.rego
```


## Pod VM APIs (Unauthenticated)

These APIs are called by pod VMs after successful attestation.

### Get Credentials

Request credentials for a pod VM by specifying the required secret types and counts.

**Endpoint**: `GET /kbs/v0/keyflux/credentials`

**Query Parameters**:
- `id` (required): Unique identifier for the pod
- `spec` (required): Secret specification in format `type:count;type:count;...`

**Supported Secret Types**:
- `tls`: TLS certificate and private key
- `sym` or `symmetric`: Symmetric encryption key
- `ed25519` or `pkey`: Ed25519 key pair
- `rsa`: RSA key pair

**Example Request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    get-resource --path "credentials?id=pod123&spec=tls:1;sym:2;ed25519:1"
```

**Response Format**:

```json
{
  "entity": "server",
  "secrets": {
    "tls_0": {
      "type": "Tls",
      "private_key": [45, 45, 45, ...],
      "cert": [45, 45, 45, ...],
      "ca_cert": [45, 45, 45, ...]
    },
    "sym_0": {
      "type": "Symmetric",
      "key": [176, 33, 138, ...]
    },
    "sym_1": {
      "type": "Symmetric",
      "key": [92, 145, 201, ...]
    },
    "ed25519_key_0": {
      "type": "Ed25519",
      "key": [45, 45, 45, ...]
    }
  }
}
```

The response is automatically encrypted using the TEE's public key and must be decrypted by the pod VM.

## Owner/Client APIs (Authenticated)

These APIs require authentication using the KBS private key and are intended for workload owners.

### List Pods

Retrieve a list of all pod identifiers that have credentials stored.

**Endpoint**: `POST /kbs/v0/keyflux/list_pods`

**Example Request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    list-pods
```

**Response**:

```json
["pod123", "pod456", "pod789"]
```

### Get Client Credentials

Retrieve client-side credentials for a specific pod. The credentials match the secrets previously generated for the server.

**Endpoint**: `POST /kbs/v0/keyflux/client_creds`

**Query Parameters**:
- `id` (required): Pod identifier (must match the ID used when requesting server credentials)

**Example Request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    get-client-creds --query "id=pod123"
```

**Response Format**:

```json
{
  "entity": "client",
  "secrets": {
    "tls_0": {
      "type": "Tls",
      "private_key": [45, 45, 45, ...],
      "cert": [45, 45, 45, ...],
      "ca_cert": [45, 45, 45, ...]
    },
    "sym_0": {
      "type": "Symmetric",
      "key": [176, 33, 138, ...]
    },
    "sym_1": {
      "type": "Symmetric",
      "key": [92, 145, 201, ...]
    },
    "ed25519_key_0": {
      "type": "Ed25519",
      "key": [45, 45, 45, ...]
    }
  }
}
```

**Note**: For TLS credentials, the client receives a different certificate than the server, but both are signed by the same CA. For symmetric keys and public keys (Ed25519, RSA), the client receives the same key or the corresponding public key.

### Update Certificate Details

Customize certificate details for server and/or client certificates before they are generated.

**Endpoint**: `POST /kbs/v0/keyflux/update_cert`

**Query Parameters**:
- `id` (required): Pod identifier

**Request Body**:

```json
{
  "server": {
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "organization": "My Org",
    "org_unit": "Engineering",
    "common_name": "Pod Server",
    "validity_days": 180
  },
  "client": {
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "organization": "My Org",
    "org_unit": "Client Team",
    "common_name": "Workload Owner",
    "validity_days": 180
  }
}
```

**Example Request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    update-cert --query "id=123" --spec-file test/spec.json
```
**Where the  spec file looks like this:**

cat test/spec.json 
```json
{
  "server": {
    "common_name": "my-server",
    "organization": "MyOrg"
  },
  "client": {
    "common_name": "my-client"
  }
}
```

## Usage Workflow

### Complete Example

1. **Start KBS** with KeyFlux plugin enabled

2. **Set resource policy** to allow keyflux plugin

3. **Pod VM requests credentials** (after attestation):
   ```bash
   kbs-client --url http://localhost:8090 \
       get-resource --path "credentials?id=pod123&spec=tls:1;sym:1"
   ```

4. **Workload owner lists pods**:
   ```bash
   kbs-client --url http://localhost:8090 \
       config --auth-private-key config/private.key \
       list-pods
   ```

5. **Workload owner retrieves client credentials**:
   ```bash
   kbs-client --url http://localhost:8090 \
       config --auth-private-key config/private.key \
       get-client-creds --query "id=pod123"
   ```

6. **Establish mutual TLS connection** between pod VM (server) and workload owner (client) using the credentials

## Security Considerations

- **Per-Pod CA Isolation**: Each pod has its own CA, limiting the blast radius of a compromise
- **Non-Persistent Storage**: Credentials are stored in memory only and are lost on restart
- **Attestation Required**: Pod VMs must pass attestation before receiving credentials
- **Authentication Required**: Client APIs require KBS private key authentication
- **Automatic Encryption**: Server credentials are automatically encrypted with TEE public key

## Troubleshooting

### Missing Required Parameters

**Error**: `Missing required query parameter: id`

**Solution**: Ensure all required query parameters are provided in the request URL.

### Spec Not Found

**Error**: `Spec not found for req_id: pod123`

**Solution**: The pod must request server credentials first before client credentials can be retrieved.

### Invalid Spec Format

**Error**: `Invalid spec format: tls`

**Solution**: Ensure the spec parameter follows the format `type:count`, e.g., `tls:1;sym:2`.

### CA Not Found

**Error**: `CA not found for sandbox: pod123`

**Solution**: The pod must request server credentials first to create the CA.


