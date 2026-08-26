# SecretProv Plugin

The SecretProv plugin dynamically generates cryptographic credentials (keys and certificates) for confidential VMs and workload owners. It enables secure mutual authentication between servers running inside confidential VMs and their clients (workload owners).

## Overview

SecretProv creates a separate Certificate Authority (CA) for each confidential VM, providing independent roots of trust. If one VM's CA is compromised, others remain secure. The plugin supports multiple secret types:

- **TLS credentials**: X.509 certificates and private keys for mutual TLS authentication
- **Symmetric keys**: Shared secrets for symmetric encryption
- **Ed25519 keys**: Elliptic curve keys for signing and encryption
- **RSA keys**: RSA key pairs for asymmetric cryptography
- **P-256 keys**: ECDSA P-256 key pairs with a self-signed certificate
- **Random bytes**: Cryptographically-random byte sequences shared identically between the server and the owner

Credentials are stored in non-persistent memory and are automatically cleaned up when the service restarts.

## Architecture

The plugin operates in two phases:

1. **Server Phase**: When a confidential VM requests credentials via `GET /credentials`, SecretProv generates server-side credentials (private keys, certificates) and stores the corresponding public material for later retrieval.

2. **Client Phase**: When a workload owner requests credentials via authenticated `POST /client_creds`, the plugin returns the matching public-side material (public keys, CA-signed client cert for TLS, etc.).

## Setup

### 1. Build KBS with SecretProv Plugin

Build KBS with the `secretprov-plugin` cargo feature enabled:

```bash
cd kbs
make background-check-kbs POLICY_ENGINE=opa SECRETPROV_PLUGIN=true
```

### 2. Configure the Plugin

Add the SecretProv plugin configuration to your KBS config file (e.g., `kbs/config/kbs-config.toml`):

```toml
[[plugins]]
name = "secretprov"

[plugins.secretprov.ca]
country = "US"
state = "California"
locality = "San Francisco"
organization = "My Organization"
org_unit = "Security Team"
common_name = "SecretProv CA"
validity_days = 3650

[plugins.secretprov.query]
required = ["name", "ns"]
spec_required = true

[plugins.secretprov.limits]
symmetric_key_size = 32
rsa_bits = 2048
random_bytes_size = 32
supported_types = ["tls", "symmetric", "ed25519", "rsa", "p256", "random"]
```

#### Configuration Options

**CA Configuration** (`plugins.secretprov.ca`):
- `country`: Two-letter country code (default: `"AA"`)
- `state`: State or province name (default: `"Default State"`)
- `locality`: City or locality (default: `"Default City"`)
- `organization`: Organization name (default: `"Default Organization"`)
- `org_unit`: Organizational unit (default: `"Default Unit"`)
- `common_name`: CA common name (default: `"NOT_SET"`)
- `validity_days`: Certificate validity period in days (default: `3650`)

**Query Configuration** (`plugins.secretprov.query`):
- `required`: List of query parameters whose values are joined to build the per-VM identity key (default: `["name", "ns"]`). These values are supplied by the guest itself — the plugin does not verify them against any external source; policy enforcement is delegated to the KBS resource policy.
- `spec_required`: Whether `secret_name` and `secret_type` are mandatory on every request (default: `true`)

**Limits Configuration** (`plugins.secretprov.limits`):
- `symmetric_key_size`: Size of symmetric keys in bytes (default: `32`)
- `rsa_bits`: RSA key size in bits (default: `2048`)
- `random_bytes_size`: Number of random bytes to generate (default: `32`)
- `supported_types`: Allowed secret types (default: `["tls", "symmetric", "ed25519", "rsa", "p256", "random"]`)

### 3. Start KBS

```bash
../target/release/kbs --config-file ./config/kbs-config.toml
```

### 4. Configure Resource Policy

Update your KBS resource policy to allow the secretprov plugin. Example policy (`sample_policies/allow_all.rego`):

```rego
package policy

default allow = false

plugin = data.plugin

allow if {
    plugin in ["resource", "secretprov"]
}
```

Set the policy using kbs-client:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    set-resource-policy --policy-file sample_policies/allow_all.rego
```


## Confidential VM APIs (Unauthenticated, TEE-Encrypted Response)

These APIs are called by confidential VMs after successful attestation. Responses are automatically encrypted using the TEE's public key and delivered via the standard KBS protocol envelope.

### Get Credentials

Request a single secret (key or certificate) for a confidential VM.

**Endpoint**: `GET /kbs/v0/secretprov/credentials`

**Query Parameters**:
- `name` (required by default): Workload name
- `ns` (required by default): Namespace
- `secret_name` (required): Logical name for this secret (e.g. `grpc`)
- `secret_type` (required): One of `tls`, `symmetric`, `ed25519`, `rsa`, `p256`, `random`

**Example request via the KBS REST API** (e.g. from inside a confidential VM using the Attestation Service REST client):

```http
GET /kbs/v0/secretprov/credentials?name=myvm&ns=default&secret_name=grpc&secret_type=tls
```

**Example response**:

```json
{
  "secret_name": "grpc",
  "secret_type": "tls",
  "material_type": "Tls",
  "private_key": "...",
  "cert": "...",
  "ca_cert": "..."
}
```

For Ed25519 and RSA types, the VM receives the **private key**. For P-256, it receives the **private key** only (the self-signed cert is available to the owner via the client API). For symmetric keys, both sides receive the same shared key. For random bytes, both sides receive the same raw byte sequence.

## Owner/Client APIs (Authenticated)

These APIs require an admin authentication token and are intended for workload owners.

### List Known Identities

Retrieve a list of all identity keys that have credentials stored.

**Endpoint**: `POST /kbs/v0/secretprov/list_pods`

**Example request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    list-pods
```

**Response**:

```json
["myvm_default", "othervm_prod"]
```

### Get Client Credentials

Retrieve the public-side material for a specific secret. The credentials match the secrets previously generated for the VM.

**Endpoint**: `POST /kbs/v0/secretprov/client_creds`

**Query Parameters**:
- `name` (required by default): Workload name (must match the value used when the VM requested credentials)
- `ns` (required by default): Namespace
- `secret_name` (required): Secret name
- `secret_type` (required): Secret type

**Example request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    get-client-creds --query "name=myvm&ns=default&secret_name=grpc&secret_type=tls"
```

**Example response** (TLS):

```json
{
  "secret_name": "grpc",
  "secret_type": "tls",
  "material_type": "Tls",
  "private_key": "...",
  "cert": "...",
  "ca_cert": "..."
}
```

For TLS, the owner receives a freshly issued client certificate signed by the same CA that signed the VM's server certificate. For Ed25519/RSA, the owner receives the **public key**. For P-256, the owner receives the **self-signed certificate**. For symmetric keys, the owner receives the same shared key as the VM. For random bytes, the owner receives the same byte sequence as the VM.

### Update Certificate Details

Customize certificate details for server and/or client certificates before they are generated. Must be called before the VM requests credentials.

**Endpoint**: `POST /kbs/v0/secretprov/update_cert`

**Query Parameters**:
- `name` (required by default): Workload name
- `ns` (required by default): Namespace

**Request Body**:

```json
{
  "server": {
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "organization": "My Org",
    "org_unit": "Engineering",
    "common_name": "VM Server",
    "validity_days": 180
  },
  "client": {
    "common_name": "Workload Owner",
    "validity_days": 180
  }
}
```

**Example request**:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --auth-private-key config/private.key \
    update-cert \
    --query "name=myvm&ns=default" \
    --spec-file test/spec.json
```

## Usage Workflow

1. **Start KBS** with SecretProv plugin enabled.

2. **Set resource policy** to allow the secretprov plugin.

3. **(Optional) Set custom certificate details** before the VM connects:
   ```bash
   kbs-client --url http://localhost:8090 \
       config --auth-private-key config/private.key \
       update-cert --query "name=myvm&ns=default" --spec-file spec.json
   ```

4. **Confidential VM requests server credentials** (after attestation, via the Attestation Service REST client or kbs-client equivalent):
   ```http
   GET /kbs/v0/secretprov/credentials?name=myvm&ns=default&secret_name=grpc&secret_type=tls
   ```

5. **Workload owner lists known identities**:
   ```bash
   kbs-client --url http://localhost:8090 \
       config --auth-private-key config/private.key \
       list-pods
   ```

6. **Workload owner retrieves client credentials**:
   ```bash
   kbs-client --url http://localhost:8090 \
       config --auth-private-key config/private.key \
       get-client-creds --query "name=myvm&ns=default&secret_name=grpc&secret_type=tls"
   ```

7. **Establish mutual TLS** between the VM (server) and the workload owner (client) using the matching credentials.

