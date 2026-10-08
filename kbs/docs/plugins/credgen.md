# CredGen Plugin

The CredGen plugin dynamically generates cryptographic credentials for confidential VMs and their workload owners, enabling secure mutual authentication between the two sides.

## Overview

Credentials are requested by the confidential VM (server side) via `GET /credentials` and retrieved by the workload owner (client side) via `POST /client_creds`. The plugin supports four secret categories, each with one or more algorithms:

| `secret_type` | `algorithm` | What is generated |
|---|---|---|
| `cert` | `tls` | Ed25519 CA-signed TLS bundle (CA cert + server cert + private key) |
| `cert` | `p256` | P-256 (ECDSA) self-signed certificate + private key |
| `asymmetric` | `ed25519` | Ed25519 key pair |
| `asymmetric` | `rsa` | RSA key pair |
| `symmetric` | `raw` *(default)* | Raw random bytes for use as a symmetric key (AES-256, ChaCha20, …) |
| `random` | `csprng` *(default)* | Opaque random bytes shared identically with the owner |

`symmetric` and `random` do not require an explicit `algorithm` parameter — the default is used when it is omitted.

Credentials are persisted via the KBS kvstorage backend and survive restarts.

## Architecture

The plugin operates in two phases:

1. **Server phase** — The confidential VM attests and calls `GET /credentials`. CredGen generates fresh material, stores the public side (CA key/cert for TLS, public key for asymmetric, shared value for symmetric/random), and returns the private material TEE-encrypted to the VM.

2. **Client phase** — The workload owner calls `POST /client_creds`. CredGen returns the public-side material. For TLS, a fresh client certificate is signed on the fly using the CA stored from the last server call.

### Identity

The VM's identity key is derived from its **init-data** (`name` and `ns` fields), which is cryptographically bound to the TEE instance via the attestation token. This prevents any third party from forging or overwriting another VM's credentials.

Owner-side POST requests identify the target VM via the same `name` and `ns` query parameters.

### Cert expiry

When a cert expires the VM re-attests and calls `GET /credentials` again. A fresh CA and server cert are generated. The owner's next `POST /client_creds` returns a client cert chaining to the new CA, consistent with the renewed server cert.

## Testing with kbs-client

The [`credgen-client`](https://github.com/salmanyam/trustee/tree/credgen-client) branch of `salmanyam/trustee` contains a `kbs-client` build with credgen support:

```bash
git clone -b credgen-client https://github.com/salmanyam/trustee.git
cd trustee/trustee-client
cargo build --release -p kbs-client
```

The binary will be at `target/release/kbs-client`.

## Setup

### 1. Build KBS with the CredGen Plugin

```bash
cd kbs
make background-check-kbs POLICY_ENGINE=opa CREDGEN_PLUGIN=true
```

### 2. Configure the Plugin

Add the following to your KBS config file (e.g. `kbs/config/kbs-config.toml`):

```toml
[[plugins]]
name = "credgen"

[plugins.credgen.ca]
country = "AA"
state = "N/A"
locality = "N/A"
organization = "Confidential Containers"
org_unit = "Trustee"
common_name = "CredGen CA"
validity_days = 365

[plugins.credgen.settings]
symmetric_key_size = 32
rsa_bits = 2048
random_bytes_size = 32
supported_types = ["cert/tls", "cert/p256", "asymmetric/ed25519", "asymmetric/rsa", "symmetric", "random"]
```

#### Configuration Reference

**CA** (`plugins.credgen.ca`) — subject fields for the per-identity CA certificate:

| Field | Default | Description |
|---|---|---|
| `country` | `"AA"` | Two-letter country code (`"AA"` = ISO 3166-1 reserved) |
| `state` | `"N/A"` | State or province |
| `locality` | `"N/A"` | City |
| `organization` | `"Confidential Containers"` | Organization name |
| `org_unit` | `"Trustee"` | Organizational unit |
| `common_name` | `"NOT_SET"` | CA common name |
| `validity_days` | `365` | CA cert lifetime in days |

**Settings** (`plugins.credgen.settings`):

| Field | Default | Description |
|---|---|---|
| `symmetric_key_size` | `32` | Symmetric key length in bytes |
| `rsa_bits` | `2048` | RSA key size in bits |
| `random_bytes_size` | `32` | Random byte sequence length in bytes |
| `supported_types` | all six | Allowed `"type/algorithm"` pairs; `"symmetric"` and `"random"` need no suffix |

End-entity cert validity defaults to **90 days** and can be overridden per-identity via `POST /update_cert`.

### 3. Start KBS

```bash
../target/release/kbs --config-file ./config/kbs-config.toml
```

### 4. Set Resource Policy

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --admin-token-file kbs/config/admin-token \
    set-resource-policy --allow-all
```

## Confidential VM APIs (TEE-Encrypted Response)

Called by the confidential VM after successful attestation. Responses are wrapped in a TEE-encrypted JWE envelope.

### GET /credentials

Generate credentials for the VM.

**Endpoint**: `GET /kbs/v0/credgen/credentials`

**Query Parameters**:
- `secret_name` (required) — logical name for this secret (e.g. `grpc`)
- `secret_type` (required) — `cert`, `asymmetric`, `symmetric`, or `random`
- `algorithm` (required for `cert` and `asymmetric`; optional otherwise) — see table above

The VM's `name` and `ns` are read from its **init-data**, not from the query string.

**Examples**:

```http
GET /kbs/v0/credgen/credentials?secret_name=grpc&secret_type=cert&algorithm=tls
GET /kbs/v0/credgen/credentials?secret_name=sigkey&secret_type=asymmetric&algorithm=ed25519
GET /kbs/v0/credgen/credentials?secret_name=aeskey&secret_type=symmetric
GET /kbs/v0/credgen/credentials?secret_name=nonce&secret_type=random
```

**Response** (fields vary by type):

| `secret_type` / `algorithm` | Fields returned to the VM |
|---|---|
| `cert/tls` | `private_key`, `cert`, `ca_cert` |
| `cert/p256` | `private_key` |
| `asymmetric/ed25519` or `asymmetric/rsa` | `private_key` |
| `symmetric/raw` | `key` |
| `random/csprng` | `bytes` |

Example response for `cert/tls`:

```json
{
  "secret_name": "grpc",
  "secret_type": "cert",
  "algorithm": "tls",
  "material_type": "Tls",
  "private_key": [...]
  "cert": [...],
  "ca_cert": [...]
}
```

> **Note**: material fields are raw byte arrays (PEM-encoded bytes serialised as a JSON array of integers).

## Owner/Client APIs (Admin Auth Required)

These APIs require an admin bearer token.

### POST /list_pods

Return all identity keys that have credentials stored.

**Endpoint**: `POST /kbs/v0/credgen/list_pods`

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    credgen --admin-token-file kbs/config/admin-token \
    list-pods
```

**Response**:

```json
["myvm_default", "othervm_prod"]
```

### POST /client_creds

Return the public-side material for a secret previously generated for the VM.

**Endpoint**: `POST /kbs/v0/credgen/client_creds`

**Query Parameters**:
- `name` (required) — VM name (must match the value in the VM's init-data)
- `ns` (required) — namespace
- `secret_name` (required) — secret name
- `secret_type` (required) — secret category
- `algorithm` (required for `cert`/`asymmetric`) — algorithm

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    credgen --admin-token-file kbs/config/admin-token \
    client-creds --query "name=myvm&ns=default&secret_name=grpc&secret_type=cert&algorithm=tls"
```

**Response** (fields vary by type):

| `secret_type` / `algorithm` | Fields returned to the owner |
|---|---|
| `cert/tls` | `private_key`, `cert`, `ca_cert` (fresh client cert, same CA as server) |
| `cert/p256` | `cert_pem` (the self-signed cert generated for the VM) |
| `asymmetric/ed25519` or `asymmetric/rsa` | `public_key` |
| `symmetric/raw` | `key` (identical to the value delivered to the VM) |
| `random/csprng` | `bytes` (identical to the value delivered to the VM) |

### POST /update_cert

Persist custom X.509 subject fields and validity for a given identity. Settings are applied on the next `GET /credentials` call for that identity.

**Endpoint**: `POST /kbs/v0/credgen/update_cert`

**Query Parameters**:
- `name` (required) — VM name
- `ns` (required) — namespace

**Request Body** — JSON object with optional `"server"` and `"client"` keys, each a partial `TlsCertDetails`:

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

To change only the expiry:

```json
{
  "server": { "validity_days": 180 },
  "client": { "validity_days": 180 }
}
```

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    credgen --admin-token-file kbs/config/admin-token \
    update-cert \
    --query "name=myvm&ns=default" \
    --spec-file cert-details.json
```

## Typical Workflow

1. **Start KBS** with the CredGen plugin enabled.
2. **Set resource policy** to allow the credgen plugin.
3. *(Optional)* **Customise cert subject fields** before the VM connects:
   ```bash
   kbs-client credgen update-cert --query "name=myvm&ns=default" --spec-file cert-details.json
   ```
4. **VM requests credentials** after attestation (identity from init-data):
   ```http
   GET /kbs/v0/credgen/credentials?secret_name=grpc&secret_type=cert&algorithm=tls
   ```
5. **Owner lists known identities**:
   ```bash
   kbs-client credgen list-pods
   ```
6. **Owner retrieves client credentials**:
   ```bash
   kbs-client credgen client-creds --query "name=myvm&ns=default&secret_name=grpc&secret_type=cert&algorithm=tls"
   ```
7. **Establish mutual TLS** between the VM (server) and the workload owner (client) using the matching credentials.
