# CredGen Plugin

The CredGen plugin dynamically generates cryptographic credentials (keys and certificates) for confidential VMs and workload owners. It enables secure mutual authentication between servers running inside confidential VMs and their clients (workload owners).

## Overview

CredGen generates a fresh Certificate Authority (CA) for each `GET /credentials` call, ensuring that the server cert and the matching client cert always share the same root. The plugin supports multiple secret types:

- **TLS credentials**: X.509 certificates and private keys for mutual TLS
- **Symmetric keys**: Shared secrets for symmetric encryption
- **Ed25519 keys**: Ed25519 key pairs
- **RSA keys**: RSA key pairs
- **P-256 keys**: ECDSA P-256 key pairs with a self-signed certificate
- **Random bytes**: Cryptographically-random byte sequences shared between server and owner

Credentials are stored in non-persistent memory and are lost on restart.

## Architecture

The plugin operates in two phases:

1. **Server phase**: The confidential VM attests and calls `GET /credentials`. CredGen generates a fresh CA and server-side credentials, stores the CA for later use, and returns the private material TEE-encrypted to the VM.

2. **Client phase**: The workload owner calls `POST /client_creds`. CredGen signs a fresh client certificate using the CA stored from the last server request and returns the public-side material.

### Identity

The VM's identity key is derived from its **init-data** (`name` and `ns` fields), which is cryptographically bound to the TEE instance via the attestation token. This prevents any third party from forging or overwriting another VM's credentials.

Owner-side POST requests (`/client_creds`, `/update_cert`) identify the target VM via the same `name` and `ns` query parameters.

### Cert expiry

When a TLS cert expires the server must re-attest and call `GET /credentials` again. That produces a fresh CA and server cert. The owner's next `POST /client_creds` will then return a client cert chaining to the new CA, consistent with the renewed server cert.

## Testing with kbs-client

The [`credgen-client`](https://github.com/salmanyam/trustee/tree/credgen-client) branch of `salmanyam/trustee` contains a `kbs-client` build with credgen support. Clone it and build the tool to use the examples in this document:

```bash
git clone -b credgen-client https://github.com/salmanyam/trustee.git
cd trustee/trustee-client
cargo build --release -p kbs-client
```

The binary will be at `target/release/kbs-client`.

## Setup

### 1. Build KBS with CredGen Plugin

```bash
cd kbs
make background-check-kbs POLICY_ENGINE=opa CREDGEN_PLUGIN=true
```

### 2. Configure the Plugin

Add the CredGen plugin configuration to your KBS config file (e.g. `kbs/config/kbs-config.toml`):

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
supported_types = ["tls", "symmetric", "ed25519", "rsa", "p256", "random"]
```

#### Configuration Options

**CA Configuration** (`plugins.credgen.ca`):
- `country`: Two-letter country code (default: `"AA"`, ISO 3166-1 reserved private-use code)
- `state`: State or province (default: `"N/A"`)
- `locality`: City or locality (default: `"N/A"`)
- `organization`: Organization name (default: `"Confidential Containers"`)
- `org_unit`: Organizational unit (default: `"Trustee"`)
- `common_name`: CA common name (default: `"NOT_SET"`)
- `validity_days`: CA certificate lifetime in days (default: `365`)

**Settings** (`plugins.credgen.settings`):
- `symmetric_key_size`: Symmetric key size in bytes (default: `32`)
- `rsa_bits`: RSA key size in bits (default: `2048`)
- `random_bytes_size`: Number of random bytes to generate (default: `32`)
- `supported_types`: Allowed secret types (default: all six types)

**Certificate validity defaults**:
- CA certificate: **365 days** (set via `plugins.credgen.ca.validity_days`)
- Server and client end-entity certificates: **90 days** (set per-identity via `POST /update_cert`)

### 3. Start KBS

```bash
../target/release/kbs --config-file ./config/kbs-config.toml
```

### 4. Configure Resource Policy

Set a resource policy that allows access to the credgen plugin:

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    config --admin-token-file kbs/config/admin-token \
    set-resource-policy --allow-all
```

## Confidential VM APIs (TEE-Encrypted Response)

These APIs are called by the confidential VM after successful attestation. Responses are encrypted using the TEE's public key via the standard KBS protocol envelope.

### Get Credentials

Request a secret for the confidential VM.

**Endpoint**: `GET /kbs/v0/credgen/credentials`

**Query Parameters**:
- `secret_name` (required): Logical name for this secret (e.g. `grpc`)
- `secret_type` (required): One of `tls`, `symmetric`, `ed25519`, `rsa`, `p256`, `random`

**Identity**: The VM's `name` and `ns` are read from its **init-data**, not from the query string.

**Example**:

```http
GET /kbs/v0/credgen/credentials?secret_name=grpc&secret_type=tls
```

**Example response** (TLS):

```json
{
  "secret_name": "grpc",
  "secret_type": "tls",
  "material_type": "Tls",
  "private_key": "<PEM>",
  "cert": "<PEM>",
  "ca_cert": "<PEM>"
}
```

- **TLS**: VM receives private key, signed server cert, and CA cert.
- **Ed25519 / RSA**: VM receives the private key.
- **P-256**: VM receives the private key (the self-signed cert is available to the owner via `client_creds`).
- **Symmetric / Random**: VM receives the shared value (identical to what the owner receives).

## Owner/Client APIs (Admin Auth Required)

These APIs require an admin bearer token and are intended for workload owners.

### List Known Identities

Retrieve a list of all identity keys that have credentials stored.

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

### Get Client Credentials

Retrieve the public-side material for a secret previously generated for the VM.

**Endpoint**: `POST /kbs/v0/credgen/client_creds`

**Query Parameters**:
- `name` (required): VM name (must match the value in the VM's init-data)
- `ns` (required): Namespace
- `secret_name` (required): Secret name
- `secret_type` (required): Secret type

```bash
../target/release/kbs-client \
    --url http://localhost:8090 \
    credgen --admin-token-file kbs/config/admin-token \
    client-creds --query "name=myvm&ns=default&secret_name=grpc&secret_type=tls"
```

**Example response** (TLS):

```json
{
  "secret_name": "grpc",
  "secret_type": "tls",
  "material_type": "Tls",
  "private_key": "<PEM>",
  "cert": "<PEM>",
  "ca_cert": "<PEM>"
}
```

- **TLS**: Owner receives a fresh client cert signed by the same CA as the VM's server cert.
- **Ed25519 / RSA**: Owner receives the public key.
- **P-256**: Owner receives the self-signed certificate.
- **Symmetric / Random**: Owner receives the same value as the VM.

### Update Certificate Details

Customize certificate subject fields and validity for server and/or client end-entity certs.
Must be called **before** the VM calls `GET /credentials` for the settings to take effect.
Only the fields you include are applied; omitted fields use the defaults.

**Endpoint**: `POST /kbs/v0/credgen/update_cert`

**Query Parameters**:
- `name` (required): VM name
- `ns` (required): Namespace

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

To change only the expiry, supply just `validity_days`:

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

## Usage Workflow

1. **Start KBS** with the CredGen plugin enabled.

2. **Set resource policy** to allow the credgen plugin.

3. **(Optional) Set custom certificate details** before the VM connects:
   ```bash
   kbs-client --url http://localhost:8090 \
       credgen --admin-token-file kbs/config/admin-token \
       update-cert --query "name=myvm&ns=default" --spec-file cert-details.json
   ```

4. **Confidential VM requests credentials** (after attestation). The VM's identity is read from its init-data:
   ```http
   GET /kbs/v0/credgen/credentials?secret_name=grpc&secret_type=tls
   ```

5. **Workload owner lists known identities**:
   ```bash
   kbs-client --url http://localhost:8090 \
       credgen --admin-token-file kbs/config/admin-token \
       list-pods
   ```

6. **Workload owner retrieves client credentials**:
   ```bash
   kbs-client --url http://localhost:8090 \
       credgen --admin-token-file kbs/config/admin-token \
       client-creds --query "name=myvm&ns=default&secret_name=grpc&secret_type=tls"
   ```

7. **Establish mutual TLS** between the VM (server) and the workload owner (client) using the matching credentials.
