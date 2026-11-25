# CredGen Plugin

The CredGen plugin dynamically generates cryptographic credentials for confidential VMs and their workload owners, enabling secure mutual authentication between the two sides.

## Overview

Credentials are requested by the confidential VM (server side) via `GET /credentials` and retrieved by the workload owner (client side) via `GET /client_creds`. The plugin supports three secret types (`cert`, `asymmetric` and `symmetric`); the `cert` type has two kinds:

| `secret_type` | Parameters | What is generated |
|---|---|---|
| `cert` | `kind=leaf_cert`<br>`kind=self_signed_ca` | Ed25519 leaf certificate signed by a per-secret CA (CA cert + server cert + private key)<br>P-256 (ECDSA) self-signed CA certificate + private key |
| `asymmetric` | `algorithm=ec_ed25519` or `rsa` | Key pair |
| `symmetric` | `size` *(optional)* | Raw random bytes (default: 32 bytes; max: `symmetric_key_size_max`) |

`kind` describes how a certificate is issued; for certs the key algorithm is implied by the kind (`leaf_cert` → `ec_ed25519`, `self_signed_ca` → `ec_p256`). For `asymmetric`, `algorithm` is required. Only the combinations listed above are currently implemented; others are rejected.

Generated material is stored in the KBS key-value storage backend, so whether it survives a KBS restart depends on the configured backend. The default `Memory` backend loses everything on restart; `LocalJson`, `LocalFs` and `Postgres` persist it, and `Redis` persists it only if the Redis server itself is configured to.

## Architecture

The plugin operates in two phases:

1. **Server phase** — The confidential VM attests and calls `GET /credentials`. CredGen generates fresh material, stores the public side (CA key/cert for `leaf_cert`, public key for asymmetric, shared value for symmetric), and returns the private material TEE-encrypted to the VM.

2. **Client phase** — The workload owner calls `GET /client_creds` with an admin token. CredGen returns the owner-side material. For `leaf_cert`, a fresh client certificate and private key are signed on the fly using the CA stored from the last server call.

`client_creds` requires admin authentication for every secret type, even though some responses contain only public material, because the `leaf_cert` and `symmetric` responses contain private or shared secret material.

### Identity

The VM's identity key is derived from the `name` and `ns` fields of its **init-data**. Init-data is bound to the TEE instance via the attestation token, so a third party cannot forge or overwrite another VM's credentials.

The init-data must therefore be a JSON object with non-empty string `name` and `ns` fields, otherwise `GET /credentials` fails. For example, in a TOML init-data document:

```toml
version = "0.1.0"
algorithm = "sha256"

[data]
"name" = "myvm"
"ns"   = "default"
```

The `GET /credentials` request must also carry the same `name` and `ns` as query parameters; a request whose query values differ from the init-data is rejected. Owner-side requests identify the target VM with the same `name` and `ns` query parameters.

### Query parameters are not validated against the VM

Only `name` and `ns` are attested. All other query parameters (`secret_name`, `secret_type`, `kind`, `algorithm`, `size`) are chosen by the caller and are not authenticated; the plugin only checks that they are well-formed and that the requested combination is listed in `supported_types`. Any attested VM may therefore request any secret allowed by `supported_types` under its own identity.

Plugin requests pass through the KBS resource policy. Use the policy, rather than the plugin, to restrict which attested guests may call the plugin.

### Cert expiry

When a cert expires the VM re-attests and calls `GET /credentials` again. A fresh CA and server cert are generated. The owner's next `GET /client_creds` returns a client cert chaining to the new CA, consistent with the renewed server cert.

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
symmetric_key_size_max = 128
rsa_bits = 2048
supported_types = ["cert/leaf_cert/ec_ed25519", "cert/self_signed_ca/ec_p256", "asymmetric/ec_ed25519", "asymmetric/rsa", "symmetric"]
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
| `symmetric_key_size_max` | `128` | Maximum allowed `size` for symmetric keys; default is `32` when `size` is omitted |
| `rsa_bits` | `2048` | RSA key size in bits |
| `supported_types` | all five | Allowed entries: `"cert/leaf_cert/ec_ed25519"`, `"cert/self_signed_ca/ec_p256"`, `"asymmetric/ec_ed25519"`, `"asymmetric/rsa"`, `"symmetric"` |

End-entity (server and client) cert validity is fixed at **90 days**.

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
- `name` (required) — VM name; must match the `name` in the VM's init-data
- `ns` (required) — namespace; must match the `ns` in the VM's init-data
- `secret_name` (required) — logical name for this secret (e.g. `grpc`)
- `secret_type` (required) — `cert`, `asymmetric`, or `symmetric`
- `kind` (required for `cert`) — `leaf_cert` or `self_signed_ca`
- `algorithm` (required for `asymmetric`) — `ec_ed25519` or `rsa`
- `size` (optional, `symmetric` only) — key length in bytes (`1`–`symmetric_key_size_max`); defaults to `32`

The VM's identity is taken from its **init-data**. `name` and `ns` in the query string are only checked against it. See [Query parameters are not validated against the VM](#query-parameters-are-not-validated-against-the-vm) for the other parameters.

**Examples**:

```http
GET /kbs/v0/credgen/credentials?name=myvm&ns=default&secret_name=grpc&secret_type=cert&kind=leaf_cert
GET /kbs/v0/credgen/credentials?name=myvm&ns=default&secret_name=mycert&secret_type=cert&kind=self_signed_ca
GET /kbs/v0/credgen/credentials?name=myvm&ns=default&secret_name=sigkey&secret_type=asymmetric&algorithm=ec_ed25519
GET /kbs/v0/credgen/credentials?name=myvm&ns=default&secret_name=aeskey&secret_type=symmetric
GET /kbs/v0/credgen/credentials?name=myvm&ns=default&secret_name=aeskey16&secret_type=symmetric&size=16
```

The request must be made by a client that has completed KBS attestation and can decrypt the TEE-encrypted response.

**Response** (fields vary by type):

| `secret_type` / `kind` | `material_type` | Fields returned to the VM |
|---|---|---|
| `cert` / `leaf_cert` | `Cert` | `private_key`, `cert`, `ca_cert` |
| `cert` / `self_signed_ca` | `Cert` | `private_key`, `cert` |
| `asymmetric` | `Asymmetric` | `private_key` |
| `symmetric` | `Symmetric` | `key` |

The response also carries `kind` and `algorithm` (derived from the kind for certs); absent fields are omitted.

Example response for `cert/leaf_cert`:

```json
{
  "secret_name": "grpc",
  "secret_type": "cert",
  "kind": "leaf_cert",
  "algorithm": "ec_ed25519",
  "material_type": "Cert",
  "private_key": [...],
  "cert": [...],
  "ca_cert": [...]
}
```

> **Note**: material fields are raw byte arrays (PEM-encoded bytes serialised as a JSON array of integers).

## Owner/Client APIs (Admin Auth Required)

These APIs require an admin bearer token, passed as `Authorization: Bearer <token>`. Responses are not TEE-encrypted, so use TLS between the owner and the KBS.

### POST /list_identities

Return all identity keys that have credentials stored.

**Endpoint**: `POST /kbs/v0/credgen/list_identities`

```bash
curl -X POST \
    -H "Authorization: Bearer $(cat kbs/config/admin-token)" \
    http://localhost:8090/kbs/v0/credgen/list_identities
```

**Response**:

```json
["myvm_default", "othervm_prod"]
```

### GET /client_creds

Return the owner-side material for a secret previously generated for the VM.

**Endpoint**: `GET /kbs/v0/credgen/client_creds`

**Query Parameters**:
- `name` (required) — VM name (must match the value in the VM's init-data)
- `ns` (required) — namespace
- `secret_name` (required) — secret name
- `secret_type` (required) — secret type
- `kind` (required for `cert`) — `leaf_cert` or `self_signed_ca`
- `algorithm` (required for `asymmetric`) — `ec_ed25519` or `rsa`

```bash
curl -H "Authorization: Bearer $(cat kbs/config/admin-token)" \
    "http://localhost:8090/kbs/v0/credgen/client_creds?name=myvm&ns=default&secret_name=grpc&secret_type=cert&kind=leaf_cert"
```

**Response** (fields vary by type):

| `secret_type` / `kind` | `material_type` | Fields returned to the owner |
|---|---|---|
| `cert` / `leaf_cert` | `Cert` | `private_key`, `cert`, `ca_cert` (fresh client cert, same CA as server) |
| `cert` / `self_signed_ca` | `Cert` | `cert` (the self-signed CA cert generated for the VM) |
| `asymmetric` | `Asymmetric` | `public_key` |
| `symmetric` | `Symmetric` | `key` (identical to the value delivered to the VM) |

## Typical Workflow

1. **Start KBS** with the CredGen plugin enabled.
2. **Set resource policy** to allow the credgen plugin.
3. **VM requests credentials** after attestation (identity from init-data):
   ```http
   GET /kbs/v0/credgen/credentials?name=myvm&ns=default&secret_name=grpc&secret_type=cert&kind=leaf_cert
   ```
4. **Owner lists known identities**:
   ```bash
   curl -X POST -H "Authorization: Bearer $(cat kbs/config/admin-token)" \
       http://localhost:8090/kbs/v0/credgen/list_identities
   ```
5. **Owner retrieves client credentials**:
   ```bash
   curl -H "Authorization: Bearer $(cat kbs/config/admin-token)" \
       "http://localhost:8090/kbs/v0/credgen/client_creds?name=myvm&ns=default&secret_name=grpc&secret_type=cert&kind=leaf_cert"
   ```
6. **Establish mutual TLS** between the VM (server) and the workload owner (client) using the matching credentials.
