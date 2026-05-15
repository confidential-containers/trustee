# KBS Configuration File

The Confidential Containers KBS properties can be configured through a
TOML-formatted configuration file.

> NOTE: Additional formats such as YAML and JSON are supported. Other formats
> supported by the `config` crate may be supported as well. This document uses
> TOML in the configuration examples.

The location of the configuration file is passed to the KBS binary using the
`-c` or `--config-file` command line option, or using the `KBS_CONFIG_FILE`
environment variable.

## Configurable Properties

The following sections list the KBS properties which can be set through the configuration file.

### HTTP Server Configuration

The following properties can be set under the `[http_server]` section.

| Property               | Type         | Description                                      |  Required | Default                  |
|------------------------|--------------|--------------------------------------------------|----------|--------------------------|
| `sockets`              | String array | One or more sockets to listen on.                | No       | `["127.0.0.1:8080"]`     |
| `insecure_http`        | Boolean      | Don't use TLS for the KBS HTTP endpoint.         | No       | `false`                  |
| `private_key`          | String       | Path to a private key file to be used for HTTPS. | No       | None                     |
| `certificate`          | String       | Path to a certificate file to be used for HTTPS. | No       | None                     |
| `payload_request_size` | Integer      | Request payload size in mega bytes.              | No       | 2                        |
| `worker_count`         | Integer      | Number of HTTP actix worker threads              | No       | Num of logical CPU cores |
| `tls_profile`          | String       | TLS security profile (see [TLS Configuration](#tls-configuration)) | No | `intermediate` |
| `tls_min_version`      | String       | Minimum TLS version: `1.2` or `1.3`              | No       | Profile-dependent        |
| `tls_max_version`      | String       | Maximum TLS version: `1.2` or `1.3`              | No       | Profile-dependent        |
| `tls_ciphers`          | String       | TLS cipher suites (colon-separated OpenSSL list) | No       | Profile-dependent        |
| `tls_groups`           | String       | TLS key exchange groups (colon-separated list)   | No       | Auto-detected with PQC   |

#### TLS Configuration

KBS supports flexible TLS configuration through predefined security profiles and custom settings. The TLS profiles are based on [Mozilla's TLS recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS).

##### TLS Security Profiles

Four security profiles are available via the `tls_profile` setting:

| Profile         | TLS Versions | Description                                              | Use Case                          |
|-----------------|--------------|----------------------------------------------------------|-----------------------------------|
| `old`           | 1.2, 1.3     | Legacy compatibility with older clients                  | Maximum client compatibility      |
| `intermediate`  | 1.2, 1.3     | Balanced security and compatibility (recommended)        | Most production deployments       |
| `modern`        | 1.3 only     | Maximum security, TLS 1.3 only                           | High-security environments        |
| `custom`        | Configurable | Full control over TLS parameters                         | Specialized security requirements |

**Recommended:** Use `intermediate` (the default) for most deployments unless you have specific security or compatibility requirements.

##### Custom TLS Configuration

When using `tls_profile = "custom"`, you can explicitly configure:

- **`tls_min_version`**: Minimum TLS protocol version (`"1.2"` or `"1.3"`)
- **`tls_max_version`**: Maximum TLS protocol version (`"1.2"` or `"1.3"`)
- **`tls_ciphers`**: Colon-separated OpenSSL cipher suite list
  - For TLS 1.3 only (Modern profile or min=1.3): Use TLS 1.3 cipher names
    - Example: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`
    - TLS 1.3 cipher suites only specify encryption and hashing
  - For TLS 1.2 only (max=1.2): Use TLS 1.2 cipher names
    - Example: `ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384`
    - TLS 1.2 cipher suites include key exchange, authentication, encryption, and hashing
  - For both TLS 1.2 and 1.3 (Old/Intermediate): You can mix both formats in one string, separated by colons
- **`tls_groups`**: Colon-separated list of supported groups for key exchange (applies to both TLS 1.2 and 1.3)
  - For TLS 1.2: Configures elliptic curves for ECDHE cipher suites
  - For TLS 1.3: Configures all key exchange (the only mechanism since cipher suites don't include it)
  - Common classical groups: `X25519`, `X448`, `secp256r1` (P-256), `secp384r1` (P-384), `secp521r1` (P-521)
  - PQC hybrid groups (OpenSSL 3.5+): `X25519MLKEM768`, `SecP256r1MLKEM768`, `X448MLKEM1024`, `SecP384r1MLKEM1024`
  - Example: `X25519:secp256r1:secp384r1` (classical only)
  - Example: `X25519MLKEM768:X25519:secp256r1` (post-quantum with classical fallback)
  - See [OpenSSL groups documentation](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set1_groups_list.html) for complete list

> [!NOTE]
> Custom TLS fields can be used with any profile to override specific settings. If you set custom fields with a non-custom profile, a warning will be logged, but the custom settings will take precedence.

##### Post-Quantum Cryptography (PQC) Support

KBS automatically detects and enables post-quantum key exchange algorithms when supported by your OpenSSL installation (3.5+). If `tls_groups` is not explicitly configured, KBS will:

1. Detect the best available PQC algorithm (ML-KEM hybrid groups)
2. Fall back to classical algorithms if PQC is unavailable
3. Use the following priority order:
   - `X25519MLKEM768` (preferred)
   - `SecP256r1MLKEM768` (FIPS-compliant)
   - `X448MLKEM1024` (high security)
   - `SecP384r1MLKEM1024` (FIPS + high security)

To explicitly configure PQC, use the `custom` profile with `tls_groups`:

```toml
[http_server]
tls_profile = "custom"
tls_min_version = "1.3"
tls_max_version = "1.3"
tls_groups = "X25519MLKEM768:X25519:secp256r1"
```

See the [TLS Configuration Examples](#tls-configuration-examples) section for complete examples.

### Attestation Token Configuration

Attestation Token configuration controls attestation token verifications. This
is important when a resource retrievement is handled by KBS. Usually an attestation
token will be together with the request, and KBS will first verify the token.

The following properties can be set under the `[attestation_token]` section.

| Property              | Type         | Description                                                                                                                       | Default |
|-----------------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------|---------|
| `trusted_jwk_sets`    | String Array | Trusted JWKS/OpenID sources (`file://` or `https://`) used to verify attestation tokens                                         | Empty   |
| `trusted_certs_paths` | String Array | Trusted Certificates file (PEM format) for Attestation Tokens trustworthy verification                                            | Empty   |
| `extra_teekey_paths`  | String Array | User defined paths to the tee public key in the JWT body                                                                          | Empty   |
| `insecure_header_jwk`        | Boolean      | Skip `x5c`/`trusted_certs_paths` endorsement for a JWK in the JWT header; signature is still verified | `false` |

Each JWT contains a TEE Public Key. Users can use the `extra_teekey_paths` field to additionally specify the path of
this Key in the JWT.
Example of `extra_teekey_paths` is `/attester_runtime_data/tee-pubkey` which refers to the key
`attester_runtime_data.tee-pubkey` inside the JWT body claims. By default CoCo AS Token and Intel TA
Token TEE Public Key paths are supported.

For attestation services like CoCo-AS, the JWT header often carries a `jwk` (sometimes with an
`x5c` certificate chain). KBS uses that key to verify the token signature. Whether the key's
provenance is checked depends on `insecure_header_jwk`:

- If `insecure_header_jwk` is `true`, the header `jwk` is used as-is; KBS does not validate its `x5c`
  chain against `trusted_certs_paths`. The JWT signature is still verified. Intended for
  testing only.
- If `insecure_header_jwk` is `false`, the header `jwk` must include a non-empty `x5c` chain that
  matches the key and chains to a certificate in `trusted_certs_paths`.
  If `trusted_certs_paths` is empty, tokens with a header `jwk` cannot be verified.

For attestation services like Intel TA, the JWT header carries a `kid` instead of an embedded
`jwk`. The `kid` is used to look up the signing key from `trusted_jwk_sets`.
This lookup path is not affected by `insecure_header_jwk`.

### Attestation Configuration

Attestation configuration defines the attestation service that KBS' RCAR protocol will leverage.

The following properties can be set under the `[attestation_service]` section.

Concrete attestation service can be set via `type` field. Supported attestation services are

- `coco_as_builtin`: CoCo AS that built inside KBS binary
- `coco_as_grpc`: CoCo AS service running remotely
- `intel_ta`: Intel&reg; Trust Authority

Due to different `type` field, properties are different.

#### Built-In CoCo AS

When `type` is set to `coco_as_builtin`, the following properties can be set.

> Built-In CoCo AS is available only when one or more of the following features are enabled:
> `coco-as-builtin`, `coco-as-builtin-no-verifier`

| Property                   | Type                        | Description                                              | Default                                                                                                       |
|----------------------------|-----------------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `timeout`                  | Integer                     | The maximum time (in minutes) of the attestation session | 5                                                                                                             |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                       | See [RVPSConfiguration][2]                                                                                    |
| `attestation_token_broker` | [AttestationTokenBroker][1] | Attestation result token configuration.                  | See [AttestationTokenBroker][1]                                                                               |
| `verifier_config`          | Object                      | Optional verifier specific configuration (for example TPM)| None                                                                                                          |

[1]: #attestationtokenbroker
[2]: #rvps-configuration
[3]: #keyvaluestorage
[4]: #tokensignerconfig

##### AttestationTokenBroker

| Property         | Type                   | Description                                                                    | Required | Default                                                               |
|------------------|------------------------|--------------------------------------------------------------------------------|----------|-----------------------------------------------------------------------|
| `duration_min`   | Integer                | Duration of the attestation result token in minutes.                           | No       | `5`                                                                   |
| `issuer_name`    | String                 | Issure name of the attestation result token.                                   | No       | `CoCo-Attestation-Service`                                            |
| `developer_name` | String                 | The developer name to be used as part of the Verifier ID in the EAR            | No       | `https://confidentialcontainers.org`                                  |
| `build_name`     | String                 | The build name to be used as part of the Verifier ID in the EAR                | No       | Automatically generated from Cargo package and AS version             |
| `profile_name`   | String                 | The Profile that describes the EAR token                                       | No       | tag:github.com,2024:confidential-containers/Trustee`                  |
| `signer`         | [TokenSignerConfig][4] | Signing material of the attestation result token.                              | No       | None                                                                  |

##### TokenSignerConfig

This section is **optional**. When omitted, an ephemeral RSA key pair is generated and used.

| Property    | Type   | Description                                              | Required |
|-------------|--------|----------------------------------------------------------|----------|
| `key_path`  | String | RSA Key Pair file (PEM format) path.                     | Yes      |
| `cert_url`  | String | RSA Public Key certificate chain (PEM format) URL.       | No       |
| `cert_path` | String | RSA Public Key certificate chain (PEM format) file path. | No       |

##### RVPS Configuration

| Property | Type   | Description                                                                                | Required | Default   |
|----------|--------|--------------------------------------------------------------------------------------------|----------|-----------|
| `type`   | String | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `extractors` | Object | Optional configuration for provenance extractors | No | None |
| `storage_type` | String | Optional RVPS-specific storage type override. If provided, overrides `storage_backend.storage_type` for RVPS only. Backend-specific parameters are still reused from `storage_backend.backends`. | No | None |

> [!NOTE]
> **Storage Configuration:** By default, BuiltIn RVPS uses the unified `storage_backend` configuration (see [Storage Backend Configuration](#storage-backend-configuration)) with the `reference_value` namespace. However, you can optionally provide a `storage_type` field to override only the storage type used by RVPS.
> This allows you to use different storage backends for different components (e.g., LocalFs for KBS resources, but LocalJson for RVPS reference values).

For detailed information about extractors configuration, including available extractors and their options, see the [RVPS README](../../rvps/README.md#extractors-configuration).

##### Remote RVPS

If `type` is set to `GrpcRemote`, the following extra properties can be set

| Property  | Type   | Description                       | Required | Default           |
|-----------|--------|-----------------------------------|----------|-------------------|
| `address` | String | Remote address of the RVPS server | No       | `127.0.0.1:50003` |

#### gRPC CoCo AS

When `type` is set to `coco_as_grpc`, KBS will try to connect a remote CoCo AS for attestation. 
The following properties can be set.

> gRPC CoCo AS is available only when `coco-as-grpc` feature is enabled.

| Property    | Type    | Description                                                                                                                   | Default                  |
|-------------|---------|-------------------------------------------------------------------------------------------------------------------------------|--------------------------|
| `timeout`   | Integer | The maximum time (in minutes) between RCAR handshake's `auth` and `attest` requests                                           | 5                        |
| `as_addr`   | String  | The URL of the remote CoCoAS                                                                                                  | `http://127.0.0.1:50004` |
| `pool_size` | Integer | The connections between KBS and CoCoAS are maintained in a conenction pool. This property determines the max size of the pool | `100`                    |

#### Intel&reg; TA

When `type` is set to `intel_ta`, KBS will try to connect a remote Intel TA service for attestation. 
The following properties can be set.

> Intel Trust Authority AS is available only when the `intel-trust-authority-as` feature is enabled.

| Property                 | Type         | Description                                                                                            | Required | Default |
|--------------------------|--------------|--------------------------------------------------------------------------------------------------------|----------|---------|
| `timeout`                | Integer      | The maximum time (in minutes) between RCAR handshake's `auth` and `attest` requests                    | No       | 5       |
| `base_url`               | String       | Intel Trust Authority API URL.                                                                         | Yes      | -       |
| `api_key`                | String       | Intel Trust Authority API key.                                                                         | Yes      | -       |
| `certs_file`             | String       | URL to an Intel Trust Authority portal or path to JWKS file used for token verification.               | Yes      | -       |
| `policy_ids`             | String array | Quoted and comma-separated list of policy IDs defined in ITA portal.                                   | No       | `[]`    |
| `allow_unmatched_policy` | Boolean      | Whether policy matching is required. If no `policy_ids` are specified, policy matching is not checked. | No       | false   |

Detailed [documentation](https://docs.trustauthority.intel.com).

### Admin API Configuration

Admin mode is configured under `[admin]` with:

- `authorization_mode = "InsecureAllowAll"`
- `authorization_mode = "DenyAll"`
- `authorization_mode = "AuthenticatedAuthorization"` (recommended for production)

For `authorization_mode = "AuthenticatedAuthorization"`, configure:

- `[admin.authentication.bearer_jwt]`
- `[admin.authorization.regex_acl]`

`bearer_jwt` properties:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `identity_providers` | Array | Trusted issuer entries for JWT verification | No | Empty |

Each `identity_providers` item:

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `issuer` | String | Expected JWT `iss` value (leave empty to skip issuer check) | No |
| `audience` | String | Expected JWT `aud` value (leave empty to skip audience check) | No |
| `public_key_uri` | String | PEM public key source (`https://`, `file://`, local path) | No* |
| `jwk_set_uri` | String | JWKS source (`https://`, `file://`, or local path) | No* |

\* At least one of `public_key_uri` or `jwk_set_uri` is required.

JWTs used for admin access **MUST** include a `role` claim.

`regex_acl` properties:

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `acls` | Array | Role-to-endpoint allow rules | No |

Each ACL entry:

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `role` | String | JWT `role` value to match | Yes |
| `allowed_endpoints` | String | Regex of allowed request paths | Yes |

`allowed_endpoints` must start with `^/kbs` and end with `$`.

### Storage Backend Configuration

KBS supports a unified storage backend configuration that allows you to declare a single storage configuration that will be used for all storage needs in KBS, including
all the persistent storages that KBS relies on, including potentially underlying built-in AS and built-in RVPS.

This simplifies deployment by eliminating the need to configure storage separately for each component.

For detailed information about the unified storage backend configuration format, including what a **namespace** is and how it works, see the [Key-Value Storage README](../../deps/key-value-storage/README.md#unified-storage-backend-configuration).

#### Storage Namespaces in KBS

When using the unified storage backend configuration, KBS creates the following storage namespaces:

| Namespace Name | Component | Description |
|---------------|-----------|-------------|
| `kbs` | KBS Policy Engine | Stores the things used by KBS, like KBS Resource Policy |
| `repository` | Resource Plugin | Stores secret resources managed by the resource plugin |
| `kbs_protocol_session` | KBS Attestation Session | Stores RCAR attestation session state |
| `attestation_service_policy` | Built-in AS | Stores EAR policies for the built-in Attestation Service |
| `reference_value` | Built-in AS RVPS | Stores reference values for the built-in RVPS |

The KBS Resource Policy will be stored inside `kbs` namespace with key `resource-policy`.

For detailed configuration options and examples, see the [Key-Value Storage README](../../deps/key-value-storage/README.md#unified-storage-backend-configuration).

> [!NOTE]
> All persistent storage is configured via `[storage_backend]`. If `[storage_backend]` is omitted, the default in-memory storage is used (data is not persisted across restarts).

#### Optional Session Storage Type Override

KBS supports an optional `session_storage_type` field for attestation session state.

When `session_storage_type` is not configured, KBS falls back to `storage_backend.storage_type`.

Backend-specific configuration is always reused from `storage_backend.backends`.

The attestation session storage namespace is always `kbs_protocol_session`.

### Plugins Configuration

KBS supports different kinds of plugins, and they can be enabled via add corresponding configs.

Multiple `[[plugins]]` sections are allowed at the same time for different plugins.
Concrete attestation service can be set via `name` field.

#### Resource Configuration

The `name` field is `resource` to enable this plugin.

Resource plugin allows user with proper attestation token to access storage that KBS keeps.
This is also called "Repository" in old versions. The properties to be configured are listed.

| Property | Type   | Description                                                   | Required | Default    |
|----------|--------|---------------------------------------------------------------|----------|------------|
| `type`| String | Storage type for resources: `kvstorage`, `Aliyun`, `Vault` | No       | `kvstorage`|

When `storage_backend_type = "kvstorage"` (default), the resource plugin uses the unified [storage backend](#storage-backend-configuration) with namespace `repository`. Configure storage in the `[storage_backend]` section only.

When `storage_backend_type = "Aliyun"`:

| Property          | Type   | Description                       | Required | Example                                             |
|-------------------|--------|-----------------------------------|----------|-----------------------------------------------------|
| `client_key`      | String | The KMS instance's AAP client key | Yes      | `{"KeyId": "KA..", "PrivateKeyData": "MIIJqwI..."}` |
| `kms_instance_id` | String | The KMS instance id               | Yes      | `kst-shh668f7...`                                   |
| `password`        | String | AAP client key password           | Yes      | `8f9989c18d27...`                                   |
| `cert_pem`        | String | CA cert for the KMS instance      | Yes      | `-----BEGIN CERTIFICATE----- ...`                   |

When `storage_backend_type = "Vault"`:

| Property     | Type          | Required | Description                                 | Default    |
|--------------|---------------|----------|---------------------------------------------|------------|
| `vault_url`  | String        | Yes      | Vault server URL (HTTP or HTTPS)            | -          |
| `token`      | String        | Yes      | Vault authentication token                  | -          |
| `mount_path` | String        | No       | Vault KV v1 mount path                      | `"secret"` |
| `verify_ssl` | Boolean       | No       | Enable/disable SSL certificate verification | `false`    |
| `ca_certs`   | Array[String] | No       | Paths to custom CA certificate files        | `None`     |

#### Nebula CA Configuration

The Nebula CA plugin can be enabled by adding the following to the KBS config.

```yaml
[ [ plugins ] ]
  name = "nebula-ca"
```

The properties below can be used to further configure the plugin. They are optional.

| Property                   | Type       | Description                                                 | Default                                                  |
|----------------------------|------------|-------------------------------------------------------------|----------------------------------------------------------|
| `nebula_cert_bin_path`     | String     | `nebula-cert` binary path                                   | If not provided, `nebula-cert` will be searched in $PATH |
| `work_dir`                 | String     | This plugin work directory, it requires `rw` permission     | `/opt/confidential-containers/kbs/nebula-ca`             |
| `[plugins.self_signed_ca]` | SubSection | Properties used to create the Nebula CA key and certificate | See table below                                          |

The properties below can be defined under `[plugins.self_signed_ca]` to override their default value. They are optional.

| Property            | Type    | Description                                                                                                                                                     | Default                    | Example                                                   |
|---------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|-----------------------------------------------------------|
| `name`              | String  | Name of the certificate authority                                                                                                                               | `Trustee Nebula CA plugin` |                                                           |
| `argon_iterations`  | Integer | Argon2 iterations parameter used for encrypted private key passphrase                                                                                           | 1                          |                                                           |
| `argon_memory`      | Integer | Argon2 memory parameter (in KiB) used for encrypted private key passphrase                                                                                      | 2097152                    |                                                           |
| `argon_parallelism` | Integer | Argon2 parallelism parameter used for encrypted private key passphrase                                                                                          | 4                          |                                                           |
| `curve`             | String  | EdDSA/ECDSA Curve (25519, P256)                                                                                                                                 | `25519`                    |                                                           |
| `duration`          | String  | Amount of time the certificate should be valid for. Valid time units are: <hours>"h"<minutes>"m"<seconds>"s"                                                    | `8760h0m0s`                |                                                           |
| `groups`            | String  | Comma separated list of groups. This will limit which groups subordinate certs can use                                                                          | ""                         | `server,ssh`                                              |
| `ips`               | String  | Comma separated list of ipv4 address and network in CIDR notation. This will limit which ipv4 addresses and networks subordinate certs can use for ip addresses | ""                         | `192.168.100.10/24,192.168.100.15/24`                     |
| `out_qr`            | String  | Path to write a QR code image (png) of the certificate                                                                                                          |                            | `/opt/confidential-containers/kbs/nebula-ca/ca/ca_qr.crt` |
| `subnets`           | String  | Comma separated list of ipv4 address and network in CIDR notation. This will limit which ipv4 addresses and networks subordinate certs can use in subnets       | ""                         | `192.168.86.0/24`                                         |

The Nebula CA key and certificate are stored in `${work_dir}/ca/ca.{key,crt}`. If these files were generated in a
previous run
or [generated out-of-band](https://nebula.defined.net/docs/guides/quick-start/#creating-your-first-certificate-authority),
the plugin will just (re-)use them; otherwise, the plugin will generate new ones by calling the `nebula-cert` binary
with the `[plugins.self_signed_ca]` properties.

Detailed [documentation](#kbs/docs/plugins/nebula_ca.md).

#### External Plugin Configuration

External plugins extend KBS with custom gRPC-backed endpoints. A single `[[plugins]]` entry
with `name = "external"` owns all backends via a `backends` inline array:

```toml
[[plugins]]
name = "external"
backends = [
  { name = "my-plugin", endpoint = "https://localhost:50051", tls_mode = "tls", ca_cert_path = "/etc/kbs/plugin-ca.pem" },
]
```

Each backend is reachable at `/kbs/v0/external/<name>/...`.

**Per-backend fields:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | — | Sub-plugin name used in URL routing |
| `endpoint` | string | Yes | — | gRPC endpoint (`http://` for insecure, `https://` for TLS) |
| `ca_cert_path` | string | No | — | CA certificate path (required when `endpoint` is a TLS endpoint`) |
| `timeout_ms` | integer | No | — | Per-request timeout in milliseconds |

See [`ext_plugin.md`](ext_plugin.md) for deployment details and the gRPC protocol.

## Configuration Examples

### Using Storage Backend

With unified storage backend, you only need to declare one storage configuration that will be used for all storage needs:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
authorization_mode = "InsecureAllowAll"

[attestation_token]

# Unified storage backend configuration
# This single configuration will be used for:
# - KBS policy engine (namespace: "kbs")
# - Resource plugin storage (namespace: "repository")
# - KBS attestation session storage (namespace: "kbs_protocol_session")
# - Built-in AS policy storage (namespace: "attestation_service_policy")
# - Built-in AS RVPS storage (namespace: "reference_value")
[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/storage"

[attestation_service]
type = "coco_as_builtin"

[attestation_service.attestation_token_broker]
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"
# Optional: configure extractors
# [attestation_service.rvps_config.extractors]
# swid_extractor = {}

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

### Using RVPS-Specific Storage Configuration

You can configure RVPS to use a different storage backend than the rest of KBS:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
type = "InsecureAllowAll"

[attestation_token]

# Unified storage backend for most components (LocalFs)
[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/storage"

[storage_backend.backends.local_json]
file_dir_path = "/var/lib/rvps/references"

[attestation_service]
type = "coco_as_builtin"

[attestation_service.attestation_token_broker]
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

# RVPS-specific storage type override (LocalJson)
# Backend-specific parameters are still read from [storage_backend.backends]
storage_type = "LocalJson"

# Optional: configure extractors
[attestation_service.rvps_config.extractors]
swid_extractor = {}

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

### Using a remote CoCo AS

```toml
[http_server]
insecure_http = true

[admin]
authorization_mode = "InsecureAllowAll"

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50004"

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/storage"

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

Running with Intel Trust Authority attestation service:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/kbs-private.key"
certificate = "/etc/kbs-cert.pem"
insecure_http = false
payload_request_size = 2

[attestation_token]
trusted_jwk_sets = ["https://portal.trustauthority.intel.com"]

[attestation_service]
type = "intel_ta"
base_url = "https://api.trustauthority.intel.com"
api_key = "tBfd5kKX2x9ahbodKV1..."
certs_file = "https://portal.trustauthority.intel.com"
allow_unmatched_policy = true

[admin]
authorization_mode = "AuthenticatedAuthorization"

[admin.authentication.bearer_jwt]
identity_providers = [
  { public_key_uri = "/etc/kbs-admin.pub" }
]

[admin.authorization.regex_acl]
acls = [{ role = "admin", allowed_endpoints = "^/kbs/.+$" }]

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/storage"

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

Using Nebula CA plugin:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
authorization_mode = "InsecureAllowAll"

[attestation_token]

[attestation_service]
type = "coco_as_builtin"

[attestation_service.attestation_token_broker]
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/storage"

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"

[[plugins]]
name = "nebula-ca"
# If the Nebula CA key and certificate don't exist yet, the plugin will create them
# using the default configurations, which can be overriden here,
# e.g. the duration of the root CA.
#[plugin.self_signed_ca]
#duration = "4380hm0s0"
```

Distributing resources in Passport mode:

```toml
[http_server]
sockets = ["127.0.0.1:50002"]
insecure_http = true

[admin]
authorization_mode = "InsecureAllowAll"

[attestation_token]
trusted_certs_paths = ["./work/ca-cert.pem"]
insecure_header_jwk = false

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "./work/storage"

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

### TLS Configuration Examples

#### Using the Modern Profile (TLS 1.3 Only)

For high-security environments that only support modern clients:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/kbs-private.key"
certificate = "/etc/kbs-cert.pem"
tls_profile = "modern"

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50001"

[admin]
type = "DenyAll"

[storage_backend]
storage_type = "memory"
```

#### Using the Intermediate Profile (Default, Recommended)

Balances security and compatibility with TLS 1.2 and 1.3 support:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/kbs-private.key"
certificate = "/etc/kbs-cert.pem"
tls_profile = "intermediate"  # Can be omitted (it's the default)

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50001"

[admin]
type = "DenyAll"

[storage_backend]
storage_type = "memory"
```

#### Using Custom TLS Configuration

Full control over TLS parameters:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/kbs-private.key"
certificate = "/etc/kbs-cert.pem"
tls_profile = "custom"
tls_min_version = "1.2"
tls_max_version = "1.3"
# TLS 1.3 cipher suites (only encryption+hash; key exchange configured via tls_groups)
tls_ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
# Classical key exchange groups
tls_groups = "X25519:secp256r1:secp384r1"

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50001"

[admin]
type = "DenyAll"

[storage_backend]
storage_type = "memory"
```

#### Using Post-Quantum Cryptography (PQC)

Configure TLS 1.3 with post-quantum key exchange:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/kbs-private.key"
certificate = "/etc/kbs-cert.pem"
tls_profile = "custom"
tls_min_version = "1.3"
tls_max_version = "1.3"
# TLS 1.3 cipher suites (only encryption+hash; key exchange configured via tls_groups)
tls_ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
# Post-quantum key exchange groups with classical fallbacks
tls_groups = "X25519MLKEM768:X25519:secp256r1"

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50001"

[admin]
type = "DenyAll"

[storage_backend]
storage_type = "memory"
```

> [!NOTE]
> Post-quantum algorithms require OpenSSL 3.5 or later. If PQC algorithms are not available, KBS will log a warning and fall back to classical algorithms.
