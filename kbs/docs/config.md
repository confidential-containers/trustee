# KBS Configuration File

The Confidential Containers KBS properties can be configured through a
TOML-formatted configuration file.

>NOTE: Additional formats such as YAML and JSON are supported. Other formats
>supported by the `config` crate may be supported as well. This document uses
>TOML in the configuration examples.

The location of the configuration file is passed to the KBS binary using the
`-c` or `--config-file` command line option, or using the `KBS_CONFIG_FILE`
environment variable.

## Configurable Properties

The following sections list the KBS properties which can be set through the
configuration file.

### HTTP Server Configuration

The following properties can be set under the `[http_server]` section.

| Property                 | Type         | Description                                                                                                | Required | Default              |
|--------------------------|--------------|------------------------------------------------------------------------------------------------------------|----------|----------------------|
| `sockets`                | String array | One or more sockets to listen on.                                                                          | No       | `["127.0.0.1:8080"]` |
| `insecure_http`          | Boolean      | Don't use TLS for the KBS HTTP endpoint.                                                                   | No       | `false`              |
| `private_key`            | String       | Path to a private key file to be used for HTTPS.                                                           | No       | None                 |
| `certificate`            | String       | Path to a certificate file to be used for HTTPS.                                                           | No       | None                 |

### Attestation Token Configuration

Attestation Token configuration controls attestation token verifications. This
is important when a resource retrievement is handled by KBS. Usually an attestation
token will be together with the request, and KBS will first verify the token.

The following properties can be set under the `[attestation_token]` section.

| Property                   | Type         | Description                                                                                                                                               | Default |
|----------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| `trusted_jwk_sets` | String Array      | Valid Url (`file://` or `https://`) pointing to trusted JWKSets (local or OpenID) for Attestation Tokens trustworthy verification                                                                                             | Empty       |
| `trusted_certs_paths` | String Array | Trusted Certificates file (PEM format) for Attestation Tokens trustworthy verification | Empty       |
| `extra_teekey_paths` | String Array | User defined paths to the tee public key in the JWT body  | Empty       |
| `insecure_key` | Boolean | Whether to check the trustworthy of the JWK inside JWT. See comments. | `false`      |

Each JWT contains a TEE Public Key. Users can use the `extra_teekey_paths` field to additionally specify the path of this Key in the JWT.
Example of `extra_teekey_paths` is `/attester_runtime_data/tee-pubkey` which refers to the key
`attester_runtime_data.tee-pubkey` inside the JWT body claims. By default CoCo AS Token and Intel TA
Token TEE Public Key paths are supported.

For Attestation Services like CoCo-AS, the public key to verify the JWT will be given
in the token's `jwk` field (with or without the public key cert chain `x5c`).

- If `insecure_key` is set to `true`, KBS will ignore to verify the trustworthy of the `jwk`.
- If `insecure_key` is set to `false`, KBS will look up its `trusted_certs_paths` and the `x5c`
field to verify the trustworthy of the `jwk`.

For Attestation Services like Intel TA, there will only be a `kid` field inside the JWT.
The `kid` field is used to look up the trusted jwk configured by KBS via `trusted_jwk_sets` to
verify the integrity and trustworthy of the JWT.

### Attestation Configuration

Attestation configuration defines the attestation service that KBS' RCAR protocol
will leverage.

The following properties can be set under the `[attestation_service]` section.

Concrete attestation service can be set via `type` field. Supported attestation
services are
- `coco_as_builtin`: CoCo AS that built inside KBS binary
- `coco_as_grpc`: CoCo AS service running remotely
- `intel_ta`: Intel&reg; Trust Authority

Due to different `type` field, properties are different.

#### Built-In CoCo AS

When `type` is set to `coco_as_builtin`, the following properties can be set.

>Built-In CoCo AS is available only when one or more of the following features are enabled:
>`coco-as-builtin`, `coco-as-builtin-no-verifier`

| Property                   | Type                        | Description                                          | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|
| `timeout`            | Integer                      | The maximum time (in minutes) of the attestation session             |  5       |
| `work_dir`                 | String                      | The location for Attestation Service to store data. |  First try from env `AS_WORK_DIR`. If no this env, then use `/opt/confidential-containers/attestation-service`       |
| `policy_engine`            | String                      | Policy engine type. Valid values: `opa`             |  `opa`       |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                  |  See [RVPSConfiguration][2]       |
| `attestation_token_broker` | [AttestationTokenConfig][1] | Attestation result token configuration.             |  See [AttestationTokenConfig][1]       |

[1]: #attestationtokenbroker
[2]: #rvps-configuration


##### AttestationTokenBroker

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | Type of token to issue (`Ear` or `Simple`)               | No       | `Ear`   |

When `type` field is set to `Ear`, the following extra properties can be set:
| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `developer_name`  | String               | The developer name to be used as part of the Verifier ID in the EAR | No       |`https://confidentialcontainers.org`|
| `build_name`  | String                  | The build name to be used as part of the Verifier ID in the EAR         | No       | Automatically generated from Cargo package and AS version|
| `profile_name`  | String                  | The Profile that describes the EAR token         | No       |tag:github.com,2024:confidential-containers/Trustee`|
| `policy_dir`  | String                  | The path to the work directory that contains policies to provision the tokens.        | No       |`/opt/confidential-containers/attestation-service/token/ear/policies`|
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | None       |

[1]: #tokensignerconfig

When `type` field is set to `Simple`, the following extra properties can be set:
| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `policy_dir`  | String                  | The path to the work directory that contains policies to provision the tokens.        | No       |`/opt/confidential-containers/attestation-service/token//simple/policies`|
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | None       |

[1]: #tokensignerconfig

##### TokenSignerConfig

This section is **optional**. When omitted, an ephemeral RSA key pair is generated and used. 

| Property       | Type    | Description                                              | Required |
|----------------|---------|----------------------------------------------------------|----------|
| `key_path`     | String  | RSA Key Pair file (PEM format) path.                     | Yes      |
| `cert_url`     | String  | RSA Public Key certificate chain (PEM format) URL.       | No       |
| `cert_path`    | String  | RSA Public Key certificate chain (PEM format) file path. | No       |

##### RVPS Configuration

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set

| Property       | Type                    | Description                                                           | Required | Default  |
|----------------|-------------------------|-----------------------------------------------------------------------|----------|----------|
| `storage`   | ReferenceValueStorageConfig | Configuration of the storage for reference values (`LocalFs` or `LocalJson`) | No       | `LocalFs`|

A `ReferenceValueStorageConfig` can either be of type `LocalFs` or `LocalJson`

For `LocalFs`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the directory storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values`|

For `LocalJson`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the file that storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values.json`|

##### Remote RVPS

If `type` is set to `GrpcRemote`, the following extra properties can be set

| Property       | Type                    | Description                             | Required | Default          |
|----------------|-------------------------|-----------------------------------------|----------|------------------|
| `address`      | String                  | Remote address of the RVPS server       | No       | `127.0.0.1:50003`|

#### gRPC CoCo AS

When `type` is set to `coco_as_grpc`, KBS will try to connect a remote CoCo AS for
attestation. The following properties can be set.

>gRPC CoCo AS is available only when `coco-as-grpc` feature is enabled.

| Property                   | Type                        | Description                                          | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|
| `timeout`            | Integer                      | The maximum time (in minutes) between RCAR handshake's `auth` and `attest` requests             |  5       |
| `as_addr`                 | String                      | The URL of the remote CoCoAS |  `http://127.0.0.1:50004`       |
| `pool_size`   | Integer         | The connections between KBS and CoCoAS are maintained in a conenction pool. This property determines the max size of the pool                      | `100`             |

#### Intel&reg; TA

When `type` is set to `intel_ta`, KBS will try to connect a remote Intel TA service for
attestation. The following properties can be set.

> Intel Trust Authority AS is available only when the `intel-trust-authority-as` feature is enabled.

| Property                 | Type         | Description                                                                              | Required | Default |
|--------------------------|--------------|------------------------------------------------------------------------------------------|----------|---------|
| `timeout`                | Integer      | The maximum time (in minutes) between RCAR handshake's `auth` and `attest` requests      | No       | 5       |
| `base_url`               | String       | Intel Trust Authority API URL.                                                           | Yes      | -       |
| `api_key`                | String       | Intel Trust Authority API key.                                                           | Yes      | -       |
| `certs_file`             | String       | URL to an Intel Trust Authority portal or path to JWKS file used for token verification. | Yes      | -       |
| `allow_unmatched_policy` | Boolean      | If set and `policy_ids` specified, unset the `request.policy_must_match` setting         | No       | false   |
| `policy_ids`             | String array | List of one or more quoted and comma-separated policy IDs.                               | No       | `[]`    |

Detailed [documentation](https://docs.trustauthority.intel.com).

### Admin API Configuration

The following properties can be set under the `[admin]` section.

| Property                 | Type         | Description                                                                                                | Required | Default              |
|--------------------------|--------------|------------------------------------------------------------------------------------------------------------|----------|----------------------|
| `auth_public_key`        | String       | Path to the public key used to authenticate the admin APIs                                                 | No       | None                 |
| `insecure_api`           | Boolean      | Whether KBS will not verify the public key when called admin APIs                                          | No       | `false`              |

### Policy Engine Configuration

The following properties can be set under the `[policy_engine]` section.

This section is **optional**. When omitted, a default configuration is used.

| Property                 | Type    | Description                                                                                                | Required                | Default                                        |
|--------------------------|---------|------------------------------------------------------------------------------------------------------------|-------------------------|------------------------------------------------|
| `policy_path`            | String  | Path to a file containing a policy for evaluating whether the TCB status has access to specific resources. | No                      | `/opa/confidential-containers/kbs/policy.rego` |

### Plugins Configuration

KBS supports different kinds of plugins, and they can be enabled via add corresponding configs.

Multiple `[[plugins]]` sections are allowed at the same time for different plugins.
Concrete attestation service can be set via `name` field.

#### Resource Configuration

The `name` field is `resource` to enable this plugin.

Resource plugin allows user with proper attestation token to access storage that KBS keeps.
This is also called "Repository" in old versions. The properties to be configured are listed.

| Property | Type   | Description                                                     | Required | Default   |
|----------|--------|-----------------------------------------------------------------|----------|-----------|
| `type`   | String | The resource repository type. Valid values: `LocalFs`, `Aliyun` | Yes      | `LocalFs` |

**`LocalFs` Properties**

| Property   | Type   | Description                     | Required | Default                                             |
|------------|--------|---------------------------------|----------|-----------------------------------------------------|
| `dir_path` | String | Path to a repository directory. | No       | `/opt/confidential-containers/kbs/repository`       |

**`Aliyun` Properties**

| Property          | Type   | Description                       | Required | Example                                             |
|-------------------|--------|-----------------------------------|----------|-----------------------------------------------------|
| `client_key`      | String | The KMS instance's AAP client key | Yes      | `{"KeyId": "KA..", "PrivateKeyData": "MIIJqwI..."}` |
| `kms_instance_id` | String | The KMS instance id               | Yes      | `kst-shh668f7...`                                   |
| `password`        | String | AAP client key password           | Yes      | `8f9989c18d27...`                                   |
| `cert_pem`        | String | CA cert for the KMS instance      | Yes      | `-----BEGIN CERTIFICATE----- ...`                   |

## Configuration Examples

Using a built-in CoCo AS:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
insecure_api = true

[attestation_token]

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"

    [attestation_service.attestation_token_broker]
    type = "Ear"
    duration_min = 5

    [attestation_service.rvps_config]
    type = "BuiltIn"

    [attestation_service.rvps_config.storage]
    type = "LocalFs"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
```

Using a remote CoCo AS:

```toml
[http_server]
insecure_http = true

[admin]
insecure_api = true

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50004"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
```

Running with Intel Trust Authority attestation service:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/kbs-private.key"
certificate = "/etc/kbs-cert.pem"
insecure_http = false

[attestation_token]
trusted_jwk_sets = ["https://portal.trustauthority.intel.com"]

[attestation_token]

[attestation_service]
type = "intel_ta"
base_url = "https://api.trustauthority.intel.com"
api_key = "tBfd5kKX2x9ahbodKV1..."
certs_file = "https://portal.trustauthority.intel.com"
allow_unmatched_policy = true

[admin]
auth_public_key = "/etc/kbs-admin.pub"
insecure_api = false

[policy_engine]
policy_path = "/etc/kbs-policy.rego"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
```

Distributing resources in Passport mode:

```toml
[http_server]
sockets = ["127.0.0.1:50002"]
insecure_http = true

[admin]
auth_public_key = "./work/kbs.pem"

[attestation_token]
trusted_certs_paths = ["./work/ca-cert.pem"]
insecure_key = false

[policy_engine]
policy_path = "./work/kbs-policy.rego"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "./work/repository"
```
