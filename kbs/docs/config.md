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

### Global Properties

The following properties can be set globally, i.e. not under any configuration
section:

| Property                 | Type         | Description                                                                                                | Required | Default              |
|--------------------------|--------------|------------------------------------------------------------------------------------------------------------|----------|----------------------|
| `sockets`                | String array | One or more sockets to listen on.                                                                          | No       | `["127.0.0.1:8080"]` |
| `insecure_api`           | Boolean      | Enable KBS insecure APIs such as Resource Registration without JWK verification.                           | No       | `false`              |
| `insecure_http`          | Boolean      | Don't use TLS for the KBS HTTP endpoint.                                                                   | No       | `false`              |
| `timeout`                | Integer      | HTTP session timeout in minutes.                                                                           | No       | `5`                  |
| `private_key`            | String       | Path to a private key file to be used for HTTPS.                                                           | No       | -                    |
| `certificate`            | String       | Path to a certificate file to be used for HTTPS.                                                           | No       | -                    |
| `auth_public_key`        | String       | Path to a public key file to be used for authenticating the resource registration endpoint token (JWT).    | No       | -                    |

### Attestation Token Configuration

The following properties can be set under the `attestation_token_config` section.

>This section is available only when the `resource` feature is enabled.

| Property                   | Type          | Description                                         | Required | Default   |
|----------------------------|---------------|-----------------------------------------------------|----------|-----------|
| `attestation_token_config` | String        | Attestation token broker type. Valid values: `CoCo` | Yes      | -         |
| `trusted_certs_paths`        | String Array  | Trusted root certificates file paths (PEM format).  | No       | -         |

If `trusted_certs_paths` is set, KBS will forcibly check the validity of the Attestation Token signature public key certificate,
if not set this field, KBS will skip the verification of the certificate.

### Repository Configuration

The following properties can be set under the `repository_config` section.

This section is **optional**. When omitted, a default configuration is used.

Repository configuration is **specific to a repository type**. See the following sections for
type-specific properties.

>This section is available only when the `resource` feature is enabled. Only one repository is available at a time.

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

### Native Attestation

The following properties can be set under the `as_config` section.

This section is **optional**. When omitted, a default configuration is used.

>This section is available only when one or more of the following features are enabled:
>`coco-as-builtin`, `coco-as-builtin-no-verifier`

| Property                   | Type                        | Description                                         | Required | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|---------|
| `work_dir`                 | String                      | The location for Attestation Service to store data. | Yes      | -       |
| `policy_engine`            | String                      | Policy engine type. Valid values: `opa`             | Yes      | -       |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                  | Yes      | -       |
| `attestation_token_broker` | String                      | Type of the attestation result token broker.        | Yes      | -       |
| `attestation_token_config` | [AttestationTokenConfig][1] | Attestation result token configuration.             | Yes      | -       |

[1]: #attestationtokenconfig
[2]: #rvps-configuration

#### AttestationTokenConfig

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | Yes      | -       |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       | -       |
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | -       |

[1]: #tokensignerconfig

#### TokenSignerConfig

This section is **optional**. When omitted, a new RSA key pair is generated and used.

| Property       | Type    | Description                                              | Required | Default |
|----------------|---------|----------------------------------------------------------|----------|---------|
| `key_path`     | String  | RSA Key Pair file (PEM format) path.                     | Yes      | -       |
| `cert_url`     | String  | RSA Public Key certificate chain (PEM format) URL.       | No       | -       |
| `cert_path`    | String  | RSA Public Key certificate chain (PEM format) file path. | No       | -       |

#### RVPS Configuration

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `remote_addr`  | String                  | Remote RVPS' address. If this is specified, will use a remote RVPS. Or a local RVPS will be configured with `store_type` and `store_config`| Conditional       | -       |
| `store_type`   | String                  | Used if `remote_addr` is not set. The underlying storage type of RVPS.                                                                     | Conditional       | -       |
| `store_config` | JSON Map                | Used if `remote_addr` is not set. The optional configurations to the underlying storage.                                                   | Conditional       | -       |

Different `store_type` will have different `store_config` items.
See the details of `store_config` in [concrete implementations of storages](../../rvps/src/store/).

### gRPC Attestation

The following properties can be set under the `grpc_config` section.

This section is **optional**. When omitted, a default configuration is used.

>This section is available only when the `coco-as-grpc` feature is enabled.

| Property  | Type   | Description                  | Required | Default                  |
|-----------|--------|------------------------------|----------|--------------------------|
| `as_addr` | String | Attestation service address. | No       | `http://127.0.0.1:50004` |

### Intel Trust Authority (formerly known as Amber)

The following properties can be set under the `intel_trust_authority_config` section.

>This section is available only when the `intel-trust-authority-as` feature is enabled.

| Property                 | Type    | Description                                                                              | Required                | Default |
|--------------------------|---------|------------------------------------------------------------------------------------------|-------------------------|---------|
| `base_url`               | String  | Intel Trust Authority API URL.                                                           | Yes                     | -       |
| `api_key`                | String  | Intel Trust Authority API key.                                                           | Yes                     | -       |
| `certs_file`             | String  | URL to an Intel Trust Authority portal or path to JWKS file used for token verification. | Yes                     | -       |
| `allow_unmatched_policy` | Boolean | Determines whether to ignore the `policy_ids_unmatched` token claim.                     | No                      | false   |

Detailed [documentation](https://docs.trustauthority.intel.com).

### Policy Engine Configuration

The following properties can be set under the `policy_engine_config` section.

This section is **optional**. When omitted, a default configuration is used.

| Property                 | Type    | Description                                                                                                | Required                | Default                                        |
|--------------------------|---------|------------------------------------------------------------------------------------------------------------|-------------------------|------------------------------------------------|
| `policy_path`            | String  | Path to a file containing a policy for evaluating whether the TCB status has access to specific resources. | No                      | `/opa/confidential-containers/kbs/policy.rego` |

## Configuration Examples

Running with a built-in native attestation service:

```toml
insecure_http = true
insecure_api = true

[repository_config]
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

[as_config]
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"
rvps_store_type = "LocalFs"
attestation_token_broker = "Simple"

[as_config.attestation_token_config]
duration_min = 5
```

Running the attestation service remotely:

```toml
insecure_http = true
insecure_api = true

[repository_config]
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

[grpc_config]
as_addr = "http://127.0.0.1:50004"
```

Running with Intel Trust Authority attestation service:

```toml
insecure_http = true
insecure_api = true

[attestation_token_config]
attestation_token_type = "Jwk"
trusted_certs_paths = ["https://portal.trustauthority.intel.com"]

[repository_config]
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

[intel_trust_authority_config]
base_url = "https://api.trustauthority.intel.com"
api_key = "tBfd5kKX2x9ahbodKV1..."
certs_file = "https://portal.trustauthority.intel.com"
allow_unmatched_policy = true
```

Distributing resources in Passport mode:

```toml
insecure_http = true
insecure_api = true

[repository_config]
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

[policy_engine_config]
policy_path = "/opt/confidential-containers/kbs/policy.rego"
```
