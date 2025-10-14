# CoCo AS Configuration File

The Confidential Containers KBS properties can be configured through a
JSON-formatted configuration file.

## Configurable Properties

The following sections list the CoCo AS properties which can be set through the
configuration file.

### Global Properties

The following properties can be set globally, i.e. not under any configuration
section:

| Property                   | Type                        | Description                                         | Required | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|---------|
| `work_dir`                 | String                      | The location for Attestation Service to store data. | False      | Firstly try to read from ENV `AS_WORK_DIR`. If not any, use `/opt/confidential-containers/attestation-service`       |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                  | False      | -       |
| `attestation_token_broker` | [AttestationTokenBroker][1]  | Attestation result token configuration.            | False      | -       |

[1]: #attestationtokenbroker
[2]: #rvps-configuration

#### AttestationTokenBroker

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `developer_name`  | String               | The developer name to be used as part of the Verifier ID in the EAR | No       |`https://confidentialcontainers.org`|
| `build_name`  | String                  | The build name to be used as part of the Verifier ID in the EAR         | No       | Automatically generated from Cargo package and AS version|
| `profile_name`  | String                  | The Profile that describes the EAR token         | No       |tag:github.com,2024:confidential-containers/Trustee`|
| `policy_dir`  | String                  | The path to the work directory that contains policies to provision the tokens.        | No       |`/opt/confidential-containers/attestation-service/token/policies`|
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | None       |

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
| `type`         | String                  | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set

| Property       | Type                    | Description                                                           | Required | Default  |
|----------------|-------------------------|-----------------------------------------------------------------------|----------|----------|
| `storage`   | ReferenceValueStorageConfig | Configuration of storage for reference values (`LocalFs` or `LocalJson`)       | No       | `LocalFs`|

`ReferenceValueStorageConfig` can contain either a `LocalFs` configuration or a `LocalJson` configuration.

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


## Configuration Examples

Running with a built-in RVPS:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "LocalFs"
            "file_path": "/var/lib/attestation-service/reference-values"
        }
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

Running with a remote RVPS:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

Configurations for token signer

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5,
        "issuer_name": "some-body",
        "signer": {
            "key_path": "/etc/coco-as/signer.key",
            "cert_url": "https://example.io/coco-as-certchain",
            "cert_path": "/etc/coco-as/signer.pub"
        }
    }
}
```
