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
| `work_dir`                 | String                      | The location for Attestation Service to store data. | No       | ENV `AS_WORK_DIR`, otherwise `/opt/confidential-containers/attestation-service` |
| `rvps_config`              | [RVPSConfiguration][3]      | RVPS configuration                                  | No       | `BuiltIn` |
| `attestation_token_broker` | [AttestationTokenBroker][1] | Attestation result token configuration.             | No       | See below |
| `verifier_config`          | Object                      | Optional verifier specific configuration (for example TPM) | No | None |

[1]: #attestationtokenbroker
[2]: #tokensignerconfig
[3]: #rvps-configuration
[4]: #policyengineconfig
[5]: #keyvaluestorage

#### AttestationTokenBroker

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `developer_name`  | String               | The developer name to be used as part of the Verifier ID in the EAR | No       |`https://confidentialcontainers.org`|
| `build_name`  | String                  | The build name to be used as part of the Verifier ID in the EAR         | No       | Automatically generated from Cargo package and AS version|
| `profile_name`  | String                  | The Profile that describes the EAR token         | No       |tag:github.com,2024:confidential-containers/Trustee`|
| `signer`       | [TokenSignerConfig][2]  | Signing material of the attestation result token.    | No       | None       |
| `policy_engine`| [PolicyEngineConfig][4] | Storage backend used to keep EAR policies.           | No       | In‑memory storage |

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

| Property | Type                       | Description                                   | Required | Default  |
|----------|----------------------------|-----------------------------------------------|----------|----------|
| `storage`| [KeyValueStorage][5]       | Storage backend for reference values          | No       | `Memory` |

`storage` accepts the following shapes:

- `{"type": "Memory"}` (default, in‑memory)
- `{"type": "LocalFs", "dir_path": "/opt/confidential-containers/storage/local_fs"}` (each value as a file)
- `{"type": "LocalJson", "file_path": "/opt/confidential-containers/storage/local_json/key_value.json"}` (all values in one JSON file)

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
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "LocalFs",
            "dir_path": "/var/lib/attestation-service/reference-values"
        }
    },
    "attestation_token_broker": {
        "duration_min": 5,
        "policy_engine": {
            "storage": {
                "type": "LocalJson",
                "file_path": "/var/lib/attestation-service/ear-policies.json"
            }
        }
    }
}
```

Running with a remote RVPS:

```json
{
    "work_dir": "/var/lib/attestation-service/",
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
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5,
        "issuer_name": "some-body",
        "policy_engine": {
            "storage": { "type": "Memory" }
        },
        "signer": {
            "key_path": "/etc/coco-as/signer.key",
            "cert_url": "https://example.io/coco-as-certchain",
            "cert_path": "/etc/coco-as/signer.pub"
        }
    }
}
```

#### PolicyEngineConfig

| Property | Type                 | Description                                       | Default  |
|----------|----------------------|---------------------------------------------------|----------|
| `storage`| [KeyValueStorage][5] | Backend used to persist EAR policies              | `Memory` |

#### KeyValueStorage

| `type` value | Extra fields | Description | Default path |
|--------------|--------------|-------------|--------------|
| `Memory`     | None         | Ephemeral in‑memory store | N/A |
| `LocalFs`    | `dir_path`   | Store each value as a file | `/opt/confidential-containers/storage/local_fs` |
| `LocalJson`  | `file_path`  | Store all values in one JSON file | `/opt/confidential-containers/storage/local_json/key_value.json` |
