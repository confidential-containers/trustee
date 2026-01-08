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

This section is **optional**. When omitted, a new EC key pair is generated and used.

| Property       | Type    | Description                                             | Required | Default |
|----------------|---------|---------------------------------------------------------|----------|---------|
| `key_path`     | String  | EC Key Pair file (PEM format) path.                     | Yes      | -       |
| `cert_url`     | String  | EC Public Key certificate chain (PEM format) URL.       | No       | -       |
| `cert_path`    | String  | EC Public Key certificate chain (PEM format) file path. | No       | -       |

#### RVPS Configuration

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set

| Property | Type                       | Description                                   | Required | Default  |
|----------|----------------------------|-----------------------------------------------|----------|----------|
| `storage`| [KeyValueStorage][5]       | Storage backend for reference values          | No       | `Memory` |

See [KeyValueStorage][5] for available storage backends and their configuration options.

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

Running with PostgreSQL storage:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "Postgres",
            "host": "localhost",
            "port": 5432,
            "db": "coco_as",
            "username": "postgres",
            "password": "password",
            "table": "reference_values"
        }
    },
    "attestation_token_broker": {
        "duration_min": 5,
        "policy_engine": {
            "storage": {
                "type": "Postgres",
                "host": "localhost",
                "port": 5432,
                "db": "coco_as",
                "username": "postgres",
                "password": "password",
                "table": "ear_policies"
            }
        }
    }
}
```

#### PolicyEngineConfig

| Property | Type                 | Description                                       | Default  |
|----------|----------------------|---------------------------------------------------|----------|
| `storage`| [KeyValueStorage][5] | Backend used to persist EAR policies              | `Memory` |

See [KeyValueStorage][5] for available storage backends and their configuration options.

#### KeyValueStorage

The `KeyValueStorage` configuration defines the storage backend used for key-value pairs. It is used in multiple places throughout the configuration, including:

- Policy Engine storage (see [PolicyEngineConfig][4])
- RVPS storage (see [RVPS Configuration][3])

The following storage types are supported:

| `type` value | Extra fields | Description | Default path |
|--------------|--------------|-------------|--------------|
| `Memory`     | None         | Ephemeral in‑memory store (data is lost on restart) | N/A |
| `LocalFs`    | `dir_path`   | Store each value as a file | `/opt/confidential-containers/storage/local_fs` |
| `LocalJson`  | `file_path`  | Store all values in one JSON file | `/opt/confidential-containers/storage/local_json/key_value.json` |
| `Postgres`   | See below    | Store key-value pairs in a PostgreSQL database table | N/A |

When `type` is `Postgres`, the following properties can be set:

| Property   | Type    | Description                                    | Required | Default      |
|------------|---------|------------------------------------------------|----------|--------------|
| `db`       | String  | The name of the PostgreSQL database            | No       | `postgres`   |
| `username` | String  | The username of the PostgreSQL database        | No       | `postgres`   |
| `password` | String  | The password of the PostgreSQL database        | No       | None         |
| `port`     | Integer | The port of the PostgreSQL database            | No       | `5432`       |
| `host`     | String  | The host of the PostgreSQL database            | No       | `localhost`  |
| `table`    | String  | The name of the table to store key-value pairs | No       | `key_value`  |

> NOTE: If the `POSTGRES_URL` environment variable is set with a PostgreSQL connection URI, it will be used instead of the configuration parameters above.
