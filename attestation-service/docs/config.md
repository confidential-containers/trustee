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
| `storage_backend`          | [StorageBackendConfig][4]   | Unified storage backend configuration for all storage needs | No | See below |

[1]: #attestationtokenbroker
[2]: #tokensignerconfig
[3]: #rvps-configuration
[4]: #unified-storage-backend-configuration

#### AttestationTokenBroker

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `developer_name`  | String               | The developer name to be used as part of the Verifier ID in the EAR | No       |`https://confidentialcontainers.org`|
| `build_name`  | String                  | The build name to be used as part of the Verifier ID in the EAR         | No       | Automatically generated from Cargo package and AS version|
| `profile_name`  | String                  | The Profile that describes the EAR token         | No       |tag:github.com,2024:confidential-containers/Trustee`|
| `signer`       | [TokenSignerConfig][2]  | Signing material of the attestation result token.    | No       | None       |

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

If `type` is set to `BuiltIn`, the following extra properties can be set:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `extractors` | Object | Optional configuration for provenance extractors | No | None |

**Note:** Storage configuration for BuiltIn RVPS is now managed through the unified `storage_backend` configuration (see [Storage Backend Configuration](#storage-backend-configuration)). The BuiltIn RVPS will use the `reference-value` instance from the unified storage backend.

For detailed information about extractors configuration, including available extractors and their options, see the [RVPS README](../../rvps/README.md#extractors-configuration).

**Example:**
```json
{
    "rvps_config": {
        "type": "BuiltIn",
        "extractors": {
            "swid_extractor": {}
        }
    }
}
```

##### Remote RVPS

If `type` is set to `GrpcRemote`, the following extra properties can be set

| Property       | Type                    | Description                             | Required | Default          |
|----------------|-------------------------|-----------------------------------------|----------|------------------|
| `address`      | String                  | Remote address of the RVPS server       | No       | `127.0.0.1:50003`|


## Configuration Examples

Running with a built-in RVPS (using unified storage backend):

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "storage_backend": {
        "storage_type": "LocalFs",
        "backends": {
            "local_fs": {
                "dir_path": "/var/lib/attestation-service/storage"
            }
        }
    },
    "rvps_config": {
        "type": "BuiltIn"
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

Running with a built-in RVPS with extractor configuration:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "storage_backend": {
        "storage_type": "LocalFs",
        "backends": {
            "local_fs": {
                "dir_path": "/var/lib/attestation-service/storage"
            }
        }
    },
    "rvps_config": {
        "type": "BuiltIn",
        "extractors": {
            "swid_extractor": {}
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
        "signer": {
            "key_path": "/etc/coco-as/signer.key",
            "cert_url": "https://example.io/coco-as-certchain",
            "cert_path": "/etc/coco-as/signer.pub"
        }
    }
}
```

Running with unified storage backend (recommended):

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "storage_backend": {
        "storage_type": "LocalFs",
        "backends": {
            "local_fs": {
                "dir_path": "/var/lib/attestation-service/storage"
            }
        }
    },
    "rvps_config": {
        "type": "BuiltIn"
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

Running with PostgreSQL storage using unified storage backend:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "storage_backend": {
        "storage_type": "Postgres",
        "backends": {
            "postgres": {
                "host": "localhost",
                "port": 5432,
                "db": "coco_as",
                "username": "postgres",
                "password": "password"
            }
        }
    },
    "rvps_config": {
        "type": "BuiltIn"
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

### Storage Backend Configuration

CoCo AS supports a unified storage backend configuration that allows you to declare a single storage configuration that will be used for all storage needs in the Attestation Service.

This simplifies deployment by eliminating the need to configure storage separately for each component.

For detailed information about the unified storage backend configuration format, including what an **instance** is and how it works, see the [Key-Value Storage README](../../deps/key-value-storage/README.md#unified-storage-backend-configuration).

#### Storage Instances in CoCo AS

When using the unified storage backend configuration, CoCo AS creates the following storage instances:

| Instance Name | Component | Description |
|---------------|-----------|-------------|
| `attestation-service-policy` | Attestation Token Broker | Stores EAR (Entity Attestation Report) policies |
| `reference-value` | Built-in RVPS | Stores reference values for software supply chain verification |

The unified storage backend configuration is optional. If not provided, CoCo AS will use the legacy per-component storage configurations.

For detailed configuration options and examples, see the [Key-Value Storage README](../../deps/key-value-storage/README.md#unified-storage-backend-configuration).
