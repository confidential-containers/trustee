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

**Note:** Storage configuration for BuiltIn RVPS is now managed through the unified `storage_backend` configuration (see [Storage Backend Configuration](#storage-backend-configuration)). The BuiltIn RVPS will use the `reference-value` namespace from the unified storage backend.

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

#### Verifier Configuration

The `verifier_config` section allows for TEE-specific verifier configuration. Each verifier can have its own configuration based on the enabled features.

##### NVIDIA GPU Verifier

Available when the `nvidia-verifier` feature is enabled. See details in [`nvidia-verifier` documentation](../../deps/verifier/src/nvidia/README.md).

| Property          | Type                             | Description                                     | Required | Default |
|-------------------|----------------------------------|-------------------------------------------------|----------|---------|
| `nvidia_verifier` | [NvidiaVerifierConfig][nvidia-1] | NVIDIA GPU verifier configuration               | No       | -       |

[nvidia-1]: #nvidiaverifierconfig

###### NvidiaVerifierConfig

| Property | Type   | Description                                                     | Required | Default |
|----------|--------|-----------------------------------------------------------------|----------|---------|
| `type`   | String | Verification type: `"Local"` or `"Remote"`                      | No       | `"Local"` |
| `verifier_url` | String | Remote verifier URL (only for `"Remote"` type)            | No       | `https://nras.attestation.nvidia.com/v4/attest` |

##### TPM Verifier

Available when the `tpm-verifier` feature is enabled.

| Property      | Type                           | Description                      | Required | Default |
|---------------|--------------------------------|----------------------------------|----------|---------|
| `tpm_verifier` | [TpmVerifierConfig][tpm-1]     | TPM verifier configuration       | No       | -       |

[tpm-1]: #tpmverifierconfig

###### TpmVerifierConfig

| Property              | Type   | Description                                             | Required | Default                          |
|-----------------------|--------|---------------------------------------------------------|----------|----------------------------------|
| `trusted_ak_keys_dir` | String | Directory containing trusted Attestation Key (AK) files | No       | `/etc/tpm/trusted_ak_keys`       |
| `max_trusted_ak_keys` | Integer | Maximum number of trusted AK keys to load              | No       | `100`                            |

##### SNP Verifier

Available when the `snp-verifier` feature is enabled. See details in [AMD SNP certificates caching guide](./amd-offline-certificate-cache.md).

| Property      | Type                           | Description                      | Required | Default |
|---------------|--------------------------------|----------------------------------|----------|---------|
| `snp_verifier` | [SnpVerifierConfig][snp-1]     | AMD SEV-SNP verifier configuration | No     | -       |

[snp-1]: #snpverifierconfig

###### SnpVerifierConfig

| Property       | Type                 | Description                                   | Required | Default                         |
|----------------|----------------------|-----------------------------------------------|----------|---------------------------------|
| `vcek_sources` | Array of [VCEKSource][snp-2] | Sources for fetching VCEK certificates | No       | `[{"type": "KDS"}]`             |

[snp-2]: #vceksource

###### VCEKSource

A VCEK source can be either `KDS` (AMD Key Distribution Service) or `OfflineStore` (local filesystem).

For `KDS` type:

| Property   | Type   | Description                    | Required | Default                               |
|------------|--------|--------------------------------|----------|---------------------------------------|
| `type`     | String | Must be `"KDS"`                | Yes      | -                                     |
| `base_url` | String | Base URL for KDS service       | No       | `https://kdsintf.amd.com`             |

For `OfflineStore` type:

| Property | Type   | Description                                | Required | Default                                                              |
|----------|--------|--------------------------------------------|----------|----------------------------------------------------------------------|
| `type`   | String | Must be `"OfflineStore"`                   | Yes      | -                                                                    |
| `path`   | String | Path to offline certificate store          | No       | `/opt/confidential-containers/attestation-service/kds-store`         |

##### Intel DCAP Verifier

Available when the `tdx-verifier`, `sgx-verifier`, or `az-tdx-vtpm-verifier` feature is enabled.

| Property        | Type                      | Description                                  | Required | Default |
|-----------------|---------------------------|----------------------------------------------|----------|---------|
| `dcap_verifier` | [QcnlConfig][dcap-1]      | Intel DCAP QCNL configuration                | No       | -       |

[dcap-1]: #qcnlconfig

###### QcnlConfig

| Property              | Type    | Description                                           | Required | Default                                                    |
|-----------------------|---------|-------------------------------------------------------|----------|------------------------------------------------------------|
| `collateral_service`  | String  | URL of the Intel PCS collateral service               | No       | `https://api.trustedservices.intel.com/sgx/certification/v4/` |
| `use_secure_cert`     | Boolean | Whether to use secure certificates                    | No       | -                                                          |
| `tcb_update_type`     | String  | TCB update type: `"early"` or `"standard"`            | No       | `"early"`                                                  |


## Configuration Examples

Running with a built-in RVPS (using unified storage backend):

```json
{
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

Configuration with TPM verifier:

```json
{
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    },
    "verifier_config": {
        "tpm_verifier": {
            "trusted_ak_keys_dir": "/etc/tpm/trusted_ak_keys",
            "max_trusted_ak_keys": 50
        }
    }
}
```

Configuration with AMD SEV-SNP verifier using KDS:

```json
{
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    },
    "verifier_config": {
        "snp_verifier": {
            "vcek_sources": [
                {
                    "type": "KDS",
                    "base_url": "https://kdsintf.amd.com"
                }
            ]
        }
    }
}
```

Running with unified storage backend (recommended):

```json
{
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

Configuration with AMD SEV-SNP verifier using offline store:

```json
{
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    },
    "verifier_config": {
        "snp_verifier": {
            "vcek_sources": [
                {
                    "type": "OfflineStore",
                    "path": "/var/lib/attestation-service/kds-store"
                }
            ]
        }
    }
}
```

Configuration with NVIDIA GPU verifier (local verification):

```json
{
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    },
    "verifier_config": {
        "nvidia_verifier": {
            "type": "Local"
        }
    }
}
```

Configuration with NVIDIA GPU verifier (remote verification via NRAS):

```json
{
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    },
    "verifier_config": {
        "nvidia_verifier": {
            "type": "Remote",
            "verifier_url": "https://nras.attestation.nvidia.com/v4/attest"
        }
    }
}
```

Configuration with Intel DCAP verifier (TDX/SGX):

```json
{
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    },
    "verifier_config": {
        "dcap_verifier": {
            "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",
            "use_secure_cert": true,
            "tcb_update_type": "early"
        }
    }
}
```
### Storage Backend Configuration

CoCo AS supports a unified storage backend configuration that allows you to declare a single storage configuration that will be used for all storage needs in the Attestation Service.

This simplifies deployment by eliminating the need to configure storage separately for each component.

For detailed information about the unified storage backend configuration format, including what a **namespace** is and how it works, see the [Key-Value Storage README](../../deps/key-value-storage/README.md#unified-storage-backend-configuration).

#### Storage Namespaces in CoCo AS

When using the unified storage backend configuration, CoCo AS creates the following storage namespaces:

| Namespace Name | Component | Description |
|----------------|-----------|-------------|
| `attestation-service-policy` | Attestation Token Broker | Stores EAR (Entity Attestation Report) policies |
| `reference-value` | Built-in RVPS | Stores reference values for software supply chain verification |

The unified storage backend configuration is optional. If not provided, CoCo AS will use the legacy per-component storage configurations.

For detailed configuration options and examples, see the [Key-Value Storage README](../../deps/key-value-storage/README.md#unified-storage-backend-configuration).
