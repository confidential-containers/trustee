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
| `verifier_config`          | [VerifierConfig][3]          | TEE verifier-specific configuration.               | False      | -       |

[1]: #attestationtokenbroker
[2]: #rvps-configuration
[3]: #verifier-configuration

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

Configuration with TPM verifier:

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
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
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

Configuration with AMD SEV-SNP verifier using offline store:

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
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
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
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
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
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
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
