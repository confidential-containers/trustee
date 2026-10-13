# Verifying NVIDIA devices with the Trustee Attestation Service

This verifier has four modes.
* **NvRemote** Uses the official NVIDIA Attestation SDK in conjunection with
the NVIDIA Remote Attestation Service. Depends on `nvat` feature.
* **NvLocal** Uses the NVIDIA Attestation SDK in conjunction with a remote
RIM and OCSP service. Depends on `nvat` feature.
* **Remote** Uses the NVIDIA Remote Attestation Service directly. This is similar
to `NvRemote`, but does not depend on `libnvat`.
* **Local** Extracts and verifies evidence locally with no dependencies. Only a
small set of devices are supported. Users must provide reference values and policy.
Revocation is not supported. 

Using a mode that depends on a remote NVIDIA service for attestation
assumes that the user has entered into a [licensing agreement](https://docs.nvidia.com/attestation/cloud-services/latest/license.html) with NVIDIA.
There are provisions for use in research and development.

The verifier type can be specified in the AS configuration file.

- JSON format (`as-config.json`):

    ```json
    {
        "verifier_config" : {
            "nvidia_verifier": {
                "type": "Remote"
            }
        }
    }
    ```
  
- TOML format:

    ```toml
    [verifier_config.nvidia_verifier.verifier]
        type = "Remote"
    ```

Alternatively, verifier configuration can be specified in the KBS config file `kbs-config.toml` file
(when using the built-in AS):

```toml
[attestation_service.verifier_config.nvidia_verifier]
    type = "Remote"
```


## Claims

`Remote`, `NvRemote` and `NvLocal` all emit similar claims and can be used
interchangeably with the default GPU policy.

These three modes all support PPCIE.

The `Local` verifier extracts claims directly from the SPDM sessions and exposes
these as TCB claims.

## Local verifier
The `Local` verifier will parse the hardware evidence (SPDM messages) and extract the measurements.
The policy can then compare these measurements with reference values. Only Hopper GPUs are supported.

## Remote verifier
The `Remote` verifier uses the NVIDIA NRAS service to validate the evidence.
Trustee posts the evidence to the NRAS `/v4/attest/{gpu,switch}` endpoint
(claims version 3.0) and validates the returned JWTs.

Rather than providing the raw HW measurements as TCB Claims, the `remote` verifier exports claims relating to each step of the verification process.

The policy checks these claims to make sure that attestation has been completed successfully.

The remote verifier is more forgiving than the NVAT verifiers.
For example, if the NRAS does not have a RIM corresponding to the device being attested,
the remote verifier will still issue TCB Claims.
The NVAT verifiers will not.
The remote verifier also provides 60 seconds of leeway when checking token
expiration. The NVAT verifiers do not.

## NVAT SDK verifiers (`NvLocal` / `NvRemote`)

These modes use `libnvat` to verify the evidence.

### NvRemote

`NvRemote` uses the SDK's NRAS verifiers. Its options are:

- `nras_url`: the NRAS *base* URL, not the `/v4/attest` path used by `Remote`.
  If unset or empty, the `NVAT_NRAS_BASE_URL` environment variable is used. If
  that is also unset, the default is `https://nras.attestation.nvidia.com`.
- `service_key`: the NVIDIA service key sent with requests to NRAS.

For example:

```json
{
    "verifier_config": {
        "nvidia_verifier": {
            "type": "NvRemote",
            "nras_url": "https://nras.attestation.nvidia.com"
        }
    }
}
```

### NvLocal

`NvLocal` verifies directly using RIM and OCSP services. Its options are:

- `rim_url`: the URL of the remote RIM service. If unset or empty, the
  `NVAT_RIM_SERVICE_BASE_URL` environment variable is used. If that is also
  unset, the default is `https://rim.attestation.nvidia.com`. Ignored when
  `rim_store_path` is set.
- `rim_store_path`: the path of a filesystem RIM store. If set, it is used
  instead of the remote RIM service.
- `ocsp_url`: the URL of the OCSP service. If unset or empty, the
  `NVAT_OCSP_BASE_URL` environment variable is used. If that is also unset, the
  default is `https://ocsp.ndis.nvidia.com`.
- `service_key`: the NVIDIA service key sent with requests to the RIM and OCSP
  services.
- `verify_rim_signature`: whether to verify the RIM signature. Defaults to `true`.
- `verify_rim_cert_chain`: whether to verify the RIM certificate chain. Defaults
  to `true`.

For example:

```json
{
    "verifier_config": {
        "nvidia_verifier": {
            "type": "NvLocal",
            "rim_url": "https://rim.attestation.nvidia.com",
            "ocsp_url": "https://ocsp.ndis.nvidia.com"
        }
    }
}
```
