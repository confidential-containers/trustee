# Verifying NVIDIA devices with the Trustee Attestation Service

This verifier provides two ways to verify NVIDIA devices.

## Local verifier
The `local` verifier supports Hopper and Blackwell GPUs. It verifies the report
signature, nonce, FWID, and certificate chain before returning the SPDM
measurements as claims.

Hopper certificates use NVIDIA's legacy TCB extension, where the FWID is the
last SHA-384 digest in the extension value. Blackwell certificates use the TCG
DICE `DiceTcbInfoAlias` extension, so the verifier parses the extension and
uses `fwids[0]`.

The default EAR policy compares local claims with these RVPS reference-value
IDs:

- `allowed_driver_versions`: non-empty array of exact driver-version strings
- `allowed_vbios_versions`: non-empty array of exact VBIOS-version strings
- `allowed_gpu_fwids`: non-empty array of SHA-384 FWIDs as lowercase hex
- `allowed_gpu_measurements`: non-empty object whose keys are decimal SPDM
  measurement indices and whose values are either one SHA-384 digest or a
  non-empty array of accepted digests, all as lowercase hex

For example, the decoded payload accepted by RVPS's sample extractor has this
shape:

```json
{
  "allowed_driver_versions": ["<driver-version>"],
  "allowed_vbios_versions": ["<vbios-version>"],
  "allowed_gpu_fwids": ["<96-character-sha384-hex>"],
  "allowed_gpu_measurements": {
    "<measurement-index>": "<96-character-sha384-hex>",
    "<another-index>": [
      "<96-character-sha384-hex>",
      "<another-accepted-sha384-hex>"
    ]
  }
}
```

The policy requires every listed measurement to match. It does not require a
reference for every measurement in the report.

Trustee does not fetch NVIDIA RIMs or populate these values. Operators must
derive them from an authenticated source, such as signed NVIDIA driver and
VBIOS RIMs, or from a separate hardware and software qualification process.
Values copied from the evidence being evaluated are not a trust anchor.

Reference values can be registered through the KBS `POST /reference-value`
admin API or with `rvps-tool`. The RVPS [client-tool
guide](../../../../rvps/README.md#client-tool) shows the message envelope and
registration command. Its `sample` extractor does not authenticate the
payload, so it is only suitable for tests and demos. Production deployments
need an authenticated provenance and an extractor that verifies it.

## Remote verifier
The `remote` verifier uses the NVIDIA NRAS service to validate the evidence.

To use this, the user should first enter into a licensing agreement with NVIDIA.
The agreement is described [here](https://docs.nvidia.com/attestation/cloud-services/latest/license.html)
and has provisions for research and development.

When the `remote` verifier is enabled, NRAS handles evaluating the evidence against reference values.

Rather than providing the raw HW measurements as TCB Claims, the `remote` verifier exports claims relating to each step of the verification process.

The policy checks these claims to make sure that attestation has been completed successfully.

The remote verifier can be enabled with the following entry in the attestation service config file:

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

Alternatively, verifier configuration can be specified in the KBS config file `kbs-config.toml` file:

```toml
[attestation_service.verifier_config.nvidia_verifier]
    type = "Remote"
```

For more details, see the [NVIDIA GPU Verifier configuration section](../../../../attestation-service/docs/config.md#nvidia-gpu-verifier).
