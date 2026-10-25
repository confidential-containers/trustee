# Verifying NVIDIA devices with the Trustee Attestation Service

This verifier provides two ways to verify NVIDIA devices, selected by
`nvidia_verifier.type`: `Local` (default) or `Remote`.

Detailed claim fields for policy are listed in
[TCB Claims — NVIDIA](../../../../attestation-service/docs/tcb_claims.md#nvidia).

## Local (`type = "Local"`)

Parses GPU hardware evidence (SPDM) locally and exports measurements and
device config for the Attestation Service policy to check against reference
values.

- Supports Hopper GPUs only.
- Does not support nvSwitch.

## Remote (`type = "Remote"`)

Sends evidence to NVIDIA NRAS for verification.

A licensing agreement with NVIDIA is required; see
[NVIDIA Attestation Cloud Services license](https://docs.nvidia.com/attestation/cloud-services/latest/license.html).

After NRAS returns a result, the verifier enforces fixed checks (report
signature, certificate chains, RIM / measurement comparison, nonce, secure
boot, debug status, and related outcomes). Only variable fields useful for
policy (versions, identity, optional PPCIE topology, nonce) are exported;
pass/fail verification flags are not.

Supports GPU and nvSwitch. Uses NRAS claims version 3.0.

Optional remote settings:

| Option | Effect | Default |
|--------|--------|---------|
| `verifier_url` | NRAS endpoint to call | `https://nras.attestation.nvidia.com/v4/attest` |
| `debug` | When `true`, relaxes RIM / measurement / secure-boot / debug-status checks | `false` |

### Configuration examples

- JSON (`as-config.json`):

    ```json
    {
        "verifier_config": {
            "nvidia_verifier": {
                "type": "Remote"
            }
        }
    }
    ```

- TOML:

    ```toml
    [verifier_config.nvidia_verifier]
    type = "Remote"
    ```

Or in KBS `kbs-config.toml`:

```toml
[attestation_service.verifier_config.nvidia_verifier]
type = "Remote"
```

For more details, see the [NVIDIA GPU Verifier configuration section](../../../../attestation-service/docs/config.md#nvidia-gpu-verifier).
