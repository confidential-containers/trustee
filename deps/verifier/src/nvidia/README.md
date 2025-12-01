# Verifying NVIDIA devices with the Trustee Attestation Service

This verifier provides two ways to verify NVIDIA devices.
The `local` verifier will parse the hardware evidence (SPDM messages)
and extract the measurements.
The policy can then compare these measurements with reference values.

The `remote` verifier uses the NVIDIA NRAS service to validate the evidence.
To use this, the user should first enter into a licensing agreement with NVIDIA.
The agreement is described [here](https://docs.nvidia.com/attestation/cloud-services/latest/license.html)
and has provisions for research and development.
When the `remote` verifier is enabled, NRAS handles evaluating the evidence
against reference values.
Rather than providing the raw HW measurements as TCB Claims, the `remote` verifier
exports claims relating to each step of the verification process.
The policy checks these claims to make sure that attestation has been completed
successfully.

The remote verifier can be enabled with the following entry in the attestation service
config file.
```
[verifier_config.nvidia_verifier.verifier]
    type = "Remote"
```
