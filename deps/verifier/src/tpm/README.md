# TPM Verifier

The TPM verifier validates attestation evidence from TPM (Trusted Platform Module) based systems.
It verifies TPM quotes signed by Attestation Key(AK) and validates PCR (Platform Configuration Register) values.

The TPM verifier requires trusted AK public keys to be pre-configured.


## Setup

### 1. Policy Configuration

In order to check that the received AK is trusted, you need to configure the policy to include the following condition:

```rego
input.tpm.ak_public in query_reference_value(<reference_name_for_trusted_ak>)
```
In the default policy, the reference name is `trusted_ak`, but you can choose any name as long as it matches the one used in the policy.

### 2. Add Trusted AK Public Keys

Export the AK public key from your TPM device:

The public key file should be in PEM format (base64-encoded DER):
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmS6twmGpeO2i8JpQ9ZV
...
-----END PUBLIC KEY-----
```
Copy the key and set the reference value as follows:

```bash
kbs-client config --auth-private-key <private_key_file> set-sample-reference-value <reference_name_for_trusted_ak> <trusted_ak>
```

## Evidence Format

The TPM verifier expects evidence in the following JSON format:

```json
{
  "ak_public": "base64-encoded DER public key",
  "tpm_quote": {
    "message": "base64-encoded attestation message",
    "pcrs": [
      "hex-encoded PCR0",
      "hex-encoded PCR1",
      ...
      "hex-encoded PCR23"
    ],
    "signature": "base64-encoded TPM signature"
  }
}
```
