# TPM Verifier

The TPM verifier validates attestation evidence from TPM (Trusted Platform Module) based systems.
It verifies TPM quotes signed by Attestation Key(AK) and validates PCR (Platform Configuration Register) values.

The TPM verifier requires trusted AK public keys to be pre-configured.

## Configuration

The TPM verifier configuration is specified in the Attestation Service configuration file as part of the `verifier_config` object.

### Configuration Schema

For JSON configuration:
```json
{
  "work_dir": "/var/lib/attestation-service/",
  "rvps_config": {
    "type": "BuiltIn",
    "storage": {
      "type": "LocalFs"
    }
  },
  "attestation_token_broker": {
    "type": "Ear",
    "duration_min": 5
  },
  "verifier_config": {
    "tpm_verifier": {
      "trusted_ak_keys_dir": "/etc/tpm/trusted_ak_keys",
      "max_trusted_ak_keys": 100
    }
  }
}
```

For TOML configuration:
```toml
[attestation_service.verifier_config.tpm_verifier]
trusted_ak_keys_dir = "/etc/tpm/trusted_ak_keys"
max_trusted_ak_keys = 100
```

### Configuration Fields

- `trusted_ak_keys_dir` (optional): Directory containing trusted AK (Attestation Key) public keys in PEM format with `.pub` extension
  - **Default**: `/etc/tpm/trusted_ak_keys`
  - The verifier will load all `.pub` files from this directory as trusted AK public keys

- `max_trusted_ak_keys` (optional): Maximum number of trusted AK keys to load from the directory
  - **Default**: `100`
  - This limit prevents resource exhaustion from directories with many files

## Setup

### 1. Create the Trusted AK Keys Directory

```bash
sudo mkdir -p /etc/tpm/trusted_ak_keys
sudo chmod 755 /etc/tpm/trusted_ak_keys
```

### 2. Add Trusted AK Public Keys

Export the AK public key from your TPM device and save it in PEM format with a `.pub` extension:

```bash
# Example: Save the AK public key
sudo cp ak_public_key.pem /etc/tpm/trusted_ak_keys/device1.pub
sudo chmod 644 /etc/tpm/trusted_ak_keys/device1.pub
```

The public key file should be in PEM format (base64-encoded DER):
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtmS6twmGpeO2i8JpQ9ZV
...
-----END PUBLIC KEY-----
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
