# TPM Verifier Configuration

## Configuration File

The TPM verifier reads its configuration from a JSON file. The path can be specified using the `TPM_CONFIG_FILE` environment variable, defaulting to `/etc/tpm_verifier.json`.

### Configuration Schema

```json
{
  "tpm_verifier": {
    "trusted_ak_keys_dir": "/path/to/trusted/ak/keys",
    "max_trusted_ak_keys": 100
  }
}
```

### Configuration Fields

- `trusted_ak_keys_dir` (optional): Directory containing trusted AK public keys. The public keys must be PEM formated.
- `max_trusted_ak_keys` (optional): Maximum number of trusted AK keys to load (default: 100, defined by `MAX_TRUSTED_AK_KEYS` constant)

### Example

See `sample_config.json` for a complete example configuration.

### Notes

- If the configuration file is missing or invalid, the verifier will use default values
- The `max_trusted_ak_keys` value corresponds to the `MAX_TRUSTED_AK_KEYS` constant in the code
