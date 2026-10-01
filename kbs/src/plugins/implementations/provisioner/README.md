# Provisioner Plugin

The provisioner plugin automates LUKS key generation and resource creation for
confidential VMs. It is designed to work with a provisioner operator (or hook
sidecar) that calls the plugin before the VM boots to obtain the values needed
to bind the VM to its encryption key.

## Flow

1. The operator sends `POST /kbs/v0/provisioner/provision` with the VM identity.
2. The plugin derives a deterministic UUID from the VM identity and generates a
   random LUKS encryption key.
3. The key is persisted in the KBS storage backend so the guest can retrieve
   it after attestation via the plugin.
4. The plugin returns a JSON response containing the values that the operator
   must inject into the VM.

On boot, the guest attests to the KBS and fetches the key through the
`/kbs/v0/provisioner/...` path. In the guest, `systemd-repart` uses the key to
encrypt the disk and `systemd-cryptsetup` uses it to decrypt the disk on
subsequent boots.

## Provision Response

The JSON response returned to the operator:

```json
{
  "uuid": "c007d2cc-5f14-41e5-a202-8d15f6f68607",
  "resource_path": "default/c007d2cc-5f14-41e5-a202-8d15f6f68607/root"
}
```

### Fields
- **`uuid`**: Deterministic identifier for the VM, used by the operator to
  construct initdata and for deprovision operations.
- **`resource_path`**: KBS resource path where the LUKS key is stored. The
  operator embeds this in the guest's initdata so the guest knows where to
  fetch its key after attestation.

## Resource Format

The resource stored in the KBS storage backend follows the
[confdata](https://gitlab.com/berrange/cvminjector#confidential-data-format)
TOML format that `trustee-attester` expects:

```toml
version = "0.1.0"

[data]
"io.cryptsetup.key.text.root" = "<random LUKS key>"
```

The guest retrieves this resource after attestation at
`/kbs/v0/provisioner/default/{uuid}/root` and parses the
`io.cryptsetup.key.text.root` field to obtain the LUKS passphrase.

## Deprovision

To remove a provisioned resource:

```
DELETE /kbs/v0/provisioner/provision/{uuid}
```

## Authentication

The plugin uses two authentication paths depending on the caller:

- **POST/DELETE** (operator): `validate_auth` returns `true`, routing
  through KBS admin authentication. The operator is infrastructure, not a TEE.
- **GET** (guest VM): `validate_auth` returns `false`, requiring a TEE
  attestation token verified by the Attestation Service and evaluated against
  the KBS resource policy. The response is JWE-encrypted with the TEE public
  key.
