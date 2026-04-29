# Provisioner Plugin

The provisioner plugin automates LUKS key generation and resource creation for
confidential VMs. It is designed to work with a KubeVirt hook sidecar that
calls the plugin before the VM boots to obtain the SMBIOS values needed to
bind the VM to its encryption key.

## Flow

1. The hook sidecar sends `POST /kbs/v0/provisioner/provision` with the VM
   identity.
2. The plugin generates a random UUID, a LUKS encryption key, and an
   `initdata.toml` pointing the guest to the KBS resource path where the key
   is stored.
3. The key is persisted in the KBS storage backend so the guest can retrieve
   it after attestation via the plugin.
4. The plugin returns a JSON response containing the SMBIOS values that the
   hook sidecar must inject into the VM domain.

On boot, the guest attests to the KBS and fetches the key through the
`/kbs/v0/provisioner/...` path. In the guest, `systemd-repart` uses the key to
encrypt the disk and `systemd-cryptsetup` uses it to decrypt the disk on
subsequent boots.

## Provision Response

The JSON response returned to the hook sidecar:

```json
{
  "uuid": "c007d2cc-5f14-41e5-a202-8d15f6f68607",
  "oemstring": "<base64-encoded initdata.toml>",
  "mrconfigid": "<base64-encoded SHA-384 hash of initdata.toml>",
  "resource_path": "default/c007d2cc-5f14-41e5-a202-8d15f6f68607/root"
}
```

The `oemstring` field is the base64 encoding of the `initdata.toml` generated
by the plugin. The TOML has the following structure:

```toml
algorithm = "sha384"
version = "0.1.0"

[data]
"trustee.kbs.url" = "<kbs_url from plugin config>"
"trustee.kbs.resource" = "kbs+provisioner:///default/<uuid>/root"
```

The hook sidecar injects this into the VM as a SMBIOS OEM string so the guest
knows the KBS URL and the resource path to fetch after attestation.

The `mrconfigid` field is the base64 encoding of the SHA-384 digest of that
same `initdata.toml`. The hook sidecar injects it into the TDX `mrConfigId`
register, binding the VM configuration to hardware attestation.

`uuid` and `resource_path` are included for debugging and deprovision
operations. The hook sidecar only needs `oemstring` and `mrconfigid`.

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

- **POST/DELETE** (hook sidecar): `validate_auth` returns `true`, routing
  through KBS admin authentication. The sidecar is infrastructure, not a TEE.
- **GET** (guest VM): `validate_auth` returns `false`, requiring a TEE
  attestation token verified by the Attestation Service and evaluated against
  the KBS resource policy. The response is JWE-encrypted with the TEE public
  key.
