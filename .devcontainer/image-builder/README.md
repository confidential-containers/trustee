# Updating Hadolint

To update please download the checksum for the desired version as below example. 

```console
hadolint_version=v2.14.0
curl -L https://github.com/hadolint/hadolint/releases/download/${hadolint_version}/hadolint-linux-x86_64.sha256 -o hadolint-linux-x86_64_${hadolint_version}.sha256
```

Then update the postCreateCommand.sh accordingly.