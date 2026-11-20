# KBS client image

Build from the repository root. The `attesters` build argument is a
comma-separated list of attesters and defaults to `sample-attester`:

```sh
docker build -f kbs/docker/kbs-client-image/Dockerfile \
  --build-arg attesters=tdx-attester,az-tdx-vtpm-attester \
  -t kbs-client .
docker run --rm kbs-client kbs-client --help
```

Omitting `--build-arg attesters=...` builds the sample-only variant, intended for
testing rather than production attestation.

`RUST_VERSION` defaults to `1.95.0`, matching the repository toolchain pin, and
can be overridden with `--build-arg RUST_VERSION=...`.

## Published images

CI publishes one `ghcr.io/confidential-containers/staged-images/kbs-client-image`
image per architecture:

| Architecture | Enabled attesters |
| --- | --- |
| amd64 | `all-attesters` |
| arm64 | All individual client attester features except `nvidia-attester` |
| s390x | All individual client attester features except `nvidia-attester`, `tpm-attester`, `az-snp-vtpm-attester`, and `az-tdx-vtpm-attester` |

## Attester specific dependencies

For builds including `se-attester` and `all-attesters` - `libcurl` package will be installed in the image.

For builds including `tpm-attester`, `az-*-attester` and `all-attesters` - TPM runtime libraries will be installed in the image.

For builds including `nvidia-attester` and `all-attesters` - `libnvat` package will be installed in the image.
