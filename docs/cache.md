# Caching and Offline Provisioning

Trustee caches material its verifiers fetch from vendor services (VCEKs, DCAP
collateral, Hygon HSK/CEK certificates, JWK sets) through
[pluggable-cache](https://github.com/larrydewey/pluggable-cache), a standalone
crate with a strict LRU core (`strict-lru`), memory, persistent and tiered
backends, and signed OCI preload bundles. Trustee provides the glue
(`deps/cache-storage`, which backs persistent caches with
`key-value-storage`), the KBS admin API and metrics, and the
`trustee cache` commands. See the crate's README for configuration reference
and the security model.

Cached values are never trusted: each consumer re-verifies a cached value
exactly as it would a freshly fetched one.

## What this adds over existing options

| Item | Network cache (this feature) | Pre-provision, before this feature | Pre-provision, with this feature |
|---|---|---|---|
| SNP VCEK | Cached after the first KDS fetch, verified against the AMD root | `OfflineStore` VCEK directory, see [amd-offline-certificate-cache.md](../attestation-service/docs/amd-offline-certificate-cache.md) | Same entries in a signed bundle or the admin API, alongside every other item |
| TDX / SGX / Azure TDX collateral | Cached PCS/PCCS responses, retried once with fresh collateral if cached collateral fails verification | `collateral_service` as a `file://` path | Signed bundle or admin API |
| Hygon CSV HSK/CEK | Cached by chip serial number, verified against the HRK | None | Signed bundle or admin API |
| NVIDIA NRAS JWKS | Cached, refreshed on an unknown key ID. Trust anchor | None | Signed bundle (the admin API refuses to write trust anchors) |
| KBS token and admin JWK sets | Fetched first, cached copy used only when the source is unreachable. Trust anchor | `file://` JWKS or a public key path | Not applicable |
| Multi-replica sharing | Persistent or tiered backend on a shared `key-value-storage` | None | None |
| Inspection, purge, metrics | KBS admin API and Prometheus metrics | None | None |

## Air-gapped workflow

On a connected machine, with the `trustee` CLI:

```bash
# Collect entries, e.g. the VCEKs of the hosts' SNP reports.
trustee cache fetch-vcek --report host1-report.bin --dir ./cache
trustee cache fetch-vcek --report host2-report.bin --dir ./cache

# Pack and sign them. `cosign generate-key-pair` keys work too.
trustee cache bundle keygen --output bundle.key
trustee cache bundle create --dir ./cache --layout ./bundle --tag v1
trustee cache bundle sign --layout ./bundle --tag v1 --key bundle.key \
    --identity registry.internal/trustee/cache
```

Carry `./bundle` (or a `trustee cache bundle pull` of it) into the
air-gapped environment, then either point an `OciLayout` source at it, or push
it to the internal registry and use an `OciRegistry` source:

```bash
trustee cache bundle push --layout ./bundle --tag v1 \
    --to registry.internal/trustee/cache:v1 \
    --username robot --password-file ./password
trustee cache bundle verify --from registry.internal/trustee/cache:v1 \
    --public-key bundle.pub
```

Alternatively, seed a running KBS through its admin API with
`kbs-client config cache upload --dir ./cache`.

## Consumers

| Namespace               | Component         | Content                       | Behavior |
|-------------------------|-------------------|-------------------------------|----------|
| `snp_vcek`              | SNP verifier      | VCEKs, keyed `<Milan\|Genoa\|Turin>/<hw_id>/<tcb>` | Cache first; verified against the AMD root before use and before caching. Not used when the chip ID is masked. |
| `intel_dcap_collateral` | TDX, SGX, Azure TDX verifiers | PCS/PCCS collateral | Cache first; verified by the quote verification library. A verification that fails with cached collateral is retried once with fresh collateral, which replaces the cached one. |
| `hygon_csv_hsk_cek`     | Hygon CSV verifier | HSK/CEK certificates, keyed by chip serial number | Cache first; verified against the HRK before use and before caching. |
| `nvidia_nras_jwks`      | NVIDIA remote verifier | NRAS token signing keys | Cache first; refreshed when a token is signed by an unknown key. Trust anchor. |
| `kbs_jwks`              | KBS token and admin verifiers | Remote JWK sets | Fetch first; the cached copy is only used when the source is unreachable. Trust anchor. |
