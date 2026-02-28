# Reference Value URI

## Background

[Attestation Service](../../attestation-service/) policy currently provides `query_reference_value` extension, which allows policy enforcement to retrieve reference values (RVs) from RVPS during evaluation. As RV usage grows (e.g., publishing RVs for CoCo/Kata releases in build pipelines), we need a recommended and interoperable way to organize and index RVs so that they are easy to manage across different projects/domains and versions.

At the same time, today’s RVPS storage interface is essentially a key-value model where the key can be any arbitrary string. This means the system is already functional without a standardized key format. Therefore, this RFC defines a convention/spec **recommendation** for RV identifiers, primarily to improve consistency and operability, while keeping backward compatibility with arbitrary keys.

> [!NOTE]  
> During [discussion](https://github.com/confidential-containers/trustee/issues/1159), a future direction is identified: the "pull model" (RVPS fetching RVs from external sources), which is the main driver for URIs that can locate external resources. However, because “external location URI design” is tightly coupled with pull-model design, we explicitly scope this RFC to a minimal format first, and leave the authority/external-pointer story for a follow-up proposal.

## Specifications

### Scope and Non-Goals

#### In scope

1. Define a recommended RV identifier format to be consumed by `query_reference_value`.
2. Provide namespace/path + optional tag semantics suitable for organizing RVs and versions.
3. Define expected behavior around missing tags and latest-like usage (as recommendations).

#### Out of scope (future work)
1. Encoding RVPS address / remote location / plugin mechanism into the URI (pull model).
2. Standard push/update APIs

### Semantics: "Instance-local" Identifier, "Globally meaningful" Convention

An RV URI is resolved within a specific RVPS instance. Concretely:

`query_reference_value(rv_uri)` is evaluated against the RVPS configured/used by the AS deployment.
The same `rvps:///...` identifier may resolve to different contents on different RVPS instances, depending on what has been set there.

Although resolution is instance-local today, it's recommended that reference value publishers adopt stable and unique URI naming conventions so that:

1. Different components are clearly separated by namespace paths.
2. Different versions are clearly separated by tags.
3. The same logical RV can be referred to consistently across tooling, documentation, and policies—even if multiple RVPS instances mirror the same naming scheme.

### RV Identifier Format (Recommended)

#### Canonical form
```
rvps:/// <namespace-1> / <namespace-2> / ... / <namespace-n> [ : <tag> ]
```

Here,
1. The prefix MUST be `rvps:///` (scheme + empty authority).
2. There **MUST** be at least one namespace segment.
3. `:tag` is **OPTIONAL**.

Examples:

- `rvps:///confidential-containers/kata/measurements:v0.18.0`
- `rvps:///org/project/component`
- `rvps:///coco/kata/tdx/rtmr0:latest`

#### Namespaces (`/<namespace-x>/...`)

1. Namespace segments are hierarchical and purely organizational.
2. The spec does not mandate segment meanings; publishers/operators define their own conventions.
3. Implementations **SHOULD** treat the entire /<...> part (plus tag if present) as the lookup key.

> [!NOTE]  
> **Difference from KBS resource URI:** The KBS resource URI uses a fixed three-part structure (e.g. `kbs:///repo/type/tag` for repository, type, and tag). The RV URI is different: it has a variable number of namespace segments (`/<namespace-1>/<namespace-2>/.../<namespace-n>`) and an optional `:tag`. There is no fixed "three parts" rule for RV URIs; the number of path segments is chosen by the publisher.

#### Character guidance (recommended, not enforced):

1. Use URL-safe characters; avoid spaces.
2. Prefer lowercase, `-`, `_`, `.`

#### Tag (`:tag`)

1. Tag represents a version/variant selector.
2. Tags are not guaranteed immutable (e.g., latest can move).
3. Operators **SHOULD** prefer immutable release tags (e.g., `v0.18.0`) for stable policies.
4. **No default behavior:** The RV identifier is an opaque string to the storage layer. Omitting the tag (e.g. `rvps:///coco/kata/measurements`) and using an explicit `:latest` tag (e.g. `rvps:///coco/kata/measurements:latest`) are **not** equivalent unless an implementation explicitly defines such behavior. Policies and tooling should use the full string they intend to resolve; do not assume that "no tag" implies "latest" or vice versa.

### Resolution Rules in RVPS (Recommended Behavior)

Because the underlying storage is key-value with arbitrary-string keys, RVPS **MAY** implement the following by simply using the full RV identifier string as the key. However, if RVPS chooses to parse the canonical form, the following behaviors are recommended for interoperability:

#### With tag present

Resolve by exact match of (ns-path, tag).

#### latest tag
If latest is supported:

RVPS **MAY** resolve it to a movable alias.
RVPS **SHOULD** log/audit the resolved concrete RV instance.

### Backward Compatibility / Non-enforcement

1. This RFC does not require all reference value keys to follow this format.
2. `query_reference_value` and RVPS MUST continue to work with arbitrary string keys (legacy behavior).
3. The `rvps:///...` format is a recommended convention to improve consistency and enable future extensions.

### CoCo Naming Convention

For the Confidential Containers (CoCo) ecosystem, we define a recommended common prefix to standardize RV naming across components and releases:

1. Common prefix: `rvps:///github.com/confidential-containers/`

2. Component and artifact naming:
Publishers **SHOULD** place component-specific paths under this prefix, for example (illustrative, not mandatory):

- `rvps:///github.com/confidential-containers/tdx/mr_td:<release-tag>`
- `rvps:///github.com/confidential-containers/tdx/eventlog/kernel:<release-tag>`
- `rvps:///github.com/confidential-containers/snp/measurement:<release-tag>`

3. Versioning: CoCo publishers **SHOULD** use `:tag` to distinguish release versions (e.g., `:v0.18.0`).
Policies that require reproducibility **SHOULD** avoid `:latest`.

This convention aims to ensure that different components and different releases are naturally separated by path and tag, and makes it easier to build shared tooling (publishers, CI pipelines, mirroring RVPS instances) around a consistent identifier scheme.

### Policy Example

Attestation policies use the `query_reference_value(rv_uri)` extension to fetch reference values from RVPS. The argument is the RV identifier string (e.g. in the recommended `rvps:///...` form). The following is a minimal TDX-oriented example in Rego, illustrating how RVs are queried by URI; in practice you would use the same URIs that publishers store under (e.g. with CoCo naming and version tags).

```rego
package policy

import rego.v1

# ...

# Example: TDX executables check using RV URIs (recommended format with tag)
executables := 3 if {
    input.tdx

    # RTMR measurements from RVPS using versioned URIs
    input.tdx.quote.body.rtmr_1 == query_reference_value("rvps:///github.com/confidential-containers/tdx/rtmr_1:v0.18.0")
    input.tdx.quote.body.rtmr_2 == query_reference_value("rvps:///github.com/confidential-containers/tdx/rtmr_2:v0.18.0")
}

# Example: TDX hardware check (mr_seam, tcb_svn, mr_td)
hardware := 2 if {
    input.tdx

    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.body.mr_seam == query_reference_value("rvps:///github.com/confidential-containers/tdx/mr_seam:v0.18.0")
    input.tdx.quote.body.tcb_svn == query_reference_value("rvps:///github.com/confidential-containers/tdx/tcb_svn:v0.18.0")
    input.tdx.quote.body.mr_td == query_reference_value("rvps:///github.com/confidential-containers/tdx/mr_td:v0.18.0")
}
```

> [!WARN]
> This policy is only used for example. The reference value URIs mentioned does not exist yet.
> Policies should use the exact RV URI strings that correspond to what is published to RVPS (including namespace path and tag). Using immutable tags (e.g. `v0.18.0`) in policy ensures reproducible attestation decisions.

### Future Extension Point (Pull Model)

The part between `://` and the first `/` (i.e., URI authority / location / method) is intentionally left unused in this RFC.
A follow-up proposal **MAY** define how to reference external RV sources as part of a pull model, potentially introducing:
1. authority-based RVPS selection, and/or
2. source-locator encoding, and/or
3. structured metadata mapping from RV IDs to pull sources.
Any future design MUST remain compatible with identifiers of the form `rvps:///path[:tag]`.

