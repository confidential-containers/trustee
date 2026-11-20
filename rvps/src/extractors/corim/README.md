# CoRIM Extractor

This extractor parses CoRIM manifests and extracts reference values.

The CoRIM specification goes beyond simply specifying reference values, 
but our extractors are tightly tied to the internal RV representation
in the RVPS.

Thus, this extractor maps CoRIMs and the CoMIDs within to RV values
identified by URIs.

We use a flexible mechanism to map RVs in a CoRIM to RV URIs.
Specifically, any id-like fields found while parsing the manifest are
concatenated together with slashes to produce the reference values URI.

This extractor currently only supports a subset of CoRIM.
Only reference triples are supported and not all types of
identifiers are parsed.

> [!WARNING]
> The extractor does not verify CoRIM signatures. The authenticity of a
> CoRIM should be verified before it is provided to the RVPS.

The following identifiers will be added to the RV URI if they are present.
This list is in order, such that the first available identifier will be
the base of the URI. 

* Environment map vendor field
* Environment map model field
* MKey String, integer, or Uuid
* Mval name
* Mval serial number

If the mval is a list of digests, the string "digests" will be added to
the end of the URI, and the value will be a list of digests.

If the mval is raw bytes, the string "raw_bytes" will be added to the end
of the URI and the value will be the bytes converted to hex.

For example, an RV URI might look like:

* `ACME/RoadRunner/31fb5abf-023e-4992-aa4e-95f9c1503bfa/digests`
* `ACME/RoadRunner/31fb5abf-023e-4992-aa4e-95f9c1503bfa/raw_bytes`

## Intel Platform Ownership Endorsement (POE)

[draft-bzb-rats-intel-poe-endorsements](https://datatracker.ietf.org/doc/draft-bzb-rats-intel-poe-endorsements/)
defines a CoRIM profile, `tag:intel.com,2026:tee.poe#1.0`, that binds a
platform's Platform Instance ID (PIID) to the name of its owner. Intel's
`poe-gen-tool` produces such CoRIMs. They are handled by a dedicated
extractor, which produces one RV:

* name: `intel.com/tee.poe/<piid>`, after the profile's tag URI, with
  `<piid>` the PIID's raw bytes in lowercase hex, as in the TDX and SGX
  verifiers' `platform_instance_id` claim;
* value: `{"owner-name": "<owner>"}`, expiring at the POE's `not-after`.

An AS policy can look up the POE for the platform being appraised by the
PIID in its evidence, e.g.:

```rego
# TDX
poe := query_reference_value(sprintf("intel.com/tee.poe/%s", [input.tdx.platform_instance_id]))
# SGX
poe := query_reference_value(sprintf("intel.com/tee.poe/%s", [input.sgx.platform_instance_id]))
```

`query_reference_value` returns `null` if no POE is registered for the
platform, or if it has expired.

> [!NOTE]
> A POE is an endorsement rather than a reference value. The RV name and
> value format may change once Trustee supports endorsements natively.

The extractor follows the draft's rules for verifiers: unknown fields are
ignored and any `#1.<minor>` profile version is accepted, but a CoRIM that
violates the profile is rejected with an error.
