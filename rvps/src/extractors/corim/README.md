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
