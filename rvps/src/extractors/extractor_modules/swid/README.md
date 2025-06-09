# SWID RIM Extractor

This extractor will take a manifest with RIM bindings and SWID tags
and extract reference values from it.
This extractor does not handle all possible claims within such a manifest
and has only been tested with an nvidia RIM manifest for the vbios
of an H100 GPU.
It can be extended to more general RIM/SWID support in the future.

For now, this extractor does not verify the signature of the manifest.
The authenticity of the manifest should be verified before it is provided to the RVPS.

The expiration time will be 12 months and the hash algorithm `sha384` by default.
