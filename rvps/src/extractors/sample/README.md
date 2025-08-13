# Sample Extractor

This Extractor will directly extract the reference value from the input **WITHOUT** verifying any signatures.

This format is only for test and demo. It should be replaced with a signed provenance which contains the trust relationship for a software supply chain.

## Format of Provenance

The format of sample provenance in a `Message` is as the following
```json
{
    "<name-1>": [
        "<reference-value-1>",
        "<reference-value-2>",
        ...
    ],
    "<name-2>": [
        "<reference-value-1>",
        "<reference-value-2>",
    ],
    ...
}
```

The expire time will be 12 months and the hash algorithm `sha384` by default.