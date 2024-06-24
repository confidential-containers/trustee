# In-toto Extractor

This Extractor verifies all `.link` files using in-toto 
[verify-lib](https://github.com/in-toto/in-toto-golang/blob/master/in_toto/verifylib.go).

## Format of Provenance

The format of in-toto provenance in a `Message` is as the following
```json
{
    "version" : "VERSION OF IN-TOTO",
    "line_normalization" : true/false,
    "files" : {
        "FILE_PATH" : "BASE64 ENCODED CONTENT",
        ...
    }
}
```

Here,
* `files` includes all `.link`, `.pub` and `.layout` files, with relative
file path set as `"FILE_PATH"` (e.g., `keys/key1.pub` indicates `key1.pub` is in the 
directory `keys/`), and content encoded in base64 `"BASE64 ENCODED CONTENT"`.
* `line_normalization` indicates whether line separators like CRLF in Windows
should be all converted to LF, to avoid cross-platform compatibility when
calculating digest.
* `version` indicates the version of this in-toto provenance. By default, 
the `version` will be `0.9`.

## Process Logic

All the given metadata of in-toto will be verified using golang-in-toto's verifylib.
The verification process includes the following:
* Verify the signature of the layout, together with all the linkfiles
* Verify whether the materials and products follows what the layout defines.
* Check all other operations the layout defines (s.t. Inspection)
* Return a summary link, which contains information about the products of the whole
supply chain together with its digests.

We take the summary link and gather all the related information of the products to format
into a `ReferenceValue`.

## More about In-toto

In-toto is a framework to secure software supply chain, also a CNCF project. Related links
* Main page: https://in-toto.io/
* Slides about RVPS & verifible build using in-toto: https://docs.google.com/presentation/d/1mBthljo6-UZcZrEkRrOnOdp31cp1O-gT/edit?usp=sharing&ouid=107855505470969153275&rtpof=true&sd=true
* Slides about VBDA: https://docs.google.com/presentation/d/1sdicILTowOxH7jL_701fnU8kHgSePM1L/edit?usp=sharing&ouid=107855505470969153275&rtpof=true&sd=true