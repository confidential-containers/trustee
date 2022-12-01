# In-toto shim

This is a wrapper of in-toto-golang for rust

## Usage

The function `verify()` is the rust wrapper of golang func `verifyGo` in [intoto.go](../../../../cgo/intoto.go).

The interface looks like the following

```rust
pub fn verify(
    layout_path: String,
    pub_key_paths: Vec<String>,
    intermediate_paths: Vec<String>,
    link_dir: String,
    line_normalization: bool,
) -> Result<LinkMetadata>
```

Here
- `layout_path`: Path to the layout file
- `pub_key_paths`: Paths of public keys of the software supply chain owners to verify the layout.
- `intermediate_paths`: Paths to PEM formatted certificates, used as intermediaries to verify the chain of trust to the layout's trusted root.
- `link_dir`: Directory where the link metadata files are stored.
- `line_normalization`: a flag indicating whether Windows-style line separators (CRLF) are normalized to Unix-style line separators (LF) for cross-platform consistency.