# Local File System Storage

This is a simple storage, which will store the
Reference Values in a local file. Thus the data
of the RVPS is persistent, and also safe when it
comes to restart or crash.

The underlying storage engine is `sled`, which
has the most downloads on `crates.io` as key-value
storage. Although it has now stopped updating
for almost a year, it meets our needs to save/retrieve
data on local file system.

All the data will be stored in the directory `/opt/attestation-server/reference_values`.

More about `sled` please refer to
[git repo](https://github.com/spacejam/sled).