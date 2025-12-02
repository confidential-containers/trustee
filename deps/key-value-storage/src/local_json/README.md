# Local JSON Storage

A key-value storage implementation using local JSON file format.

## Overview

`LocalJson` is a key-value storage backend implementation based on local JSON files, implementing the `KeyValueStorage` trait. It stores all key-value pairs in a single JSON file, suitable for single-machine environments or scenarios requiring simple persistent storage.

## Features

- **Persistent Storage**: Data is stored in a local JSON file, preserving data across program restarts
- **Thread Safety**: Uses `RwLock` for concurrent read-write control
- **Auto Initialization**: Automatically creates directories and empty file if the specified file path doesn't exist

## Configuration

### Config Structure

```rust
pub struct Config {
    pub file_path: String,  // Path to the JSON file
}
```

### Default Configuration

- **Default File Path**: `/opt/confidential-containers/storage/key_value.json`

If `file_path` is not specified, the above default path will be used.

## Implementation Details

### File Format

Data is stored in JSON object (HashMap) format, for example:

```json
{
  "key1": [118, 97, 108, 117, 101, 49],
  "key2": [118, 97, 108, 117, 101, 50]
}
```

Values are stored as byte arrays (`Vec<u8>`), represented as number arrays in JSON.

## Notes

1. **Performance**: Each write operation reads and writes the entire file, making it unsuitable for high-frequency write scenarios
2. **Concurrency**: Although thread-safe, multiple write operations execute serially, which may become a performance bottleneck
3. **File Size**: All data is stored in a single file; excessively large files may impact performance
4. **Data Consistency**: In exceptional circumstances (such as program crashes), there may be a risk of data inconsistency

## Suitable Scenarios

- Single-machine environments
- Low-frequency write scenarios
- Applications requiring simple persistent storage
- Development and testing environments

## Unsuitable Scenarios

- High-frequency write scenarios
- Distributed environments
- Production environments requiring high availability
- Applications requiring transaction support
