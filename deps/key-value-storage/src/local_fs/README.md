# Local File System Storage

A key-value storage implementation using the local file system.

## Overview

`LocalFs` is a key-value storage backend implementation based on the local file system, implementing the `KeyValueStorage` trait. Each key-value pair is stored in a separate file in the file system, making it suitable for single-machine environments or scenarios requiring simple persistent storage with file-level granularity.

## Features

- **Persistent Storage**: Data is stored in individual files on the local file system, preserving data across program restarts
- **Thread Safety**: Uses `RwLock` for concurrent read-write control
- **Auto Initialization**: Automatically creates the directory structure if the specified directory path doesn't exist
- **File-Level Granularity**: Each key-value pair is stored in a separate file, allowing for independent file operations

## Configuration

### Default Configuration

- **Default Directory Path**: `/opt/confidential-containers/storage/local_fs`

If `dir_path` is not specified, the above default path will be used.

## Implementation Details

### Storage Format

Each key-value pair is stored as a separate file:
- **File Name**: The key name is used as the file name
- **File Content**: The value is stored as raw bytes (`Vec<u8>`)

For example, a key-value pair `("key1", b"value1")` will be stored as:
- File path: `{dir_path}/key1`
- File content: Raw bytes of `value1`

> [!NOTE]
> Only `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./` are allowed
> in the key name and the key name cannot start with `.`.
>
> `/` in key names will be converted to `@` to have a flatten directory structure. For example:
> A key-value pair `("ke/y/1", b"value1")` will be stored as:
> - File path: `{dir_path}/ke@y@1`
> - File content: Raw bytes of `value1`

## Notes

1. **Performance**: File system operations may have overhead compared to in-memory storage, but provide persistence
2. **Concurrency**: Thread-safe through `RwLock`, but multiple write operations execute serially, which may become a performance bottleneck
3. **File System Limits**: Subject to file system limitations (e.g., maximum file name length, maximum number of files per directory)
4. **Data Consistency**: File system operations are atomic at the file level, providing reasonable consistency guarantees
5. **Key Restrictions**: Keys should be valid file names for the underlying file system

## Suitable Scenarios

- Single-machine environments
- Scenarios requiring file-level access to stored data
- Applications requiring simple persistent storage
- Development and testing environments
- Scenarios where data needs to be easily inspectable or manipulable via standard file system tools

## Unsuitable Scenarios

- High-frequency write scenarios (file system overhead)
- Distributed environments
- Production environments requiring high availability
- Applications requiring transaction support
- Scenarios with very large numbers of keys (may hit file system directory limits)
