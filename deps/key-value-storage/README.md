# Key-Value Storage

A key-value storage interface and multiple backend implementations for Rust applications.

## Overview

This crate provides a unified `KeyValueStorage` trait and multiple backend implementations, allowing applications to choose the most suitable storage backend based on their requirements. It supports both in-memory and persistent storage options, suitable for various deployment scenarios.

## Features

- **Unified Interface**: A common `KeyValueStorage` trait that all backends implement
- **Multiple Backends**: Support for memory, local file system, local JSON file, and PostgreSQL storage
- **Thread Safety**: All implementations are thread-safe and support concurrent access
- **Async Support**: Built on async/await for efficient I/O operations
- **Flexible Configuration**: Easy configuration through config structures

## Available Backends

### Memory (`Memory`)

In-memory key-value storage using a `HashMap`. Data is not persisted and will be lost when the program terminates.

- **Use Cases**: Testing, caching, temporary storage
- **Features**: Fast access, no I/O overhead

### Local File System (`LocalFs`)

Each key-value pair is stored as a separate file in the local file system.

- **Use Cases**: Single-machine environments, file-level access requirements
- **Features**: File-level granularity, automatic directory creation

See [LocalFs README](src/local_fs/README.md) for more details.

### Local JSON (`LocalJson`)

All key-value pairs are stored in a single JSON file.

- **Use Cases**: Single-machine environments, simple persistent storage
- **Features**: Human-readable format, easy inspection

See [LocalJson README](src/local_json/README.md) for more details.

### PostgreSQL (`Postgres`)

Stores key-value pairs in a PostgreSQL database table.

- **Use Cases**: Production environments, distributed systems, high availability requirements
- **Features**: ACID transactions, concurrent access, scalability

See [Postgres README](src/postgres/README.md) for more details.

## Unified Storage Backend Configuration

The `StorageBackendConfig` provides a unified way to configure storage backends that can be shared across multiple components in an application. This is particularly useful for applications like KBS (Key Broker Service) that need to manage multiple storage namespaces for different purposes.

### What is an Namespace?

An **namespace** is a logical separation of data within the same storage backend. When using a unified storage backend configuration, different components of an application can share the same storage backend type and configuration, but their data is stored separately using different namespaces.

For example:
- With `LocalFs` backend: Different namespaces are stored in different subdirectories
- With `LocalJson` backend: Different namespaces use different JSON file names
- With `Postgres` backend: Different namespaces use different table names

This allows you to:
- Use a single storage configuration for all components
- Keep data logically separated by component
- Simplify deployment and maintenance

### Configuration Structure

The unified storage backend configuration uses the following structure:

```toml
[storage_backend]
storage_type = "LocalFs"  # or "Memory", "LocalJson", "Postgres"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/storage/local_fs"

[storage_backend.backends.local_json]
file_dir_path = "/opt/confidential-containers/storage/local_json"

[storage_backend.backends.postgres]
host = "localhost"
port = 5432
db = "postgres"
username = "postgres"
password = "password"
```

Or in JSON format:

```json
{
    "storage_backend": {
        "storage_type": "LocalFs",
        "backends": {
            "local_fs": {
                "dir_path": "/opt/confidential-containers/storage/local_fs"
            }
        }
    }
}
```

### Configuration Properties

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `storage_type` | String | Storage backend type. Possible values: `Memory`/`memory`, `LocalFs`/`local_fs`, `LocalJson`/`local_json`, `Postgres`/`postgres` | No | `Memory` |
| `backends` | Object | Backend-specific configuration object | No | - |

The `backends` object can contain the following sub-sections:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `local_fs` | Object | LocalFs backend configuration (required when `storage_type = "LocalFs"`) | Conditional | - |
| `local_json` | Object | LocalJson backend configuration (required when `storage_type = "LocalJson"`) | Conditional | - |
| `postgres` | Object | PostgreSQL backend configuration (required when `storage_type = "Postgres"`) | Conditional | - |

### LocalFs Backend Configuration

When `storage_type = "LocalFs"`, the following properties can be set under `backends.local_fs`:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `dir_path` | String | Base directory path for all storage namespaces. Different namespaces will be stored in subdirectories under this path. | No | `/opt/confidential-containers/storage/local_fs` |

**Example:**
- Namespace `"kbs"` → stored in `<dir_path>/kbs/`
- Namespace `"resource"` → stored in `<dir_path>/resource/`

### LocalJson Backend Configuration

When `storage_type = "LocalJson"`, the following properties can be set under `backends.local_json`:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `file_dir_path` | String | Base directory path for all JSON files. Different namespaces will use different file names under this directory. | No | `/opt/confidential-containers/storage/local_json` |

**Example:**
- Namespace `"kbs"` → stored in `<file_dir_path>/kbs.json`
- Namespace `"resource"` → stored in `<file_dir_path>/resource.json`

### PostgreSQL Backend Configuration

When `storage_type = "Postgres"`, the following properties can be set under `backends.postgres`:

| Property | Type | Description | Required | Default |
|----------|------|-------------|----------|---------|
| `db` | String | The name of the PostgreSQL database | No | `postgres` |
| `username` | String | The username of the PostgreSQL database | No | `postgres` |
| `password` | String | The password of the PostgreSQL database | No | None |
| `port` | Integer | The port of the PostgreSQL database | No | `5432` |
| `host` | String | The host of the PostgreSQL database | No | `localhost` |

**Example:**
- Namespace `"kbs"` → stored in table `kbs`
- Namespace `"resource"` → stored in table `resource`

> **NOTE:** If the `POSTGRES_URL` environment variable is set with a PostgreSQL connection URI, it will be used instead of the configuration parameters above.

### Memory Backend

When `storage_type = "Memory"`, no additional configuration is needed. Each namespace will have its own in-memory storage that is not persisted.

## Key Format

The supported key character set includes:
- Lowercase letters: `a-z`
- Uppercase letters: `A-Z`
- Digits: `0-9`
- Special characters: `-`, `_`, `.`, `/`

**Key Restrictions:**
- Keys cannot start with `.` (period)
- Keys cannot start with `/` (slash)
