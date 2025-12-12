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

## Key Format

The supported key character set includes:
- Lowercase letters: `a-z`
- Uppercase letters: `A-Z`
- Digits: `0-9`
- Special characters: `-`, `_`, `.`, `/`

**Key Restrictions:**
- Keys cannot start with `.` (period)
- Keys cannot start with `/` (slash)
