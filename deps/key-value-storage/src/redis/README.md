# Redis Protocol Storage

A key-value storage implementation that speaks the **Redis protocol** (RESP). It is **not tied to Redis specifically** — any backend that implements the Redis wire protocol can be used, for example:

- [Redis](https://redis.io/)
- [Valkey](https://valkey.io/)
- [KeyDB](https://docs.keydb.dev/)
- Other Redis-protocol–compatible services

Throughout this document, "Redis-protocol server" refers to any such compatible backend unless noted otherwise.

## Overview

`RedisClient` is a key-value storage backend that connects via the Redis protocol and implements the `KeyValueStorage` trait.
It stores each key-value pair as a string key on the remote server. Values are stored as raw bytes.

## Features

- **Persistent Storage**: Data can be persisted by the server based on its configuration (AOF/RDB or equivalent)
- **Namespace Isolation**: Different namespaces are isolated by key prefix (`{namespace}:{key}`)
- **Concurrent Access**: Supports concurrent reads and writes through the Redis-protocol server

## Configuration

### Default Configuration

- **Default URL**: `redis://127.0.0.1:6379`

If `url` is not specified, the default URL above will be used. The URL scheme follows the usual Redis client convention (`redis://` or `rediss://` for TLS).

## Implementation Details

### Storage Format

Each key-value pair is stored as:

- **Key**: `{namespace}:{key}`
- **Value**: Raw bytes (`Vec<u8>`)

For example, with namespace `kbs`:

- `("policy/default", b"allow")` is stored as key `kbs:policy/default`

### List Operation

`list()` queries keys with pattern `{namespace}:*`, then strips the namespace prefix before returning.

## Testing

End-to-end coverage is provided by an ignored async test (`redis::tests::test_redis_client`). Start a Redis-protocol server locally first; the default config URL `redis://127.0.0.1:6379` matches a container published on host port `6379`.

### Start a server with Docker (example: Redis)

```bash
docker run -d --name redis-kvs-test -p 6379:6379 redis:8-alpine
```

Any other Redis-protocol image or deployment on the same URL works the same way.

Stop and remove the container when finished:

```bash
docker stop redis-kvs-test && docker rm redis-kvs-test
```

### Run the ignored test

Enable the `redis` feature (it is optional and not part of the crate default features):

```bash
cargo test -p key-value-storage --no-default-features --features redis --lib -- redis::tests::test_redis_client --exact --ignored --show-output
```

## Notes

1. **Key Restrictions**: Keys must only include `a-z`, `A-Z`, `0-9`, `-`, `_`, `.`, `/`
2. **Operational Dependency**: Requires a reachable Redis-protocol–compatible server
3. **Large Keyspace**: `list()` uses pattern-based key lookup and may be expensive with a very large keyspace

## Suitable Scenarios

- Shared storage across multiple service instances
- Low-latency distributed key-value access
- Production environments already operating a Redis-protocol backend (Redis, Valkey, managed cloud offerings, etc.)
