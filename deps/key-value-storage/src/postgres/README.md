# PostgreSQL backend for key-value storage

This module provides a PostgreSQL-backed implementation of `KeyValueStorage` for the key-value storage system. Key-value pairs are stored in a single table with the value content stored as binary data (BYTEA) to ensure safe storage of arbitrary binary content.

## Features

- Stores key-value pairs in a configurable table (`key` primary key, `value` as binary)
- Optional per-entry expiry through an `expires_at` column
- Safe parameter binding via `sqlx`

## Expiry (TTL)

A table supports TTL when it has an `expires_at TIMESTAMPTZ` column; the client
checks for it at startup, and `supports_ttl()` reports the result. Expiry times
are computed with the database's `now()`, so all clients agree on them. Reads
ignore expired rows, and writes delete them at most once a minute.

Tables without the column work as before and ignore TTLs. To enable TTL on an
existing table, add the column (and an index for the cleanup) and restart.
Existing rows get no expiry, and once the table supports TTL, KBS no longer
sweeps it, so give leftover sessions one (any value above the session timeout
works):

```sql
ALTER TABLE kbs_protocol_session ADD COLUMN expires_at TIMESTAMPTZ;
CREATE INDEX kbs_protocol_session_expires_at
  ON kbs_protocol_session (expires_at) WHERE expires_at IS NOT NULL;
UPDATE kbs_protocol_session SET expires_at = now() + interval '1 day';
```

## Quick start (with Docker)

Use the provided helper scripts to spin up a local PostgreSQL for development:

```bash
bash set-up.sh
```

What it does:
- Starts a container named `postgres` on host port `6432`
- Uses `POSTGRES_HOST_AUTH_METHOD=trust` for local, non-production convenience
- Runs `set-up.sql` inside the container to create the key-value table

Teardown:
```bash
docker stop policy-postgres && docker rm policy-postgres
```

## Configuration

`PostgresClient::new` accepts a `Config` with the following fields and defaults:

- `db` (default: `postgres`)
- `username` (default: `postgres`)
- `password` (optional)
- `port` (default: `5432`)
- `host` (default: `localhost`)
- `table` (default: `key_value`)

Connection string format constructed internally:
`postgresql://username[:password]@host:port/db`

If `POSTGRES_URL` env is set with postgres connection URI, use it instead of the config.

## Testing

There is an ignored async test that demonstrates end-to-end usage. To run it locally:

```bash
# ensure the database is running (e.g., via set-up.sh)
cargo test --package key-value-storage --lib -- postgres::tests::test_postgres_client --exact --show-output --ignored
```

Alternatively, run your regular test suite after ensuring a reachable PostgreSQL namespace matching your `Config`.
