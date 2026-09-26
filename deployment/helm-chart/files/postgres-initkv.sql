-- Trustee unified Postgres KV: one table per namespace (key-value-storage).
-- Bitnami PostgreSQL runs init scripts only when the data directory is empty (first init).
-- CREATE IF NOT EXISTS keeps re-runs safe if the script is ever executed again.
-- Every table needs expires_at (see the key-value-storage PostgreSQL README).
CREATE TABLE IF NOT EXISTS kbs (
  value BYTEA,
  key TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS repository (
  value BYTEA,
  key TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ
);
-- Sessions all expire, so index expires_at for the periodic cleanup.
CREATE TABLE IF NOT EXISTS kbs_protocol_session (
  value BYTEA,
  key TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS kbs_protocol_session_expires_at
  ON kbs_protocol_session (expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS attestation_service_policy (
  value BYTEA,
  key TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS reference_value (
  value BYTEA,
  key TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ
);
