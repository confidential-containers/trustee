-- Trustee unified Postgres KV: one table per namespace (key-value-storage).
-- Bitnami PostgreSQL runs init scripts only when the data directory is empty (first init).
-- CREATE IF NOT EXISTS keeps re-runs safe if the script is ever executed again.
CREATE TABLE IF NOT EXISTS kbs (
  value BYTEA,
  key TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS repository (
  value BYTEA,
  key TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS kbs_protocol_session (
  value BYTEA,
  key TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS attestation_service_policy (
  value BYTEA,
  key TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS reference_value (
  value BYTEA,
  key TEXT PRIMARY KEY
);
