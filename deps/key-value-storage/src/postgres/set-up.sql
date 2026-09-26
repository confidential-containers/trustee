CREATE TABLE key_value (
    value BYTEA,
    key TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ
);