# HashiCorp Vault KV secrets engine resource backend

[HashiCorp Vault](https://developer.hashicorp.com/vault) is a secrets
management tool that securely stores and tightly controls access to tokens,
passwords, certificates, encryption keys, and other secrets. This backend
integrates the Vault KV v1 (Key-Value version 1) secret engine as a storage
backend for the Key Broker Service (KBS).

The Vault KV v1 backend allows KBS to store and retrieve confidential resources
(secrets, keys, certificates, etc.) from a centralized Vault instance with
enterprise-grade security features including access control, audit logging, and
encryption at rest.

## Features

- **Read/Write Operations**: Full support for storing and retrieving secrets from Vault KV v1 engine
- **HTTPS Support**: Secure communication with Vault servers over TLS/SSL
- **Custom CA Certificates**: Support for enterprise and self-signed certificate authorities
- **Token Authentication**: Secure authentication using Vault tokens
- **Path Mapping**: Automatic mapping of KBS resource descriptors to Vault paths

## Setup

### 1. Enable the Vault Feature

Build the KBS with the `vault` cargo feature enabled:

```bash
cd kbs

# Using the Makefile
make VAULT=true

# Or directly with cargo
cargo build --features vault
```

### 2. Configure Vault Access

Ensure your Vault instance is running and accessible. The backend requires:

- A running Vault server with KV v1 engine enabled
- A valid Vault token with appropriate permissions
- Network connectivity from KBS to the Vault server

#### Vault Configuration Example

```bash
# Enable KV v1 engine (if not already enabled)
vault secrets enable -version=1 -path=kv kv

# Create a policy for KBS access
vault policy write kbs-policy - <<EOF
path "kv/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Create a token for KBS
vault token create -policy=kbs-policy
```

### 3. Configure KBS

Add the Vault configuration to your KBS config file (e.g., `kbs-config.toml`):

```toml
[[plugins]]
name = "resource"
type = "Vault"
vault_url = "https://vault.example.com:8200"
token = "hvs.your-vault-token-here"
mount_path = "kv"                              # Optional, defaults to "secret"
verify_ssl = true                              # Optional, defaults to false
ca_certs = ["/path/to/ca-bundle.pem"]          # Optional, custom CA certificates
```

### 4. Start Trustee

```bash
# Using docker-compose
docker compose up

# Or directly
../target/release/kbs --config-file /path/to/kbs-config.toml
```

## Configuration Options

| Property      | Type           | Required | Description                                              | Default     |
|---------------|----------------|----------|----------------------------------------------------------|-------------|
| `vault_url`   | String         | Yes      | Vault server URL (HTTP or HTTPS)                         | -           |
| `token`       | String         | Yes      | Vault authentication token                               | -           |
| `mount_path`  | String         | No       | Vault KV v1 mount path                                   | `"secret"`  |
| `verify_ssl`  | Boolean        | No       | Enable/disable SSL certificate verification              | `false`     |
| `ca_certs`    | Array[String]  | No       | Paths to custom CA certificate files                     | `None`      |

### HTTPS Configuration

The backend supports secure HTTPS communication with comprehensive TLS configuration options:

#### Basic HTTPS (Default)

```toml
[[plugins]]
name = "resource"
type = "Vault"
vault_url = "https://vault.example.com:8200"
token = "hvs.your-vault-token-here"
verify_ssl = true
```

#### Custom CA Certificates

For enterprise environments with custom certificate authorities:

```toml
[[plugins]]
name = "resource"
type = "Vault"
vault_url = "https://vault.mycompany.com:8200"
token = "hvs.your-vault-token-here"
verify_ssl = true
ca_certs = [
    "/etc/ssl/certs/company-ca.pem",
    "/opt/vault/tls/vault-ca.pem"
]
```

#### Development/Testing (Disable SSL Verification)

```toml
[[plugins]]
name = "resource"
type = "Vault"
vault_url = "http://vault-dev.mycompany.com:8200"
token = "hvs.your-vault-token-here"
verify_ssl = false
```

## Path Mapping

The backend automatically maps KBS resource descriptors to Vault paths using the following format:

```bash
{repository_name}/{resource_type}/{resource_tag}
```

The secret value is stored against the key "data".


### Examples

| KBS Resource Request | Vault Path |
|---------------------|------------|
| Repository: `default`, Type: `key`, Tag: `encryption-key-1` | `default/key/encryption-key-1` |
| Repository: `app1`, Type: `cert`, Tag: `tls-cert` | `app1/cert/tls-cert` |
| Repository: `prod`, Type: `secret`, Tag: `db-password` | `prod/secret/db-password` |

The actual secret value is part of the key "data" under the vault path. For example,
the secret is the value of the key `data` under the vault path
`prod/secret/db-password`.

## Vault Token Requirements

The Vault token used by KBS must have the following capabilities for the configured mount path:

```hcl
path "{mount_path}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

### Example Vault Policies

#### Minimal Policy (KV v1 at default "secret" mount)

```hcl
path "secret/*" {
  capabilities = ["create", "read", "update", "delete"]
}
```

#### Custom Mount Path

```hcl
path "kv/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

#### Restricted Access (Read-only)

```hcl
path "secret/*" {
  capabilities = ["read"]
}
```

## Troubleshooting

### Debug Logging

Enable debug logging to troubleshoot issues:

```bash
RUST_LOG=debug ./target/release/kbs --config-file /path/to/kbs-config.toml
```

## Limitations

- **KV v1 Support**: Currently only supports KV v1 engine
- **Authentication Methods**: Only token authentication is supported
- **Mount Points**: Single mount point per instance
- **Binary Data**: All data is stored as UTF-8 strings in Vault

## Related Documentation

- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Vault KV v1 Secret Engine](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1)
