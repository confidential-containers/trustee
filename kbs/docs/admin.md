# KBS Admin Module

The `kbs/src/admin` module protects KBS admin APIs. It supports three modes:

- `InsecureAllowAll`
- `DenyAll`
- `AuthenticatedAuthorization(Authentication, Authorization)`

In `AuthenticatedAuthorization` mode, KBS validates an admin token and then applies endpoint authorization rules.

> [!NOTE]
> Implementing a full authentication and authorization module is not a aim for KBS. So the part of Admin Module should
> keep as simple as it can. If complex auth control is needed, please use an out-of-band gateway in front of KBS.

## Admin Modes and Configuration

### 1) InsecureAllowAll

This mode allows all admin requests. It is useful for local development, or with an out-of-band authN + authZ service in front of KBS in production.

```toml
[admin]
authorization_mode = "InsecureAllowAll"
```

### 2) DenyAll

This mode denies all admin requests. It is useful when admin APIs should be disabled.

```toml
[admin]
authorization_mode = "DenyAll"
```

### 3) AuthenticatedAuthorization

This mode enables real admin authentication and authorization.

- `authentication = bearer_jwt` verifies `Authorization: Bearer <JWT>`
- JWT **MUST** contain a `role` claim
- `authorization = regex_acl` authorizes by `acl(role -> allowed_endpoints)`
- `allowed_endpoints` must start with `^/kbs` and end with `$`

Example:

```toml
[admin]
authorization_mode = "AuthenticatedAuthorization"

[admin.authentication.bearer_jwt]
identity_providers = [
  { issuer = "authentik", audience = "kbs-admin", jwk_set_uri = "https://auth.example.com/application/o/kbs/jwks/" },
  { issuer = "legacy-admin", public_key_uri = "file:///etc/kbs/legacy-admin-public.pem" },
  { issuer = "dev-admin", public_key_uri = "./test_data/admin/public_key.pem" }
]

[admin.authorization.regex_acl]
acls = [
  { role = "kbs-admin", allowed_endpoints = "^/kbs/v0/resource/.+$" },
  { role = "kbs-admin", allowed_endpoints = "^/kbs/v0/resource-policy$" },
  { role = "kbs-admin", allowed_endpoints = "^/kbs/v0/attestation-policy$" }
]
```

#### External Identity / Authorization Ecosystem Support

`AuthenticatedAuthorization` mode can work with external identity ecosystems, including open-source platforms:

- External IdP signs JWTs
- KBS verifies JWT signature using configured JWKS and/or PEM public keys
- KBS checks JWT `iss` an `aud` in `identity_providers` if configured
- JWT must include a `role` claim, and KBS maps it to local admin ACL roles
- KBS authorizes each admin API path via regex ACL rules

This lets you keep identity issuance external while keeping KBS-side authorization explicit and auditable.

## `bearer_jwt` Config Reference

`[admin.authentication.bearer_jwt]` accepts:

- `identity_providers` (array): list of trusted identity providers

Each `identity_providers` entry:

- `issuer` (optional string): expected JWT `iss` value; empty means no issuer check
- `audience` (optional string): expected JWT `aud` value; empty means no audience check
- `public_key_uri` (optional string): PEM public key source
- `jwk_set_uri` (optional string): trusted JWKS source (see formats below)

Each entry must provide at least one of `public_key_uri` or `jwk_set_uri`.

`jwk_set_uri` formats:

- `file://...` or local path (for example `./keys/admin.jwks`): JWKS JSON file, read directly
- `https://...`: remote JWKS URL or OpenID issuer base URL (see note below)

> [!NOTE]
> For remote `jwk_set_uri` values, KBS first tries to load JWKS from the configured URL
> directly (for example a `/jwks/` endpoint). If that fails, it falls back to OpenID discovery
> at `{uri}/.well-known/openid-configuration` and loads keys from the returned `jwks_uri`.
