# KBS Admin Module

The `kbs/src/admin` module protects KBS admin APIs. It supports three modes:

- `InsecureAllowAll`
- `DenyAll`
- `TokenAuthorization(TokenVerifier, Authorization)`

In `TokenAuthorization` mode, KBS validates an admin token and then applies endpoint authorization rules.

## Admin Modes and Configuration

### 1) InsecureAllowAll

This mode allows all admin requests. It is useful only for local development.

```toml
[admin]
mode = "InsecureAllowAll"
```

### 2) DenyAll

This mode denies all admin requests. It is useful when admin APIs should be disabled.

```toml
[admin]
mode = "DenyAll"
```

### 3) TokenAuthorization

This mode enables real admin authentication and authorization.

- `token_verifier = BearerJwt` verifies `Authorization: Bearer <JWT>`
- `authorizer = RegexAcl` authorizes by `acl(audience -> allowed_endpoints)`
- `allowed_endpoints` must start with `^/kbs` and end with `$`

Example:

```toml
[admin]
mode = "TokenAuthorization"

[admin.token_verifier]
type = "BearerJwt"
idps = [
  { issuer = "authentik", jwk_set_uri = "https://auth.example.com/application/o/kbs/jwks/" },
  { issuer = "legacy-admin", public_key_uri = "file:///etc/kbs/legacy-admin-public.pem" },
  { issuer = "dev-admin", public_key_uri = "./test_data/admin/public_key.pem" }
]

[admin.authorizer]
type = "RegexAcl"
acls = [
  { audience = "kbs-admin", allowed_endpoints = "^/kbs/v0/resource/.+$" },
  { audience = "kbs-admin", allowed_endpoints = "^/kbs/v0/resource-policy$" },
  { audience = "kbs-admin", allowed_endpoints = "^/kbs/v0/attestation-policy$" }
]
```

#### External Identity / Authorization Ecosystem Support

`TokenAuthorization` mode can work with external identity ecosystems, including open-source platforms:

- External IdP signs JWTs
- KBS verifies JWT signature using configured JWKS and/or PEM public keys
- KBS maps JWT `aud` to local admin audiences
- KBS authorizes each admin API path via regex ACL rules

This lets you keep identity issuance external while keeping KBS-side authorization explicit and auditable.

## Quick Demo: Authentik + authn Service + kbs-client

[Authentik](https://docs.goauthentik.io/) is an IdP (Identity Provider) and SSO (Single Sign On) platform that is built with security at the forefront of every piece of code, every feature, with an emphasis on flexibility and versatility.

This section describes a quick workflow where
1. Authentik works as authN service and provisions 

### Step 1: Start authn service

Recommended architecture:

- Authentik issues OIDC tokens (typically `client_credentials`)
- authn service requests token from Authentik and exposes `POST /token`

See [the official doc](https://docs.goauthentik.io/install-config/install/docker-compose/) to launch a sample Authentik service using `docker compose`.

Suppose the Authentik service runs and listens to `localhost:9000`.

Configure an application and a provider with `OAuth2/OpenID` Provider. 

The provider can be set to `Confidential`. In this case, a `client_id` and a `client_secret` can be got to do login.

Supposing the application named `kbs`.

### Step 2: Start KBS with `admin.mode = "TokenAuthorization"`

Use the following config and start KBS. Remember to change the ``:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
# Ideally we should use some solution like cert-manager to issue let's encrypt based certificate:
# https://cert-manager.io/docs/configuration/acme/
insecure_http = true

[attestation_token]
insecure_key = true

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"

[attestation_service.attestation_token_broker]
type = "Ear"
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[admin]
mode = "TokenAuthorization"

[admin.token_verifier]
type = "BearerJwt"
idps = [
    { issuer = "authentik", jwk_set_uri = "http://localhost:9000/application/o/kbs/" },
]
insecure_public_key_from_uri = true

[admin.authorizer]
type = "RegexAcl"
acls = [{ audience = "GPU5***", allowed_endpoints = "^/kbs/.+$" }]

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

```

```bash
./kbs --config-file ./kbs-config.toml
```

### Step 3: Get admin token from authn service

Login the Authentik with `client_id` and `client_secret`, whom can be found in the provider page.

```bash
access_token=$(curl -sS -X POST "http://localhost:9000/application/o/token/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=<client-id>" \
  --data-urlencode "client_secret=<client-secret>" \
  --data-urlencode "scope=kbs-admin" | jq .access_token)

access_token=${access_token#\"}
access_token=${access_token%\"}
echo -n $access_token > /tmp/kbs-admin.token
```

Optional quick check for token claims:

```bash
jwt_payload_b64url="$(cut -d. -f2 </tmp/kbs-admin.token)"
jwt_payload_b64="$(
  printf '%s' "$jwt_payload_b64url" \
    | tr '_-' '/+' \
    | awk '{ pad = (4 - (length($0) % 4)) % 4; printf "%s", $0; for (i=0; i<pad; i++) printf "=" }'
)"

printf '%s' "$jwt_payload_b64" | base64 -d | jq .
```

### Step 4: Call KBS admin APIs with `kbs-client`

```bash
echo "hello-kbs-admin" > /tmp/test_resource

./kbs-client --url http://127.0.0.1:8080 \
  config --admin-token-file /tmp/kbs-admin.token \
  set-resource \
  --path default/secret/hello \
  --resource-file /tmp/test_resource
```

## `BearerJwt` Config Reference

`[admin.token_verifier]` with `type = "BearerJwt"` accepts:

- `idps` (array): list of trusted identity providers
- `insecure_public_key_from_uri` (optional bool, default `false`): allow fetching
  `public_key_uri` over plaintext `http://` for compatibility
  - `issuer` (string): expected JWT `iss` value
  - `public_key_uri` (optional string): PEM public key source
  - `jwk_set_uri` (optional string): JWKS source

Each `idps` entry must provide at least one of `public_key_uri` or `jwk_set_uri`.

Supported source formats:

- `https://...` (remote fetch)
- `http://...` (remote fetch, only when `insecure_public_key_from_uri=true`)
- `file://...` (local file URI)
- local path without scheme (for example `./keys/admin.pem`)
