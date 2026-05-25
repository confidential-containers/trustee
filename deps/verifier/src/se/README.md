
# KBS with IBM SE verifier

This is a document to guide developer run a KBS with IBM SE verifier locally for development purpose.

## Index

- [Deployment of KBS with IBM SE verifier](#deployment-of-kbs-with-ibm-se-verifier)
- [Admin authentication](#admin-authentication)
- [Set attestation policy for IBM SE verifier](#set-attestation-policy)



# Deployment of KBS with IBM SE verifier

This section is about deployment of KBS without rvps checking.

## Generate RSA keys
Generate RSA 4096 key pair following commands:
```bash
openssl genrsa -aes256 -passout pass:test1234 -out encrypt_key-psw.pem 4096
openssl rsa -in encrypt_key-psw.pem -passin pass:test1234 -pubout -out encrypt_key.pub
openssl rsa -in encrypt_key-psw.pem -out encrypt_key.pem
```


## Download Certs, CRLs
Download these materials from: https://www.ibm.com/support/resourcelink/api/content/public/secure-execution-gen2.html
Which includes:

### Certs
ibm-z-host-key-signing-gen2.crt
DigiCertCA.crt

### CRL
ibm-z-host-key-gen2.crl
DigiCertTrustedRootG4.crl
DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl

Note: `DigiCertTrustedRootG4.crl` and `DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl` come from commands as below:
```bash
# openssl x509 -in DigiCertCA.crt --text --noout |grep crl
                  URI:http://crl3.digicert.com/DigiCertTrustedRootG4.crl
# openssl x509 -in ibm-z-host-key-signing-gen2.crt --text --noout |grep crl
                  URI:http://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
                  URI:http://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
```

## Download HKD
Download IBM Secure Execution Host Key Document following: https://www.ibm.com/docs/en/linux-on-systems?topic=execution-obtain-host-key-document

## Get SE Header
Build `se.img` following [Generate an IBM Secure Execution image](https://www.ibm.com/docs/en/cic/1.2.5?topic=kvm-generate-secure-execution-image) and retrieve the hdr.bin via command like below.
```bash
./pvextract-hdr -o hdr.bin se.img
```

Refer to [ibm-s390-linux](https://github.com/ibm-s390-linux/s390-tools/blob/v2.33.1/rust/pvattest/tools/pvextract-hdr) to get `pvextract-hdr`.

## Generate admin JWT keys

Generate an Ed25519 key pair used to sign and verify **admin API** bearer JWTs (not HTTPS certificates or attestation tokens).

```bash
openssl genpkey -algorithm ed25519 > kbs.key
openssl pkey -in kbs.key -pubout -out kbs.pem
```

See [Admin authentication](#admin-authentication) for the matching `kbs-config.toml` settings and how to create an `admin-token` file.

## (Option 1) Launch KBS as a program

- Build KBS
```bash
cargo install --locked --debug --path kbs --no-default-features --features coco-as-builtin,resource,opa
```

- Prepare the material retrieved above, similar as:
```
/run/confidential-containers/ibmse#
.
├── certs
│   ├── ibm-z-host-key-signing-gen2.crt
|   └── DigiCertCA.crt
├── crls
│   └── ibm-z-host-key-gen2.crl
│   └── DigiCertTrustedRootG4.crl
│   └── DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
├── hdr
│   └── hdr.bin
├── hkds
│   └── HKD-3931-0275D38.crt
└── rsa
    ├── encrypt_key.pem
    └── encrypt_key.pub
```

> Note: alternative is to use system variables listed in [ibmse.rs](./ibmse.rs) to overwrite the files.

- Prepare the `kbs-config.toml`, similar as:
```toml
[http_server]
sockets = ["0.0.0.0:8080"]
# Ideally we should use some solution like cert-manager to issue let's encrypt based certificate:
# https://cert-manager.io/docs/configuration/acme/
insecure_http = true

[attestation_token]
insecure_header_jwk = true

[attestation_service]
type = "coco_as_builtin"

[attestation_service.attestation_token_broker]
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[admin]
authorization_mode = "AuthenticatedAuthorization"

[admin.authentication.bearer_jwt]
identity_providers = [
  { issuer = "ibmse-dev", public_key_uri = "./kbs.pem" },
]

[admin.authorization.regex_acl]
acls = [{ role = "admin", allowed_endpoints = "^/kbs/.+$" }]

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/kbs"

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

> For local debugging only, you may set `authorization_mode = "InsecureAllowAll"` under `[admin]` and skip admin token generation. The examples below use `AuthenticatedAuthorization`.

- Launch the KBS program
```bash
export RUST_LOG=debug
export SE_SKIP_CERTS_VERIFICATION=true
./kbs --config-file ./kbs-config.toml
```

> Note: `export SE_SKIP_CERTS_VERIFICATION=true` only required for a development machine. Use `export CERTS_OFFLINE_VERIFICATION=true` to verifiy the certificates offline.

## (Option 2) Launch KBS via docker-compose
- Build the docker image
```
DOCKER_BUILDKIT=1 docker build --build-arg --build-arg ARCH="s390x" -t ghcr.io/confidential-containers/staged-images/kbs:latest . -f kbs/docker/Dockerfile
```

- Prepare a docker compose file, similar as:
```
services:
  kbs:
    image: ghcr.io/confidential-containers/staged-images/kbs:latest
    command: [
        "/usr/local/bin/kbs",
        "--config-file",
        "/etc/kbs-config.toml",
      ]
    restart: always # keep the server running
    environment:
      - RUST_LOG=debug
      - SE_SKIP_CERTS_VERIFICATION=true
    ports:
      - "8080:8080"
    volumes:
      - ./data/kbs-storage:/opt/confidential-containers/kbs/repository:rw
      - ./data/attestation-service:/opt/confidential-containers/attestation-service:rw
      - ./kbs.pem:/kbs/kbs.pem
      - ./kbs-config.toml:/etc/kbs-config.toml
      - ./data/hkds:/run/confidential-containers/ibmse/hkds
      - ./data/certs:/run/confidential-containers/ibmse/certs
      - ./data/crls:/run/confidential-containers/ibmse/crls
      - ./data/hdr.bin:/run/confidential-containers/ibmse/hdr/hdr.bin
      - ./data/rsa/encrypt_key.pem:/run/confidential-containers/ibmse/rsa/encrypt_key.pem
      - ./data/rsa/encrypt_key.pub:/run/confidential-containers/ibmse/rsa/encrypt_key.pub
```

- Prepare `kbs-config.toml` for the container (`public_key_uri` must match the `./kbs.pem:/kbs/kbs.pem` volume):

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[attestation_token]
insecure_header_jwk = true

[attestation_service]
type = "coco_as_builtin"

[attestation_service.attestation_token_broker]
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[admin]
authorization_mode = "AuthenticatedAuthorization"

[admin.authentication.bearer_jwt]
identity_providers = [
  { issuer = "ibmse-dev", public_key_uri = "/kbs/kbs.pem" },
]

[admin.authorization.regex_acl]
acls = [{ role = "admin", allowed_endpoints = "^/kbs/.+$" }]

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/kbs"

[[plugins]]
name = "resource"
storage_backend_type = "kvstorage"
```

> Note: `SE_SKIP_CERTS_VERIFICATION=true` in the compose file is only required on a development machine. Use `CERTS_OFFLINE_VERIFICATION=true` to verify certificates offline.

- Prepare the material, similar as:
```
.
├── data
│   ├── attestation-service
│   │   ├── opa
│   │   │   └── default.rego
│   ├── certs
│   │   ├── ibm-z-host-key-signing-gen2.crt
│   │   └── DigiCertCA.crt
│   ├── crls
│   │   └── ibm-z-host-key-gen2.crl
│   │   └── DigiCertTrustedRootG4.crl
│   │   └── DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
│   ├── hdr.bin
│   ├── hkds
│   │   └── HKD-3931-0275D38.crt
│   ├── kbs-storage
│   │   ├── default
│   │   └── one
│   │       └── two
│   │           └── key
│   └── rsa
│       ├── encrypt_key.pem
│       └── encrypt_key.pub
├── admin-token
├── docker-compose.yaml
├── kbs-config.toml
├── kbs.key
└── kbs.pem
```

- Launch KBS as docker compose application
```bash
docker-compose up -d
docker-compose logs kbs
docker-compose down
```


# Admin authentication

KBS admin APIs (for example `set-attestation-policy`) are protected by the `[admin]` configuration. See [KBS Admin Module](../../../../kbs/docs/admin.md) and [Admin API configuration](../../../../kbs/docs/config.md#admin-api-configuration) for details.

This guide uses `AuthenticatedAuthorization`: KBS verifies a bearer JWT and checks a `role` claim against regex ACL rules. Setting only `authorization_mode = "AuthenticatedAuthorization"` is not enough — you must also configure `[admin.authentication.bearer_jwt]` and `[admin.authorization.regex_acl]` as in the `kbs-config.toml` examples above.

## Generate an admin token

After creating `kbs.key` / `kbs.pem`, sign a long-lived admin JWT. The `iss` and `aud` values must match `identity_providers` in `kbs-config.toml`; the JWT **must** include a `role` claim that matches an ACL entry (here `admin`).

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

header='{"alg":"EdDSA","typ":"JWT"}'
iat=$(date +%s)
exp=$((iat + 315360000)) # 10 years
payload="{\"iss\":\"ibmse-dev\",\"role\":\"admin\",\"aud\":[\"kbs\"],\"iat\":${iat},\"exp\":${exp}}"

h64=$(printf '%s' "$header" | b64url)
p64=$(printf '%s' "$payload" | b64url)
signing_input=$(mktemp)
printf '%s' "${h64}.${p64}" > "${signing_input}"
sig=$(openssl pkeyutl -sign -inkey kbs.key -rawin -in "${signing_input}" | b64url)
rm -f "${signing_input}"
printf '%s.%s.%s\n' "$h64" "$p64" "$sig" > admin-token
```

Pass this file to `kbs-client` with `--admin-token-file ./admin-token` (or an absolute path). This standalone SE deployment does not use the trustee `docker compose` `setup` service, so the automatic `kbs/config/docker-compose/admin-token` lookup in `kbs-client` will not apply unless you create that path yourself.


# Set attestation policy

This section is about setting attestation policy.

### Retrive the attestation policy fields for IBM SE

Using [se_parse_hdr.py](se_parse_hdr.py) on a s390x instance to retrieve the IBM SE fields for attestation policy.

```bash
python3 se_parse_hdr.py hdr.bin HKD-3931.crt

...
  ================================================
  se.image_phkh: xxx
  se.version: 256
  se.tag: xxx
  se.attestation_phkh: xxx
```

We get following fields and will set these fields in rvps for attestation policy.
`se.version: 256`
`se.tag: xxx`
`se.attestation_phkh: xxx`
`se.image_phkh: xxx`


### Set attestation policy

#### Generate attestation policy file
```bash
cat << EOF > ibmse-policy.rego
package policy
import rego.v1
default allow = false

converted_version := sprintf("%v", [input["se.version"]])

allow if {
    input["se.attestation_phkh"] == "xxx"
    input["se.image_phkh"] == "xxx"
    input["se.tag"] == "xxx"
    input["se.user_data"] == "xxx"
    converted_version == "256"
}
EOF
```

Where the values `se.version`, `se.attestation_phkh`, `se.image_phkh` and `se.tag` come from [retrive-the-rvps-field-for-an-ibm-se-image](#retrive-the-rvps-field-for-an-ibm-se-image). The value `se.user_data` comes from [initdata](https://github.com/confidential-containers/cloud-api-adaptor/blob/main/src/cloud-api-adaptor/docs/initdata.md). Please remove `input["se.user_data"] == "xxx"` if `initdata` is not used.

#### Set the attestation policy
```bash
kbs-client --url http://127.0.0.1:8080 \
  config --admin-token-file ./admin-token \
  set-attestation-policy --policy-file ./ibmse-policy.rego
```
