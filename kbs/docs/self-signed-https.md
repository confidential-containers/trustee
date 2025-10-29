# Use a Self-Signed Cert to Leverage HTTPS

This guide will take the following goals
- Generate a private key and a self-signed HTTPS certificate of the public part of the private key.
- Use the private key and the cert to launch KBS
- Use KBS client tool to access the KBS HTTPS server

## Generate a self-signed certificate

```bash
# Edit a crt configuration. You can change the following items to any you want
cat << EOF > localhost.conf
[req]
default_bits       = 2048
default_keyfile    = localhost.key
distinguished_name = req_distinguished_name
req_extensions     = req_ext
x509_extensions    = v3_ca

[req_distinguished_name]
countryName                 = Country Name (2 letter code)
countryName_default         = CN
stateOrProvinceName         = State or Province Name (full name)
stateOrProvinceName_default = Zhejiang
localityName                = Locality Name (eg, city)
localityName_default        = Hangzhou
organizationName            = Organization Name (eg, company)
organizationName_default    = localhost
organizationalUnitName      = organizationalunit
organizationalUnitName_default = Development
commonName                  = Common Name (e.g. server FQDN or YOUR name)
commonName_default          = localhost
commonName_max              = 64

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names

[alt_names]
DNS.1   = localhost
DNS.2   = 127.0.0.1
EOF

# generate the private key and self-signed cert
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout localhost.key \
  -out localhost.crt \
  -config localhost.conf \
  -passin pass:
```
## Generate resource retrieve key pair

```bash
openssl genpkey -algorithm ed25519 > private.key
openssl pkey -in private.key -pubout -out public.pub
```

## Launch KBS server
Set up a `kbs-config.toml`
```bash
cat << EOF > kbs-config.toml
[http_server]
sockets = ["0.0.0.0:8080"]
private_key = "/etc/key.pem"
certificate = "/etc/cert.pem"
insecure_http = false

[[admin.admin_backend.Simple.personas]]
id = "admin"
public_key_path = "/etc/public.pub"

[attestation_token]
insecure_key = true

[policy_engine]
policy_path = "/opa/confidential-containers/kbs/policy.rego"

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"

    [attestation_service.attestation_token_broker]
    type = "Ear"
    duration_min = 5

    [attestation_service.rvps_config]
    type = "BuiltIn"

    [attestation_service.rvps_config.storage]
    type = "LocalFs"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
EOF
```

Use docker to run KBS-built-in-as
```bash
docker run -it --rm \
  -v $(pwd)/kbs-config.toml:/etc/kbs-config.toml \
  -v $(pwd)/localhost.key:/etc/key.pem \
  -v $(pwd)/localhost.crt:/etc/cert.pem \
  -v $(pwd)/public.pub:/etc/public.pub \
  --env RUST_LOG=debug \
  -p 8080:8080 \
  kbs:coco-as \
  kbs --config-file /etc/kbs-config.toml
```

`kbs:coco-as` is built from `docker build -t kbs:coco-as . -f kbs/docker/Dockerfile`, also can use a staged image from https://github.com/confidential-containers/kbs/pkgs/container/staged-images%2Fkbs

## Use client tool to access

```bash
echo testdata > dummy_data
kbs-client --cert-file localhost.crt \
  --url https://localhost:8080 \
  config \
  --auth-private-key private.key \
  set-resource \
  --resource-file dummy_data \
  --path default/test/dummy
```

and the result 
```plaintext
Set resource success
```

shows it succeeded.

**The port mapping is very important as the FQDN inside the cert is set as `localhost`.** We must ensure the URI used on the client tool set is the same as the one inside the certificate's CommonName.
