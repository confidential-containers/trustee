# Quick Start

This is a guide for building and deploying the KBS components locally (without containers) on Ubuntu 22.04.
The guide also covers configuration and testing.
If you're looking for something even quicker, you might want to deploy the KBS components with
[docker compose](./docs/cluster.md) or the [KBS operator](https://github.com/confidential-containers/kbs-operator).

## Prerequisite

Install Rust tooling:
```shell
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

In order to compile some Go components (e.g. the OPA policy engine), install
the Go compiler (>= 1.20):
```shell
sudo apt-get install -y golang-1.20
export PATH=/usr/lib/go-1.20/bin:$PATH
```

Install dependencies:
```shell
curl -L "https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key" | sudo apt-key add -
echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" \
	| sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo apt-get update
sudo apt-get install -y \
	build-essential \
	clang \
	libsgx-dcap-quote-verify-dev \
	libsgx-dcap-quote-verify \
	libtdx-attest-dev \
	libtdx-attest \
	libtss2-dev \
	openssl \
	pkg-config \
	protobuf-compiler
```

Generate User authentication key pair:
```shell
openssl genpkey -algorithm ed25519 > config/private.key
openssl pkey -in config/private.key -pubout -out config/public.pub
```

If you want connect KBS with HTTPS,
you should generate a server-side certificate for KBS using a trusted CA
and pass it to the KBS server through startup parameters.

## Background Check Mode

### Build and Deploy

Build KBS in Background Check mode:
```shell
make background-check-kbs POLICY_ENGINE=opa
sudo make install-kbs
```

Build and install the kbs-client:
```shell
make cli
sudo make install-cli
```

Start KBS with HTTP server:
```shell
sudo kbs --config-file config/kbs-config.toml &
```

If you want start KBS with HTTPS server, use `--private-key` and `--certificate`
to provide file path of server-side HTTPS key and certificate (both in PEM format).

### Upload resource data

Generate a dummy resource data file:
```shell
cat > test/dummy_data << EOF
1234567890abcde
EOF
```

Use `kbs-client` to upload resource data to KBS storage:

```shell
kbs-client --url http://127.0.0.1:8080 config --auth-private-key config/private.key set-resource --resource-file test/dummy_data --path default/test/dummy
```

Here we assigned a custom path for this resource: `default/test/dummy`.

### Get resource data

Run following command to get resource data from KBS:
```shell
kbs-client --url http://127.0.0.1:8080 get-resource --path default/test/dummy
```

If you run the client outside of a TEE, the sample attester will be used.
By default the KBS rejects all sample evidence.
To test the KBS with sample evidence, you'll need to update the resource policy
to something more permissive.
This can be done with a command such as
```shell
./kbs-client --url http://127.0.0.1:8080 config --auth-private-key config/private.key  set-resource-policy --policy-file allow_all.rego
```

## Passport Mode

### Build and Deploy

Build and start KBS for token distribution:
```shell
make passport-issuer-kbs
make install-issuer-kbs
issuer-kbs --socket 127.0.0.1:50001 --insecure-http --auth-public-key config/public.pub
```

Build and start KBS for resource distribution:
```shell
make passport-resource-kbs POLICY_ENGINE=opa
make install-resource-kbs
resource-kbs --socket 127.0.0.1:50002 --insecure-http --auth-public-key config/public.pub
```

If you want start KBS with HTTPS server, use `--private-key` and `--certificate` to set server-side HTTPS key and certificate.

### Upload resource data

Generate a dummy resource data file:
```shell
cat > test/dummy_data << EOF
1234567890abcde
EOF
```

Use `kbs-client` to upload resource data to KBS storage:

```shell
kbs-client --url http://127.0.0.1:50002 config --auth-private-key config/private.key set-resource --resource-file test/dummy_data --path default/test/dummy
```

Here we assigned a custom path for this resource: `default/test/dummy`.

### Get resource data

Generate a TEE key pair (RSA):

```shell
openssl genrsa -traditional -out test/tee_key.pem 2048
openssl rsa -in test/tee_key.pem  -pubout -out test/tee_pubkey.pem
```

First, use `kbs-client` to get Attestation Token from KBS which is responsible for issuing token:
```shell
kbs-client --url http://127.0.0.1:50001 attest --tee-key-file test/tee_key.pem > test/attestation_token
```

The public part of TEE key is included in the Attestation Token claims to identify the TEE.

Then get resource from KBS with the attestation_token:
```shell
kbs-client --url http://127.0.0.1:50002 get-resource --attestation-token test/attestation_token --tee-key-file test/tee_key.pem --path default/test/dummy
```

## Custom Policy

### Attestation Policy
Use `kbs-client` to set a custom attestation policy to KBS in background check mode:
```shell
kbs-client --url http://127.0.0.1:50001 config --auth-private-key config/private.key set-attestation-policy --policy-file /path/to/policy
```

Where `/path/to/policy` should be replaced by the real path to your policy file.

Attestation policies need to be specified using the `rego` syntax defined by [Open Policy Agent](https://www.openpolicyagent.org/).
For example, you can use the following policy to verify the value of TCB SVN and firmware measurement of TDX:

```
package my_policy

import future.keywords.if

default allow = false

# The allowed reference values for the specific field in the quote
reference_tdx_tcb_svn = [ "03000500000000000000000000000000" ]
reference_tdx_mr_td = [ "abcd1234", "1234abcd", "a1b2c3d4" ]

allow if {
    input["tdx.quote.body.tcb_svn"] == reference_tdx_tcb_svn[_]
    input["tdx.quote.body.mr_td"] == reference_tdx_mrtd[_]
}
```

Refer to [Attestation-Service](https://github.com/confidential-containers/attestation-service) for filed names.

### Resource Policy
Use `kbs-client` to set custom resource policy to KBS:
```shell
kbs-client --url http://127.0.0.1:50002 config --auth-private-key config/private.key set-attestation-policy --policy-file /path/to/policy
```

Where `/path/to/policy` should be replaced by the real path to your policy file.

Resource policy also needs to be the `rego` syntax defined by [Open Policy Agent](https://www.openpolicyagent.org/).

You can read the notes of [default resource policy file](./src/api/src/policy_engine/opa/default_policy.rego) for more details of resource policy.

## Attestation Token Certificate

You can configure certificate of the signing key of Attestation Token (JWT) by config files.

### Configure signing key and certificate chain of AS Token

Adding the following content to the config file of Issuer KBS to specify token signing key and its certificate chain,
which both should be PEM format.

#### Builtin AS mode

Adding the following content to TOML config file of KBS itself:
```toml
[as_config.attestation_token_config.signer]
key_path = "/path/to/token-key.pem"
cert_path = "/path/to/token-cert-chain.pem"
```

Refer to [config.md](./docs/config.md) for more details.

#### gRPC AS mode

Adding the following content to JSON config file of gRPC AS:
```json
{
    ...

    "attestation_token_config": {
        "duration_min": 5,
		"signer": {
			"key_path": "/path/to/token-key.pem",
			"cert_path": "/path/to/token-cert-chain.pem"
		}
    }
}
```

### Configure trusted root certificate of KBS

Adding the following content to the config file of Resource KBS to specify trusted root certificate (PEM format),
which used to verify the trustworthy of the certificate in Attestation Token:

```toml
[attestation_token_config]
attestation_token_type = "CoCo"
trusted_certs_paths = ["/path/to/trusted_cacert.pem"]
```

If `trusted_certs_paths` field is not set, KBS will skip the verification of the certificate in Attestation Token.

Refer to [config.md](./docs/config.md) for more details.
