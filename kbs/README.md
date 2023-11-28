# Key Broker Service

The Confidential Containers Key Broker Service (KBS) is a remote server which facilitates remote attestation.
It is the reference implementation of [Relying Party](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html)
and [Verifier](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html) in [RATS](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/)
role terminology.

This project relies on the [Attestation-Service (AS)](https://github.com/confidential-containers/attestation-service) to verify TEE evidence.

The following TEE platforms are currently supported:

- AMD SEV-SNP
- Azure SNP vTPM
- Intel SGX
- Intel TDX

KBS has two deployment modes, which are consistent with [RATS](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html)
- Background Check Mode: KBS integrates AS to verify TEE evidence, then distribute resource data.
- Passport Mode: One KBS integrates AS to verify TEE evidence and distribute tokens,
the other KBS verifies the token then distributes resource data.

## Background Check Mode

The name of [Background Check](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#section-5.2) is from RATS architecture.

In this mode, the Client in TEE conveys Evidence to KBS,
which treats it as opaque and simply forwards it to an integrated Attestation Service.
AS compares the Evidence against its appraisal policy, and returns an Attestation Token (including parsed evidence claims) to KBS.
The KBS then compares the Attestation Token against its own appraisal policy and return the requested resource data to client.

**Here, the KBS is corresponding to the Relying Party of RATS and the AS is corresponding to the Verifier of RATS.**

Build and install KBS with native integrated AS in background check mode:
```shell
make background-check-kbs
make install-kbs
```

The optional compile parameters that can be added are as follows:
```shell
make background-check-kbs [HTTPS_CRYPTO=?] [POLICY_ENGINE=?] [AS_TYPES=?] [COCO_AS_INTEGRATION_TYPE=?]
```

where:
- `HTTPS_CRYPTO`: 
Can be `rustls` or `openssl`. Specify the library KBS uses to support HTTPS.
Default value is `rustls`
- `POLICY_ENGINE`: Can be `opa`.
Specify the resource policy engine type of KBS.
If not set this parameter, KBS will not integrate resource policy engine.
- `AS_TYPES`: can be `coco-as` or `intel-trust-authority-as`.
Specify the Attestation Service type KBS relies on.
- `COCO_AS_INTEGRATION_TYPE`: can be `grpc` or `builtin`. This parameter only takes effect when `AS_TYPES=coco-as`.
Specify the integration mode of CoCo Attestation Service.


## Passport Mode

The name of [Passport](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#section-5.1) is from RATS architecture.

In this mode, the Client in TEE conveys Evidence to one KBS which is responsible for issuing token,
this KBS relies on an integrated AS to verify the Evidence against its appraisal policy.
This KBS then gives back the Attestation Token which the Client treats as opaque data.
The Client can then present the Attestation Token (including parsed evidence claims) to the other KBS,
which is responsible for distributing resources.
This KBS then compares the Token's payload against its appraisal policy and returns the requested resource data to client.

**Here, the KBS for issueing token is corresponding to the Verifier of RATS and the KBS for distributing resources is corresponding to the Rely Party of RATS.**

Build and install KBS for issueing token:
```shell
make passport-issuer-kbs [HTTPS_CRYPTO=?] [AS_TYPES=?] [COCO_AS_INTEGRATION_TYPE=?]
make install-issuer-kbs
```

The explanation for compiling optional parameters is the same as above.

Build and install KBS for distributing resources:
```shell
make passport-resource-kbs [HTTPS_CRYPTO=?] [POLICY_ENGINE=?]
make install-resource-kbs
```

The explanation for compiling optional parameters is the same as above.

## Documents

### Quick Start

We provide a [quick start](./quickstart.md) guide to deploy KBS locally and conduct configuration and testing on Ubuntu 22.04.

### Attestation Protocol
The KBS implements and supports a simple, vendor and hardware-agnostic
[implementation protocol](./docs/kbs_attestation_protocol.md) to perform attestation.

### API
KBS implements an HTTP-based, [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0) compliant API.
This API is formally described in its [OpenAPI formatted specification](./docs/kbs.yaml).

### Resource Repository
The [resource repository](./docs/resource_repository.md) where KBS store resource data.

### Config
A custom, [JSON-formatted configuration file](./docs/config.md) can be provided to configure KBS.

### Cluster
We provide a `docker compose` script for quickly deploying the KBS in Background check with gRPC AS,
the Reference Value Provider and the Key Provider
as local cluster services. Please refer to the [Cluster Guide](./docs/cluster.md)
for a quick start.

## Tools

### KBS Client
We provide a [KBS client](./tools/client/) rust SDK and binary cmdline tool.

### Dockerfile
Build the KBS container (background check mode with native AS) image:

```shell
DOCKER_BUILDKIT=1 docker build -t kbs:coco-as . -f docker/Dockerfile
```
