# Key Broker Service

The Confidential Containers Key Broker Service (KBS) is a remote attestation
entry point, also known as a [Relying Party](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html)
in [RATS](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/)
role terminology.

KBS integrates the [Attestation-Service](https://github.com/confidential-containers/attestation-service) to verify TEE evidence.

KBS can also be deployed as [RATS Verifier](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html).
In this case, KBS will be responsible for distributing the Attestation Token (Following the RATS Passport model).

## Protocol

The KBS implements and supports a simple, vendor and hardware-agnostic
[implementation protocol](https://github.com/confidential-containers/kbs/blob/main/docs/kbs_attestation_protocol.md).

## API

KBS implements an HTTP-based, [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0) compliant API.
This API is formally described in its [OpenAPI formatted specification](./docs/kbs.yaml).

## Attestation

By default, KBS relies on the [Confidential Containers Attestation-Service (AS)](https://github.com/confidential-containers/attestation-service)
to verify the TEE Evidence.

KBS can either integrate the CoCo AS as a dependent crate, or as a separated `gRPC`
service. This integration interface is defined by the KBS `coco-as-builtin` feature.

### Integrated CoCo Attestation Service

By default, KBS will integrate the CoCo Attestation Service as a crate.
This can be build with:

``` shell
cargo build
```

or with the default Makefile target:

``` shell
make
```

The integrated Attestation Service configuration file can be provided at
runtime through the [KBS config file](./docs/config.md), by using the `--config`
command line option.

### `gRPC` CoCo Attestation Service

In some cases, it is preferable to deploy the Attestation Service as a separate
(local or remote) service. KBS supports that model by using the AS `gRPC`
interface, with the `coco-as-grpc` Cargo feature.

This can be built with:

``` shell
cargo build --no-default-features --features coco-as-grpc
```

or with the corresponding Makefile target:

``` shell
make kbs-coco-as-grpc
```

The AS `gRPC` address can be specified in the [KBS config file](./docs/config.md),
and by default KBS will try to reach a locally running AS at `127.0.0.1:50004`.

### `Amber` Attestation Service

KBS supports Amber as the Attestation Service with the `amber-as` Cargo feature.

This can be built with:

``` shell
cargo build --no-default-features --features amber-as,rustls
```

or with the corresponding Makefile target:

``` shell
make kbs-amber-as
```

The Amber configuration can be specified in the [KBS config file](https://github.com/confidential-containers/kbs/blob/main/src/api/src/config.rs).

## Resource Repository

KBS stores confidential resources through a `Repository` abstraction specified
by a Rust trait. The `Repository` interface can be implemented for different
storage backends like e.g. databases or local file systems.

The [KBS config file](./docs/config.md)
defines which resource repository backend KBS will use. The default is the local
file system (`LocalFs`).

### Local File System Repository

With the local file system `Repository` default implementation, each resource
file maps to a KBS resource URL. The file path to URL conversion scheme is
defined below:

| Resource File Path  | Resource URL |
| ------------------- | -------------- |
| `file://<$(KBS_REPOSITORY_DIR)>/<repository_name>/<type>/<tag>`  |  `https://<kbs_address>/kbs/v0/resource/<repository_name>/<type>/<tag>`  |

The KBS root file system resource path is specified in the KBS config file
as well, and the default value is `/opt/confidential-containers/kbs/repository`.

## Usage

### Build and Run

Start KBS and specify the `HTTPS` address it should listen to with `--socket`.
When using `HTTPS`, a private key and a certificate must be provided as well:

```shell
make kbs
./target/debug/kbs --private-key key.pem --certificate cert.pem --socket https://127.0.0.1:8080
```

KBS can also run in insecure mode, through `HTTP`. This is targeted for
development purposes and should not be used in production.

A custom, [JSON-formatted configuration file](./docs/config.md)
can also be provided:

```shell
./target/debug/kbs --private-key key.pem --certificate cert.pem --socket https://127.0.0.1:8080 --config /path/to/config.json
```

### Build and Deploy with Container

Build the KBS container image:

```shell
DOCKER_BUILDKIT=1 docker build -t kbs:coco-as . -f docker/Dockerfile
```

Deploy KBS with the integrated Attestation Service:

```shell
docker run -it --name=kbs --ip=<IP> -p <PORT>:<PORT> kbs:coco-as kbs -s <IP>:<PORT>
```

**Note**: When relying on a local Provisioning Certificate Caching Service (PCCS)
for verifying a TDX or SGX Evidence, the PCCS local port must be passed to
the above described `docker run` command through the `-p` option. Using
`--net host` will work as well for that use case.

### KBS cluster

We provide a `docker compose` script for quickly deploying the KBS, the
Attestation Service, the Reference Value Provider and the Key Provider
as local cluster services. Please refer to the [Cluster Guide](./docs/cluster.md)
for a quick start.

