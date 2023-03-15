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
This API is formally described in its [OpenAPI formatted specification](docs/kbs.yaml).

## Usage

### Build and Run

Start KBS and specify the address it listens to (take `127.0.0.1:8080` as an example):

```shell
make kbs
./target/debug/kbs --socket 127.0.0.1:8080
```

A custom, [JSON-formatted configuration file](src/config.rs) can be used:

```shell
./target/debug/kbs --socket 127.0.0.1:8080 --config /path/to/config.json
```

### Build and Deploy with Container

Build Container image:

```shell
DOCKER_BUILDKIT=1 docker build -t kbs:native-as . -f docker/Dockerfile
```

Quick Deploy KBS with Native AS:

```shell
docker run -it --name=kbs --ip=<IP> -p <PORT>:<PORT> kbs:native-as kbs -s <IP>:<PORT>
```

**Note**: If needs to verify TDX/SGX evidence using local PCCS (localhost:8081), please add `-p 8081` or directly use `--net host` when deploy KBS with `docker run`.

## Attestation

KBS communicate with [Attestation-Service](https://github.com/confidential-containers/attestation-service) to verify TEE evidence.
KBS supports communication with AS in two ways, which is determined by the compilation option.

#### Native AS mode

KBS integrates AS library crate, this is the default attestation mode. Build with:

```shell
make kbs-native-as
# Or directly:
make kbs
```
Native AS config file path can be specified in KBS config file.

#### Remote AS mode

KBS connects remote gRPC AS server to verify TEE evidence. In this mode, a standalone AS server should be running.
Build with:
```
make kbs-grpc-as
```
Remote AS address can be specified in KBS config file, default address is `127.0.0.1:50004`.

## Resource Repository

Resource Repository is the storage module of KBS, which is used to manage and store confidential resources.
KBS supports a variety of repository implementations, such as database or local file system.

Which resource repository implementation to use is specified by config at startup (the default is the local file system)

### Local File System Repository

Resource files path map to a KBS resource URLs, as follows:
| Resource File Path  | Resource URL |
| ------------------- | -------------- |
| `file://<$(KBS_REPOSITORY_DIR)>/<repository_name>/<type>/<tag>`  |  `http://<kbs_address>/kbs/v0/resource/<repository_name>/<type>/<tag>`  |

The KBS repository directory is specified in config file (if repository type is local file system).
The default KBS repository directory is `/opt/confidential-containers/kbs/repository`.


