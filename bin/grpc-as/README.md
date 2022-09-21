# gRPC Attestation Service

`grpc-as` is an Attestation Service application based on gRPC protocol.

## API

gRPC Attestation Service provides two groups of GRPC endpoints:
- attestation: Attest the received Evidence which is defined in [protobuf](proto/attestation.proto).
- management: Customize the Server's configuration which is defined in [protobuf](proto/management.proto).

## Usage

Here are the steps of building and running gRPC Attestation Service:

### Build

Build and install:
```shell
git clone https://github.com/confidential-containers/attestation-service
cd attestation-service
make && make install
```

### Run

- For help information, run:
```shell
grpc-as --help
```

- For version information, run:
```shell
grpc-as --version
```

Start Attestation Service and specify the attestation and management listen ports of its gRPC service:
```shell
grpc-as --attestation-sock 127.0.0.1:3000 --management-sock 127.0.0.1:3001
```

If you want to see the runtime log, run:
```shell
RUST_LOG=debug grpc-as --attestation-sock 127.0.0.1:3000 --management-sock 127.0.0.1:3001
```
