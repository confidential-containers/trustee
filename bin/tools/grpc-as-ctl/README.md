# grpc-as-ctl

The `grpc-as-ctl` program provides a command line interface for the gRPC attestation service interface. It provides the following functions:
- Set/Get Open Policy Engine(OPA) `Policy(.rego)` and `Reference Data(.json)` files. The `Reference Data(.json)` contents should come from such as Reference Value Provider Service(RVPS), but this item is not reflected in this implementation.
- Restore `Policy(.rego)` and `Reference Data(.json)` to default value.
- Provide the Attestation Service's `attestation` endpoint testing functionality.

## Usage

Here are the steps of building and running of this `grpc-as-ctl`:

### Build

Build and install.
```shell
$ git clone https://github.com/confidential-containers/attestation-service
$ cd attestation-service
$ make && make install
```

### Run

This tool is used by Attestation-Service (AS) owners to configure and test AS after deploying it. 
Whether AS is deployed remotely or locally, users can run the tool in user mode in their local environment to configure and test the AS.

- For help information, run:
```shell
$ grpc-as-ctl --help
```
