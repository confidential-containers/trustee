# attestation-service-ctl

The `attestation-service-ctl` program provides a command line interface for the attestation server interface. It provides the following functions:
- Set/Get each TEE's Open Policy Engine(OPA) `Policy(.rego)` and `Reference Data(.json)` files. The `Reference Data(.json)` contents should come from such as Reference Value Provider Service(RVPS), but this item is not reflected in this implementation.
- Restore each TEE's `Policy(.rego)` and `Reference Data(.json)` to default value.
- Provide the Attestation Server's `attestation` endpoint testing functionality.

## Supported TEEs

Currently the `attestation-service-ctl` supports the following types of TEE:
- `sgx` (Intel SGX)
- `tdx` (Intel TDX)
- `sevsnp` (AMD SEV-SNP)
- `sample`: The dummy TEE used to demo/test Attestation Server's base functionalities.

## Usage

Here are the steps of building and running of this `attestation-service-ctl`:

### Build

Build the attestation-service-ctl and Attestation Server.
```shell
$ git clone https://github.com/confidential-containers/attestation-service
$ cd attestation-service
$ cargo build --release
```

### Run

This tool is used by Attestation-Server (AS) owners to configure and test AS after deploying it. 
Whether AS is deployed remotely or locally, users can run the tool in user mode in their local environment to configure and test the AS.

- For help information, run:
```shell
$ ./target/release/attestation-service-ctl --help
```
