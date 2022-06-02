# Attestation Server

Attestation Server is a user space application for attestation purpose. 
It receives and verifies the TEE's attestation [Evidence](https://github.com/confidential-containers/kbs/blob/main/docs/kbs_attestation_protocol.md#attestation) and responses the corresponding [Attestation Results](https://github.com/confidential-containers/attestation-service/issues/1) to ensure the Evidence's generation environment is a real TEE environment and its Trusted Computing Base (TCB) status is as expected.

Attestation Server supports the following types of TEE:
- SGX
- TDX
- SEV-SNP
- SAMPLE: Dummy TEE which is used to test/demo the Server's functionalities.

Attestation Server depends on [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/) to evaluate the Evidence's TCB status during attestation. Each supported TEE's OPA `Policy(.rego)` and `Reference Data(.json)` can be customized in order to evaluate the TCB status precisely.
Note: Please refer [Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/) for more about `.rego` syntax information.

## API

Attestation Server provides two groups of GRPC endpoints:
- attestation: Attest the received Evidence which is defined in [protobuf](https://github.com/confidential-containers/attestation-service/server/proto/attestation.proto).
- management: Customize the Server's configuration which is defined in [protobuf](https://github.com/confidential-containers/attestation-service/server/proto/management.proto).

### Attestation

The `attestation` group only includes one `Attestation` GRPC endpoint currently. It receives the attestation [Evidence](https://github.com/confidential-containers/kbs/blob/main/docs/kbs_attestation_protocol.md#attestation), executes attestation procedures, and and responds with the [Attestation Results](https://github.com/confidential-containers/attestation-service/issues/1).

`Attestation` message:
```PROTO
message AttestationRequest {
    // Attestation evidence: https://github.com/confidential-containers/kbs/blob/main/docs/kbs_attestation_protocol.md#attestatio
    bytes evidence = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
}
```

### Management

It's mainly used to customize Attestation Server's configurations:
- Customize each type of TEE's `Policy(.rego)` and `Reference Data(.json)` in order to evaluate it's TCB status precisely.
    - GetPolicy
    - GetReferenceData
    - SetPolicy
    - SetReferenceData
    - RestoreDefaultPolicy
    - RestoreDefaultReferenceData
- Test/Evaluate the local `Policy(.rego)` or `Reference Data(.json)` with remote Attestation Server's OPA engine.
    - TestOpa

The supported types of TEE:
```PROTO
enum Tee {
    Sgx = 0;
    Tdx = 1;
    SevSnp = 2;
    Sample = 3;
}
```

#### GetPolicy

Get the specific TEE's OPA `Policy(.rego)`. The message:
```PROTO
message GetPolicyRequest {
    // Supported TEE types
    Tee tee = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
}
```

#### GetReferenceData

Get the specific TEE's OPA `Reference Data(.json)`. The message:
```PROTO
message GetReferenceDataRequest {
    // Supported TEE types
    Tee tee = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
}
```

#### SetPolicy

Set the specific TEE's OPA `Policy(.rego)`. It can make the Attestation Server evaluate the TEE TCB status according to specific user's preference. And it will echo error if the new `Policy(.rego)` syntax is illegal. The message:
```PROTO
message SetPolicyRequest {
    // Supported TEE types
    Tee tee = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
    // The "Policy(.rego)" file's content.
    bytes content = 3;
}
```

#### SetReferenceData

Set the specific TEE's OPA `Reference Data(.json)`. It can attach a new released program's reference measurement value into the corresponding program's allow list. The message:
```PROTO
message SetReferenceDataRequest {
    // Supported TEE types
    Tee tee = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
    // The "Reference Data(.json)" file's content.
    bytes content = 3;
}
```

#### RestoreDefaultPolicy

Restore the specific TEE's OPA `Policy(.rego)` to default value. The message:
```PROTO
message ResetPolicyRequest {
    // Supported TEE types
    Tee tee = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
}
```

#### RestoreDefaultReferenceData

Restore the specific TEE's OPA `Reference Data(.json)` to default value. The message:
```PROTO
message ResetReferenceDataRequest {
    // Supported TEE types
    Tee tee = 1;
    // Optional: Designate the user id. It should be kept as "None" currently.
    optional string user = 2;
}
```

#### TestOpa

It's main purpose is to ensure the updated `Policy(.rego)` or `Reference Data(.json)` can work as expected before upload to remote Attestation Server. The message:
```PROTO
message TestOpaRequest {
    // The OPA "Policy(.rego)" content that need to test.
    bytes policy = 1;
    // The "Reference Data(.json)" content that need to test.
    bytes reference = 2;
    // The "input" which will be evaluated by the request's "policy" and "referece".
    bytes input = 3;
}
```

## Usage

Here are the steps of building and running Attestation Server:

### Build

Build Attestation Server:
```shell
git clone https://github.com/confidential-containers/attestation-service
cd attestation-service
cargo build --release
```

### Run

- For help information, run:
```shell
./target/release/attestation-server --help
```

- For version information, run:
```shell
./target/release/attestation-server --version
```

Start Attestation Server and specify the attestation and management listen ports of its gRPC service:
```shell
./target/release/attestation-server --attestation-sock 127.0.0.1:3000 --management-sock 127.0.0.1:3001
```

If you want to see the runtime log, run:
```shell
RUST_LOG=debug ./target/release/attestation-server --attestation-sock 127.0.0.1:3000 --management-sock 127.0.0.1:3001
```
