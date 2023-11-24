# Attestation Service

Attestation Service (AS for short, also known as CoCo-AS) is a general function set that can verify TEE evidence.
With Confidential Containers, the attestation service must run in an secure environment, outside of the guest node.

With remote attestation, Attesters (e.g. the [Attestation Agent](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent)) running on the guest node will request a resource (e.g. a container image decryption key) from the [Key Broker Service (KBS)](https://github.com/confidential-containers/kbs).
The KBS receives the attestation evidence from the client in TEE and forwards it to the Attestation Service (AS). The AS role is to verify the attestation evidence and provide Attestation Results token back to the KBS. Verifying the evidence is a two steps process:

1. Verify the evidence signature, and assess that it's been signed with a trusted key of TEE.
2. Verify that the TCB described by that evidence (including hardware status and software measurements) meets the guest owner expectations.

Those two steps are accomplished by respectively one of the [Verifier Drivers](#verifier-drivers) and the AS [Policy Engine](#policy-engine). The policy engine can be customized with different policy configurations.

In addition, CoCo-AS can also run independently as a remote attestation service which receives TEE evidence and returns the verification results as a token.

The AS can be built as a library (i.e. a Rust crate) by other confidential computing resources providers, like for example the KBS.
It can also run as a standalone binary, which exposes APIs in gRPC way.

# Components

## Library

The AS can be built and imported as a Rust crate into any project providing attestation services.

As the AS API is not yet fully stable, the AS crate needs to be imported from GitHub directly:

```toml
attestation-service = { git = "https://github.com/confidential-containers/kbs", branch = "main" }
```

## Server

This project provides the Attestation Service binary program that can be run as an independent server:

- [`grpc-as`](bin/grpc-as/): Provide AS APIs based on gRPC protocol.

# Usage

Build and install AS components:

```shell
git clone https://github.com/confidential-containers/kbs
cd kbs/attestation-service
make && make install
```

`grpc-as` will be installed into `/usr/local/bin`.

# Architecture

The main architecture of the Attestation Service is shown in the figure below:
```
                                      ┌───────────────────────┐
┌───────────────────────┐ Evidence    │  Attestation Service  │
│                       ├────────────►│                       │
│ Verification Demander │             │ ┌────────┐ ┌──────────┴───────┐
│    (Such as KBS)      │             │ │ Policy │ │ Reference Value  │◄───Reference Value
│                       │◄────────────┤ │ Engine │ │ Provider Service │
└───────────────────────┘ Attestation │ └────────┘ └──────────┬───────┘
                        Results Token │                       │
                                      │ ┌───────────────────┐ │
                                      │ │  Verifier Drivers │ │
                                      │ └───────────────────┘ │
                                      │                       │
                                      └───────────────────────┘
```

The Reference Value Provider Service supports different deploy mode,
please refer to [the doc](./rvps/README.md#run-mode) for more details.

### Evidence format:

The evidence format is different from TEE to TEE. Please refer to the concrete code definition for the specified format.
- Intel TDX: [TdxEvidence](./verifier/src/tdx/mod.rs)
- Intel SGX: [SgxEvidence](./verifier/src/sgx/mod.rs)
- AMD SNP: [SnpEvidence](./verifier/src/snp/mod.rs)
- Azure SNP vTPM: [Evidence](./verifier/src/az_snp_vtpm/mod.rs)
- Arm CCA: [CcaEvidence](./verifier/src/cca/mod.rs)
- Hygon CSV: [CsvEvidence](./verifier/src/csv/mod.rs)

### Attestation Results Token:

If the verification of TEE evidence is successful, AS will return an Attestation Results Token.
Otherwise, AS will return an Error which contain verifier output or policy engine output.

Attestation results token is a [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) which contains the parsed evidence claims such as TCB status.

Claims format of the attestation results token is:

```json
{
    "iss": $issuer_name,
    "jwk": $public_key_used_to_sign_the_token,
    "exp": $expire_timestamp,
    "nbf": $notbefore_timestamp,
    "policy-ids": $policy_ids_used_to_verify_the_evidence,
    "tcb-status": $parsed_evidence,
    "evaluation-reports": $reports_of_every_policy_specified,
    "reference-data": $reference_data_used_to_check,
    "customized_claims": $customized_claims,
}
```

* `iss`: Token issuer name, default is `CoCo-Attestation-Service`.
* `jwk`: Public key to verify token signature. Must be in format of [JSON Web Key](https://datatracker.ietf.org/doc/html/rfc7517).
* `exp`: Token expire time in Unix timestamp format.
* `nbf`: Token effective time in Unix timestamp format.
* `tcb_status`: Contains HW-TEE informations and software measurements of AA's execution environment. The format is in the [doc](./docs/parsed_claims.md).
* `policy-ids`: The OPA policy ids used to verify the evidence.
* `evaluation-reports` : The outputs of the policy engine, they are AS policies' evaluation opinion on TEE evidence.
* `reference-data`: Reference values in a map used to enforce the OPA policy.
* `customized_claims`: Customized claims whose integrity is protected by binding its digest into the evidence. It will be a JSON map.

## Verifier Drivers

A verifier driver parse the HW-TEE specific attestation evidence, and performs the following tasks:

1. Verify HW-TEE hardware signature of the TEE quote/report in the evidence.

2. Resolve the evidence, and organize the TCB status into JSON claims to return.

Supported Verifier Drivers:

- `sample`: A dummy TEE verifier driver which is used to test/demo the AS's functionalities.
- `tdx`: Verifier Driver for Intel Trust Domain Extention (Intel TDX).
- `snp`: Verifier Driver for AMD Secure Encrypted Virtualization-Secure Nested Paging (AMD SNP).
- `sgx`: Verifier Driver for Intel Software Guard Extensions (Intel SGX).
- `azsnpvtpm`: Verifier Driver for Azure vTPM based on SNP (Azure SNP vTPM)
- `cca`: Verifier Driver for Confidential Compute Architecture (Arm CCA).
- `csv`: Verifier Driver for China Security Virtualization (Hygon CSV).

## Policy Engine

The AS supports modular policy engine, which can be specified through the AS configuration. The currently supported policy engines are:

### [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/)

OPA is a very flexible and powerful policy engine, AS allows users to define and upload their own policy when performing evidence verification.

**Note**: Please refer to the [Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/) documentation for more information about the `.rego`.

If the user does not need to customize his own policy, AS will use the [default policy](./attestation-service/src/policy_engine/opa/default_policy.rego).

## Reference Value Provider

[Reference Value Provider Service](rvps/README.md) (RVPS for short) is a module integrated in the AS to verify,
store and provide reference values. RVPS receives and verifies the provenance input from the software supply chain,
stores the measurement values, and generates reference value claims for the AS according to the evidence content when the AS verifies the evidence.