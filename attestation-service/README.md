# Attestation Service

The Attestation Service (AS or CoCo-AS) verifies hardware evidence.
The AS was designed to be used with the [KBS](../kbs) for Confidential Containers,
but it can be used in a wide variety of situations.
The AS can be used anytime TEE evidence needs to be validated.

Today, the AS can validate evidence from the following TEEs:
- Intel TDX
- Intel SGX
- AMD SEV-SNP
- ARM CCA
- Hygon CSV
- Intel TDX with vTPM on Azure
- AMD SEV-SNP with vTPM on Azure

# Overview
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

The AS has a simple API. It receives attestation evidence and returns an attestation token
containing the results of a two-step verification process.
The AS can be consumed directly as a Rust crate (library) or built as a standalone service,
exposing a REST or gRPC API.
In Confidential Containers, the client of the AS is the KBS, but the evidence originates
from the Attestation Agent inside the guest.

The AS has a two-step verification process.

1. Verify the format and provenance of evidence itself (i.e. check the signature of the evidence). This is done by [verifier drivers](#verifier-drivers).
2. Evaluate the claims presented by the evidence (i.e. check that measurements are what the client expects). This is done by [policy engine](#policy-engine) and [RVPS](#reference-value-provider-service).

The first step is accomplished by one of the platform-specific [Verifier Drivers](#verifier-drivers).
The second step is driven by the [Policy Engine](#policy-engine) with help from the [RVPS](#reference-value-provider-service).

# Quick Start

Please refer to
- [Restful CoCo AS](docs/restful-as.md#quick-start)
- [gRPC CoCo AS](docs/grpc-as.md#quick-start)

# Advanced Topics 

Advanced topics for developers.

## Library

The AS can be built and imported as a Rust crate into any project providing attestation services.

As the AS API is not yet fully stable, the AS crate needs to be imported from GitHub directly:

```toml
attestation-service = { git = "https://github.com/confidential-containers/trustee" }
```

## Evidence format:

The attestation request must include attestation evidence.
The format of the attestation evidence depends on the platform
and the implementation of the verifier.

Please refer to the individual verifiers for the specific format of the evidence.
- Intel TDX: [TdxEvidence](./verifier/src/tdx/mod.rs)
- Intel SGX: [SgxEvidence](./verifier/src/sgx/mod.rs)
- AMD SNP: [SnpEvidence](./verifier/src/snp/mod.rs)
- Azure SNP vTPM: [Evidence](./verifier/src/az_snp_vtpm/mod.rs)
- Azure TDX vTPM: [Evidence](./verifier/src/az_tdx_vtpm/mod.rs)
- Arm CCA: [CcaEvidence](./verifier/src/cca/mod.rs)
- Hygon CSV: [CsvEvidence](./verifier/src/csv/mod.rs)

## Output

If the verification of TEE evidence does not fail, the AS will return an Attestation Results Token.

Attestation results token is a [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) which contains the parsed evidence claims such as TCB status.

The format of the attestation results token is:

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

## Architecture

### Verifier Drivers

A verifier driver parses the HW-TEE specific attestation evidence, and performs the following tasks:

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

### Policy Engine

[OPA](https://www.openpolicyagent.org/docs/latest/) is a flexible policy engine.
The AS allows users to define and upload their own OPA policy when performing evidence verification.
The `policy_ids` field of the attestation request determines which policies are evaluated.
The results of every policy that is evaluated are included in the attestation token.

**Note**: Please refer to the [Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/) documentation for more information about Rego.

If the policy is not updated, the AS will use the [default policy](./attestation-service/src/policy_engine/opa/default_policy.rego).

Concrete policy usages please refer to [this guide](docs/policy.md).

### Reference Value Provider Service

The [Reference Value Provider Service](rvps/README.md) (RVPS) is a module integrated into the AS to verify,
store and provide reference values. RVPS receives and verifies the provenance input from the software supply chain,
stores the measurement values, and generates reference value claims for the AS according to the evidence content when the AS verifies the evidence.

The Reference Value Provider Service supports different deployment modes,
please refer to [the doc](./rvps/README.md#run-mode) for more details.
