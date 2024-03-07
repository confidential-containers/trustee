# Initdata Specification

The Initdata Specification defines the key data structure and algorithms
to inject any well-defined data from untrusted host into TEE. To guarantee
the integrity of that data, TEE evidence's hostdata ability or (v)TPM dynamic
measurement ability will be leveraged.

## Introduction

TEE gives users an isolated execution environment to prevent untrusted
hosts and external software stacks from eavesdropping and tampering with user
data in use within the TEE.

Remote attestation technology verifies whether the footprint of software
running in the TEE meets expectations. The softwares to be measured are
often provided by hardware vendor (like the firmware and tcb security version
of TEE hardware) or software vendor (like guest kernel for VMs). These
components are relatively static, which means they may be the same among
multiple deployments

In some scenarios, users would inject some other information like
[policy files for kata](https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-use-the-kata-agent-policy.md),
[configuration files for components running in guest](https://github.com/confidential-containers/guest-components/tree/main/confidential-data-hub#configuration-file),
[identity files to specify the identity of TEE](https://github.com/keylime/rust-keylime/blob/master/keylime-agent.conf)
into the TEE guest when launching.

Compared with static software running in TEE (like guest firmware for TDX VM,
libos for SGX enclave), these information changes dynamically between different
deployments and are usually configurations
We call these information or configurations _Initdata_. Initdata mechanism will
provides a way to protect their integrity by remote attestation. One thing to note
is that the confidentiality will not be protected by initdata mechanism because
the untrusted host can see the plaintext of the data.

To achieve this goal, we defined the following things
- A data structure named **Initdata**. This structure is provided by the
user to contain any data in key-value format to untrusted host to inject into
the TEE when launching. We do not limit the encoding of this data structure, which
means that JSON, TOML and YAML are optional. This will be introduced in [Initdata](#initdata)
- A data integrity binding mechanism. It will guide the untrusted host to bind the
digest of the `data` part (initdata data) in the Initdata to the hardware TEE-specific 
field in evidence. This field will be checked by the verifier during the remote
attestation. This will be introduced in 
[Integrity Binding for Different TEEs](#integrity-binding-for-different-tees)
- A data serialization method. This method is used to serialize the Initdata data
into a canonicalized one, which will help to get consistent cryptographic hash for
different forms of a same initdata. This will be introduced in
[Data Canonicalization Algorithm](#data-canonicalization-algorithm).

This spec does not define how the initdata will be delivered into the TEE.
Different projects will have its own way to do this. For Confidential Containers,
we will use kata-runtime and kata-agent to collaborate to achieve this function.

## Terminology

This section will introduce the terminology used in this spec to avoid ambiguity.

- `Initdata`: A data structure that includes initdata data and other information
that will help to calculate the initdata digest. The whole data structure will
be delivered into the guest.
- `Initdata Metadata`: Metadata fields of initdata, s.t. `algorithm`, `version`,
etc. They are used to calculate the initdata digest.
- `Initdata data`: Data that needs to be injected when the TEE is started. This data
requires integrity protection but does not require confidentiality protection. In
initdata, this will be included inside the `data` section.
- `Initdata digest`: Digest of the initdata data calculated following this spec.
It will be used as the value of the TEE hostdata/initdata field.
- `TEE initdata/hostdata`: Fields that can be bound to a specific TEE instance. This field
information will be included in the TEE-signed remote attestation report. Typically,
Intel TDX's `mr_config_id`, AMD SNP's `hostdata` and Arm CCA's `CCA_REALM_PERSONALIZATION_VALUE`.
In order to avoid confusion with the hostdata field of AMD SNP, when we do not
emphasize a specific platform s.t. SNP, we are referring to the corresponding fields of
various TEE platforms.

## Specifications

### Initdata

Initdata defines a standardized structure format. Please note that it
does not indicate the specific encoding format, but requires that the encoding format
must support the expression of key-value data pairs. Typical encodings that meet
this requirement include JSON, TOML and YAML, etc.

An initdata SHOULD have the following fields
- `version`: The format version of the initdata metadata. Version number will provide
extensibility. The definition in this spec is all `0.1.0`.
- `algorithm`: The hash algorithm to calculate the value to set as `HOSTDATA`. The typical
algorithms are `sha-256`, `sha-384`, `sha-512`. The name follows 
[IANA Hash Function Textual Names](https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml)
- `data`: a key-value map from string to string. Including the concrete content of initdata.

#### Examples for Different Encodings

Suppose there is an initdata with the following values
- `version`: `0.1.0`
- `algorithm`: `sha384`
- `data`: there are two objects. The first's key name is `attestation-agent.json` and the value
is a string of a JSON. The second's key name is `policy.rego` and the value is a string of a rego file.

##### JSON version

The JSON version initdata looks like the following
```json
{
  "algorithm": "sha384",
  "version": "0.1.0",
  "data": {
    "attestation-agent.json": "{\"aa_kbc_params\": \"cc_kbc::http://127.0.0.1:8080\"}",
    "policy.rego": "package agent_policy\nimport future.keywords.in\nimport future.keywords.every\nimport input\n\n# Default values, returned by OPA when rules cannot be evaluated to true.\ndefault CopyFileRequest := false\ndefault CreateContainerRequest := false\ndefault CreateSandboxRequest := true\ndefault DestroySandboxRequest := true\ndefault ExecProcessRequest := false\ndefault GetOOMEventRequest := true\ndefault GuestDetailsRequest := true\ndefault OnlineCPUMemRequest := true\ndefault PullImageRequest := true\ndefault ReadStreamRequest := false\ndefault RemoveContainerRequest := true\ndefault RemoveStaleVirtiofsShareMountsRequest := true\ndefault SignalProcessRequest := true\ndefault StartContainerRequest := true\ndefault StatsContainerRequest := true\ndefault TtyWinResizeRequest := true\ndefault UpdateEphemeralMountsRequest := true\ndefault UpdateInterfaceRequest := true\ndefault UpdateRoutesRequest := true\ndefault WaitProcessRequest := true\ndefault WriteStreamRequest := false"
  }
}
```

it would involve a lot of escape characters. JSON is better to set simple key
values, like the following
```json
{
  "algorithm": "sha384",
  "version": "0.1.0",
  "data": {
    "key1": "value1",
    "key2": "value2"
  }
}
```

##### TOML version

If you want to avoid escape characters and use the plaintext of ascii file contents as initdata,
TOML format will be better. A TOML version initdata looks like the following
```toml
algorithm = "sha384"
version = "0.1.0"
# digest = "e4744fddbb00dd4201326d16ee5a647debf86562a77f1aca176d23017c1cf88821af5c05c03b1ac9b46afa93b9a1d368"

[data]
"attestation-agent.json" = '''
{
"kbs_addr": "http://172.18.0.1:8080"
}
'''

"policy.rego" = '''
package agent_policy

import future.keywords.in
import future.keywords.every

import input

# Default values, returned by OPA when rules cannot be evaluated to true.
default CopyFileRequest := false
default CreateContainerRequest := false
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default OnlineCPUMemRequest := true
default PullImageRequest := true
default ReadStreamRequest := false
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StatsContainerRequest := true
default TtyWinResizeRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := false'''
```

### Integrity Binding for Different TEEs

There are multiple ways to binding the integrity of initdata data to the TEE evidence.
Many TEE platforms supports TEE initdata field. The TEE initdata field could be set by
the untrusted host when launching the TEE, and the field will be included in the
TEE evidence for remote attestation.

Platforms and corresponding field of the evidence
- Intel TDX: `mr_config_id`, 48 bytes. Actually `mr_owner` and `mr_owner_config` have similiar
attributes, but we select only `mr_config_id` for such use.
- AMD SNP: `hostdata`, 32 bytes.
- Arm CCA: `CCA_REALM_PERSONALIZATION_VALUE`, 64 bytes.
- Intel SGX: `CONFIGID`, 64 bytes.

When users want to deploy a TEE, they need to prepare an initdata metadata. The host
(probably untrusted) SHOULD start TEE instance with initdata digest as TEE initdata.

The software outside the TEE delivers the initdata into the TEE in a way that
is not specified in this document. The software stack inside the TEE **MUST**
establish the integrity of the initdata data fields. 

Other platforms, such as (v)TPM based platforms, can record the initdata digest
by extending the PCR before using it. This way will also accomplish the integrity binding
to the TEE evidence.

### Data Canonicalization Algorithm

When we use JSON or Toml to represent an initdata, control characters like
line breaks that do not affect the semantics but will cause the original initdata
data content to change. This fact will make it difficult for us to calculate a
determined digest from different forms of a same initdata data. We need a canonicalization
algorithm. With this algorithm, all different forms of a same initdata will be calculated
into a same initdata digest. The difference of forms at least include the following

1. The encoding of the initdata, e.g. JSON and TOML.
2. Initdata metadata with different expressions but the same semantics, e.g. multiple line
JSON vs one line JSON like the following
```json
{
  "algorithm": "sha384",
  "version": "0.1.0",
  "data": {
    "key1": "value1",
    "key2": "value2"
  }
}
```
and
```json
{"algorithm":"sha384","version":"0.1.0","data":{"key1":"value1","key2":"value2"}}
```

The algorithm has 2 steps as following

1. Transform the original initdata data, s.t. `data` field into JSON. This step requires converting
different forms of initdata metadata into JSON without changing the semantics. This is practical
because JSON, TOML and YAML all support key-value, string, and nested formats.
2. Canonicalize the JSON resulted in step 1. The canonicalization follows [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).
This includes removing extra whitespace characters and ordering of object members.

After performing the algorithm, the result string can be used to apply hash `algorithm`.

# Use cases

## Confidential Containers

Confidential Containers (CoCo) leverages Initdata to inject configurations like
[kata-agent's policy](https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-use-the-kata-agent-policy.md),
configurations for [guest components](https://github.com/confidential-containers/guest-components).

The encoding of initdata is TOML.

To establish the integrity of the initdata data, CoCo software inside TEE:

Calculates the digest of the data fields following the spec, verifies that
the calculated value matches the value of the TEE field used for integrity
binding. Performs remote attestation, that verifies that the expected value
of the TEE field used for integrity binding.
