# The Attestation Token

The Attestation Service generates an EAR attestation token, which contains many claims.

For the general structure of the attestation token, refer to the [EAR specification](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/).

Generally speaking, the attestation token will include an Appraisal for each device
that is part of the TCB (including the CPU).
These appraisals can be accessed through the `submods` field in the EAR Token.
Each submod is given a generic key constructed from the CPU class and the device count.
For instance, the CPU submod will be called `cpu0`.
If a GPU has been attested as part of the guest, there will be a `gpu0` submod.
If there is more than one GPU, there will be additional `gpuN` submods.

`cpu0` is considered to be the primary attester and has some special
information associated with it.

# ReportData and InitData

ReportData and InitData are two key Trustee concepts.
ReportData refers to data provided by a guest at attestation time.
This is sometimes called user data. The KBS protocol uses this
field to measure the the nonce and Tee Public Key.
During attestation Trustee will ensure that the corresponding
field in the hardware evidence matches the report data values
that are expected for a given connection.

InitData is a more powerful and subtle concept. See the [InitData Specification](../../kbs/docs/initdata.md)
for more information.
The basic idea is that InitData is a generalization over boot-time configuration
fields such as HostData (on SNP) or MRConfig (on TDX).
InitData is used to provision dynamic, measured, but not secret 
configuration data to the guest.
The InitData plaintext is a TOML or JSON file containing this configuration
while the InitData hash is the hash of this file which is added to the measuremet.
A client can optionally provide the InitData plaintext to Trustee.
If so, Trustee will check the plaintext against the hardware evidence
and expose the InitData plaintext to the policy engine and as part of the
attestation token.

Both the InitData and ReportData will usually be included the attestation token.
These fields will be available under the `AnnotatedEvidence` extension of the
`cpu0` Appraisal.

If the plaintext InitData is provided, some transformations will be applied
to the InitData to make it more easy to consume.

As a result, the InitData section in the token may contain the following fields:
- `cdh.toml` JSON version of the CDH config file from the InitData.
- `aa.toml` JSON version of the AA config file from the InitData.
- `agent_policy_claims` The `policy_data` claim from the Kata Agent policy (as JSON).

These fields will only be present if the plaintext InitData contains the corresponding
data.

# Hardware Claims

The annotated evidence extension will also include hardware-specific claims
extracted by the verifiers. These are listed in the [TCB Claims](./tcb_claims.md) document.
