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
Hygon DCU attestation uses `dcu0` and additional `dcuN` submods in the same way.

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

Both InitData and ReportData will usually be included in the attestation token.
Raw values extracted from evidence are under `ear_attester_claims` of the
`cpu0` appraisal. Parsed JSON that has been bound to the evidence is under
`ear_verifier_claims`:

- Raw hash and report bytes: `ear_attester_claims.init_data` and
  `ear_attester_claims.report_data`
- TEE type and hardware claims: `ear_attester_claims.tee` and
  `ear_attester_claims.claims`
- Parsed data: `ear_verifier_claims.init_data` and
  `ear_verifier_claims.runtime_data`

The `ear_verifier_claims` entries are only emitted when the client supplied the
corresponding plaintext and the verifier bound it to the evidence. If only a
digest (InitData) or raw bytes (ReportData) were supplied, there is nothing to
report and the key is omitted entirely rather than set to `null`.

If plaintext InitData is provided, the Attestation Service applies
transformations that make it easier to consume.

As a result, the InitData section in the token (`ear_verifier_claims.init_data`)
may contain the following fields:
- `cdh.toml`: JSON representation of the CDH configuration from InitData.
- `aa.toml`: JSON representation of the AA configuration from InitData.
- `agent_policy_claims`: JSON representation of the `policy_data` claim from
  the Kata Agent policy.

These fields are present only if the plaintext InitData contains the
corresponding data.

# Hardware Claims

`ear_attester_claims.claims` holds hardware-specific claims extracted by the
verifiers, and `ear_attester_claims.tee` names the TEE (for example `tdx`,
`snp`). The AS policy input still nests those claims under the TEE name; only
the issued token uses the `tee` + `claims` shape. Field definitions are listed
in the [TCB Claims](./tcb_claims.md) document.
