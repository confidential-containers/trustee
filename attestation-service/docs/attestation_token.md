# The Attestation Token

The Attestation Service generates an EAR attestation token, which contains many claims.

For the general structure of the attestation token, refer to the [EAR specification](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/).

Generally speaking, the attestation token will include an Appraisal for each
attestation policy that has been applied, see [Policy](./policy.md).
These appraisals can be accessed through the `submods` field in the EAR Token.
The key of a submod is the `submod` that the policy declares, and the id of the
policy is in `ear_appraisal_policy_ids` of the submod.

An appraisal judges all the verifier results of the devices the policy accepts, together.
For instance, the built-in policies produce the submods `cpu0` (CPU), `gpu0`
(all GPUs), `switch0` (all NVIDIA switches) and `ppcie0`. A GPU that has been
attested as part of the guest does not get a submod of its own, neither do the
other GPUs. Hygon DCUs are judged together by the policy that accepts `hygon-dcu`.

`cpu0` of the built-in policies is considered to be the primary attester and
has some special information associated with it. KBS looks for the key of the
guest and the InitData in all of the submods, and uses the first one that has them.

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
appraisal. Parsed JSON that has been bound to the evidence is under
`ear_verifier_claims`.

`ear_attester_claims` is keyed by the name of the device. The value is a list
with an entry per device of that name, even if there is only one, because a node can
have several devices of a kind, such as GPUs, and the shape of the token must not
depend on how many there are. The entries are in the order of the evidence.

```json
"ear_attester_claims": {
  "tdx": [
    { "tee": "tdx", "claims": { }, "report_data": "...", "init_data": "..." }
  ],
  "nvidia-gpu": [
    { "tee": "nvidia", "claims": { } },
    { "tee": "nvidia", "claims": { } }
  ]
}
```

- Raw hash and report bytes of a device: `report_data` and `init_data` of its entry
- TEE type and hardware claims of a device: `tee` and `claims` of its entry

`ear_verifier_claims` belongs to the request, not to a device. It is reported once
per appraisal:

```json
"ear_verifier_claims": {
  "init_data": { },
  "runtime_data": { },
  "devices": ["tdx", "nvidia-gpu"]
}
```

- Parsed data: `init_data` and `runtime_data`
- `devices`: the names of all devices of the appraisal, whose evidence has been verified

The `init_data` and `runtime_data` entries are only emitted when the client
supplied the corresponding plaintext and the verifier bound it to the evidence.
If only a digest (InitData) or raw bytes (ReportData) were supplied, there is
nothing to report and the key is omitted entirely rather than set to `null`.

The devices of a request are assumed to agree on this data. Not every device
has it, so it is merged key by key. The runtime data of the primary evidence,
for example, has the key `additional-evidence` that the runtime data of the additional
evidence has not (it is only reported if `verbose_token` is set). The result is the
union. If two devices disagree on the value of a key, no token is issued.

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

`claims` of an entry in `ear_attester_claims` holds hardware-specific claims extracted by the
verifiers, and `tee` names the TEE (for example `tdx`, `snp`). The AS policy input
has the same fields: `d.tee` and `d.claims` for every `d` in `input.devices`. Field
definitions are listed in the [TCB Claims](./tcb_claims.md) document.
