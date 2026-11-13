# Attestation Policy (Developing)

CoCo AS provides a flexible policy support based on Rego to facilitate the customized verification rules.

The policy will be enforced to generate an attestation token, i.e. EAR token.

EAR tokens support an expressive policy result.
A policy should expose `data.policy.trust_claims`, and set at least one AR4SI trust claim as an integer between `-127` and `127`.

The supported trust claim keys are:
* `instance-identity`
* `configuration`
* `executables`
* `file-system`
* `hardware`
* `runtime-opaque`
* `storage-opaque`
* `sourced-data`

These dimensions can be used to return a detailed, but generic description of the TCB of the attester.
More information about these trust claims, including what the numerical values of the claims represent,
can be found [here](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/).

A policy can also optionally define a claim called `data.policy.extensions`.
Any extensions specified via this claim will be added to the attestation token.
The extensions claim should contain an array of extension objects.
An extension object should look like this:
```json
{
    "name": "<name-of-extension>",
    "key": "<index-of-extension>",
    "value": ...
}
```

Extension names should be Collision-Resistant Public Claim Names.
The extension key should be an i32.
If the extension is registered in the EAR specification, the key will be positive.
Otherwise, the key should be negative.
The extension value can be any valid JSON, including nested objects.

The default policy includes the extension `ear.trustee.identifiers`, which is used
to store fields that identify the workload.
With Confidential Containers these identifiers will usually be based on the Kata
Agent Policy or other configuration fields in the InitData.
Other runtimes might use other mechanisms, such as the event log.
The `identifiers` extension includes two subfields.

* `validated` identifiers are those that are bound to the hardware evidence via
attestation and that the guest runtime binds to the workload.
* `unvalidated` identifiers are anything else that describe the workload.

The default policy, which is roughly scoped to the CoCo runtime, includes logic
for the following `validated identifiers`. These will be included in the `ear.trustee.identifiers`
extension if the runtime provides/measures the required information.
* `pod-image` a list of all the images used by the pod
* `pod-image-count` the number of images used by a pod
* `container_uids` a list of the uids that containers in a pod run with

AS policies will be provided `input`.

`input` always has the same shape: `input.devices` is the list of verifier results the policy
judges, one entry per result. Every entry has a `device` field with the name of the device, a
`tee` field with the name of the TEE and the claims of the verifier under `claims`, for example
```json
{
  "devices": [
    {
      "device": "tdx",
      "tee": "tdx",
      "claims": { "...": "..." },
      "init_data": "...",
      "init_data_claims": { }
    }
  ]
}
```
Besides `device`, `tee` and `claims`, an entry holds the optional `init_data`, `init_data_claims`,
`report_data` and `runtime_data_claims`, see [TCB Claims](./tcb_claims.md).

The name of the device and the name of the TEE are not the same thing. The device name is what a
policy selects results with, the TEE name tells how to read `claims`. For example the devices
`nvidia-gpu`, `nvidia-switch` and `nvidia-ppcie` all have the TEE `nvidia`. A policy that judges
several devices tells the entries apart with `d.device` or `d.tee`:

```rego
hardware := 2 if {
	some d in input.devices
	d.tee == "tdx"
	d.claims.quote.body.mr_td in query_reference_value("tdx_mr_td")
}
```

A policy declares which results it judges and how its entry in the token is called:

```rego
# The device names the policy judges. All results with one of these names are
# passed to the policy together, and produce one entry in the token.
devices := ["tdx", "snp"]

# The name of the entry (EAR submodule) in the token.
submod := "cpu0"
```

Device names follow the shape of the verifier result, not the product generation.
Verifiers emit these names: `sample`, `tdx`, `snp`, `sgx`, `csv`, `cca`, `se`, `tpm`,
`az-snp-vtpm`, `az-tdx-vtpm`, `hygon-dcu`, `nvidia-dpu`, `sample-device`, `nvidia-gpu`,
`nvidia-switch` and `nvidia-ppcie`.

See the [default policy](../src/ear_token/ear_default_policy_cpu.rego) for an example.

> [!NOTE]
> We now provide a new extension in AS policy. If any field or value should be fetched from RVPS,
> we can use function `query_reference_value(key_name)` in the rego to get reference value with key
> id `key_name` from RVPS. If no key is found in RVPS, the extension will evaluate to `null`.
>
> An example of section is like
> ```
> executables := 3 if {
> 	some d in input.devices
> 	d.tee == "tpm"
> 	d.claims.pcr11 == query_reference_value("pcr11")
> }
> ```

> [!NOTE]
> AS policies can also call `sha256_extend(old, digest)`, which computes the value of a
> register after it is extended, i.e. the SHA-256 of `old` followed by `digest`.
> Both arguments are hex-encoded strings and the result is a lowercase hex string.
> Rego strings are UTF-8 and cannot carry raw bytes, so values are exchanged as hex.
> The call returns an error if an argument is not a string or not valid hex, for example
> when `query_reference_value` returned `null` because the key was not found.
> To convert a plain string to hex, use the Rego builtin `hex.encode`.
>
> This allows registering the inputs of a measurement as separate reference values and
> letting the policy compute the expected value, instead of precomputing it for every
> combination and registering the result.
> For example, on Azure SNP vTPM the init-data is attested through PCR[8], which holds
> `SHA256(pcr8_base || SHA256(init-data))`. `pcr8_base` is the value the guest image leaves
> in PCR[8] and is not zeros. With `pcr8_base` and the init-data digest registered in RVPS
> (the key names and fields below are examples), the policy can be written as
> ```
> configuration := 2 if {
> 	podvm := query_reference_value("podvm")
> 	init := query_reference_value("init-data")
> 	some d in input.devices
> 	d.tee == "az-snp-vtpm"
> 	d.claims.tpm.pcr08 == sha256_extend(podvm["initdata_base"], init["digest"])
> }
> ```
> When the init-data changes, only its new digest has to be registered.

For EAR token issuance, every id in `policy_ids` is the id of a policy that is stored as is.
AS does not append a suffix and does not expand an id into several policies. The id used to
upload a policy is the id that is evaluated, and it is the id recorded in the token.

Each policy produces one submodule of the token, named by the `submod` it declares, and
records its own id in it (`ear_appraisal_policy_ids`). A policy judges all results whose device
name is listed in its `devices`, together, and a result can be judged by several policies.
For example a TDX result can be judged by a hardware policy and a runtime policy, which
produces two submodules.

- Two policies that declare the same `submod` are a configuration error. AS neither merges
  them nor adds an index.
- A policy that accepts none of the results does not run and produces no submodule.
- A result that is accepted by none of the policies is not part of the token. AS logs a warning.
- A policy that does not declare a non-empty list of `devices` and a non-empty `submod` is rejected when it is uploaded.
  Whether two policies declare the same `submod` can only be checked when they are used together.
- If an attestation has several results for a policy, for example eight GPUs, they are all in
  `input.devices`, one entry each. The policy has to judge all of them, for example the built-in
  `default_gpu` only trusts the GPUs if every one of them is trusted. The claims of every device
  are reported in the submodule, see [The Attestation Token](./attestation_token.md).

AS ships these default policies, which are used if the request names no policy:

| Policy id | Devices | Submodule |
| --- | --- | --- |
| `default_cpu` | `sample`, `tdx`, `snp`, `az-snp-vtpm`, `az-tdx-vtpm`, `tpm`, `se`, `cca`, `sgx`, `csv` | `cpu0` |
| `default_gpu` | `nvidia-gpu`, `sample-device` | `gpu0` |
| `default_switch` | `nvidia-switch` | `switch0` |
| `default_ppcie` | `nvidia-ppcie` | `ppcie0` |

Replace one of them by uploading a policy under the same id. To use a policy besides the default ones,
name all policies in `policy_ids`, including the default ones that should still apply.

> [!WARNING]
> Compared with earlier versions, the built-in `default_gpu` and `default_switch` policies
> judge all GPUs (switches) of an attestation together and produce one submodule, `gpu0`
> (`switch0`), instead of `gpu0`, `gpu1`, ... . Policies uploaded for earlier versions have to
> declare `devices` and `submod` and read `input.devices`. They stay in the storage, but are
> rejected when they are used, and can not be uploaded again unchanged.

## How to Use Policy

For both [gRPC CoCo AS](../../protos/attestation.proto) and [Restful CoCo AS](./restful-as.md), we have a
parameter named `policy_ids` to specify which policies to use to enforce the evidence check.

For a running CoCoAS, we can set any new policies.

Let's give some quick guides.

### gRPC CoCo AS

Firstly, start a gRPC CoCo AS
```shell
cd attestation-service/tests/e2e
make grpc.pid
```

Then, set a new policy to the CoCo AS.
We have prepared an [example SetPolicy request](../tests/coco-as/policy/grpc-set-policy.json) with [policy](../tests/coco-as/policy/new_policy.rego) and policy id `example-policy`. The policy should be `Base64 URL SAFE NO PAD` encoded.

```shell
REQ=$(cat ../../tests/coco-as/policy/grpc-set-policy.json)
grpcurl \
  -plaintext \
  -import-path ../../protos \
  -proto ../../protos/attestation.proto \
  -d @ 127.0.0.1:50004 attestation.AttestationService/SetAttestationPolicy <<EOF
$REQ
EOF
```

Then, we can use the policy to check against an evidence. We use the [request](../tests/coco-as/policy/check.json) to do this.

```shell
REQ=$(cat ../../tests/coco-as/policy/check.json)
grpcurl \
  -plaintext \
  -import-path ../../protos \
  -proto ../../protos/attestation.proto \
  -d @ 127.0.0.1:50004 attestation.AttestationService/AttestationEvaluate <<EOF
$REQ
EOF
```

### Restful CoCo AS

Firstly, start a Restful CoCo AS
```shell
cd attestation-service/tests/e2e
make restful.pid
```

Then, set a new policy to the CoCo AS.
We have prepared an [example SetPolicy request](../tests/coco-as/policy/restful-set-policy.json) with [policy](../tests/coco-as/policy/new_policy.rego) and policy id `example-policy`. The policy should be `Base64 URL SAFE NO PAD` encoded.

```shell
curl -k -X POST http://127.0.0.1:8080/policy \
     -i \
     -H 'Content-Type: application/json' \
     -d @../../tests/coco-as/policy/restful-set-policy.json
```

Then, we can use the policy to check against an evidence. We use the [request](../tests/coco-as/policy/check.json) to do this.

```shell
curl -k -X POST http://127.0.0.1:8080/attestation \
     -i \
     -H 'Content-Type: application/json' \
     -d @../../tests/coco-as/policy/check.json
```

## How to Write a Policy (Experimental)

:warning: **Warning:** The policy feature is still under development and it might be changed flexibly before we get a stable version.

We will introduce the format of policy by providing some examples to show the use cases.

1. The [default policy](../src/ear_token/ear_default_policy_cpu.rego). This policy assigns multiple trust claims based on reference values.
2. An [SGX policy](../tests/coco-as/policy/example-1.rego). The client want to ensure the `mr_signer` and `mrenclave` are both expected value.
3. A [TDX policy](../tests/coco-as/policy/example-2.rego). The client want to ensure the TDX module (reflected by `tdx.quote.body.mr_seam`), guest firmware (reflected by `tdx.quote.body.mr_td`), tcb_status (reflected by `input.tdx.tcb_status`), collateral expiration status (reflected by `input.tdx.collateral_expiration_status`) are all as expected.
4. A [IBM SE policy](../tests/coco-as/policy/example-3.rego). The client want to ensure the `se.version`, `se.tag`, `se.user_data`, `se.image_phkh` and `se.attestation_phkh` are all expected value.
