# TCB Claims

The following claims will be extracted from the hardware evidence by the
corresponding verifier.

These claims are exposed to the Attestation Service policy and included
in the attestation token.

## Claims Data Format

Policy input is a JSON object composed from verifier output. In most cases, it follows this shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `<tee-name>` | object | TEE-specific claims (for example: `tdx`, `sgx`, `snp`, `se`, `tpm`, `nvidia`, `hygondcu`, `az-tdx-vtpm`, `az-snp-vtpm`, `sample`, `csv`, `cca`) |
| `report_data` | string | Hex/base64-encoded report data extracted from evidence (format depends on verifier) |
| `init_data` | string | Hex/base64-encoded init-data hash extracted from evidence (when supported) |
| `init_data_claims` | object | Parsed init-data claims (present when init-data is provided and verified) |
| `runtime_data_claims` | object | Parsed runtime-data claims (present when report-data is provided and verified) |

`<tee-name>` matches the serialized [`Tee`](https://docs.rs/kbs-types/latest/kbs_types/enum.Tee.html) variant string (for example `az-tdx-vtpm`, not `az_tdx_vtpm`). In Rego, hyphenated keys must use bracket syntax, e.g. `input["az-tdx-vtpm"]`.

Minimal example:

```json
{
  "tdx": {
    "quote": {
      "body": {
        "mr_td": "<hex>"
      }
    }
  },
  "report_data": "<hex>",
  "init_data": "<hex>",
  "init_data_claims": {},
  "runtime_data_claims": {}
}
```

## Sample

**This is only a test verifier**.
- `sample.svn`: String. Version information of the sample evidence.
- `sample.report_data`: String (Base64 Standard). Report data when generating the evidence.
- `sample.init_data`: String (Base64 Standard). Init data hash.
- `sample.launch_digest`: String. dummy launch digest used for policy testing. Always `abcde`.
- `sample.platform_version.major`: Number. Sample platform major version. Always `1`.
- `sample.platform_version.minor`: Number. Sample platform minor version. Always `4`.
- `sample.debug`: Boolean. Sample debug flag (always false in sample verifier). Always `false`.

## Sample Device

**This is only a test verifier for device-class attestation**.
- `sampledevice.svn`: String. Version information of the sample device evidence.
- `sampledevice.report_data`: String (Base64 Standard). Report data when generating the evidence.

## Intel TDX

- `tdx.uefi_event_logs`: **Optional**. list of objects parsed from ccel log file. Whether they appear depends on whether there is CCEL. See [UEFI Eventlog](#uefi-eventlog) for structure and definitions.

The following fields always exist.
- `tdx.quote.header`: Object. TDX Quote Header.
  - `tdx.quote.header.version`: String (hex). The quote format version. Now supports `0400` (V4 version quote format) and `0500` (V5 version quote format).
  - `tdx.quote.header.att_key_type`: String (hex for 2 bytes). Enum of the algorithm used in signature.
  - `tdx.quote.header.tee_type`: String (hex for 4 bytes). TDX is always `81000000`.
  - `tdx.quote.header.reserved`: String (hex for 4 bytes). Reserved.
  - `tdx.quote.header.vendor_id`: String (hex for 16 bytes). UID of QE Vendor. QE is a signed software component inside TEE to help to generate tdx quote.
  - `tdx.quote.header.user_data`: String (hex for 20 bytes). Custom attestation key owner data.
- `tdx.quote.body`: Object. TDX Quote Body.
  - `tdx.quote.body.mr_config_id`: String (hex for 48 bytes). Software-defined ID for non-owner-defined configuration of the guest TD – e.g., run-time or OS configuration.
  - `tdx.quote.body.mr_owner`: String (hex for 48 bytes). Software-defined ID for the guest TD’s owner.
  - `tdx.quote.body.mr_owner_config`: String (hex for 48 bytes). Software-defined ID for owner-defined configuration of the guest TD – e.g., specific to the workload rather than the run-time or OS.
  - `tdx.quote.body.mr_td`: String (hex for 48 bytes). Measurement of the initial contents of the TD.
  - `tdx.quote.body.mrsigner_seam`: String (hex for 48 bytes). Measurement of a 3rd party tdx-module's signer (SHA384 hash). If it is 0, the tdx-module is from Intel.
  - `tdx.quote.body.report_data`: String (hex for 64 bytes). Software defined ID for non-owner-defined configuration on the guest TD.
  - `tdx.quote.body.seam_attributes`: String (hex for 8 bytes). For tdx 1.0, must be `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`.
  - `tdx.quote.body.td_attributes`: String (hex for 8 bytes). TD's attributes. See `tdx.td_attributes` also.
  - `tdx.quote.body.mr_seam`: String (hex for 48 bytes). Measurement of the SEAM module.
  - `tdx.quote.body.tcb_svn`: String (hex for 16 bytes). TEE hardware tcb version, defined and meaningful to Intel. everytime firmware updates this field will change.
  - `tdx.quote.body.xfam`: String (hex for 8 bytes). TD's XFAM.
  - `tdx.quote.body.rtmr_0`: String (hex for 48 bytes). Runtime extendable measurement register 0.
  - `tdx.quote.body.rtmr_1`: String (hex for 48 bytes). Runtime extendable measurement register 1.
  - `tdx.quote.body.rtmr_2`: String (hex for 48 bytes). Runtime extendable measurement register 2.
  - `tdx.quote.body.rtmr_3`: String (hex for 48 bytes). Runtime extendable measurement register 3.
  - `tdx.quote.body.tee_tcb_svn2`: String (hex for 16 bytes). Array of TEE TCB SVNs (for TD preserving).
  - `tdx.quote.body.mr_servicetd`: String (hex for 48 bytes). If there is one or more bound or pre-bound service TDs, this field is the SHA384 hash of the `TDINFO`s of those service TDs bound. Else, this field is 0.
- `tdx.quote.type`: **Optional**. String (hex for 2 bytes). Indicating quote v5 type. `0200` means TDX 1.0 quote and `0300` means TDX 1.5 quote. Only quote format V5 contains this field.
- `tdx.quote.size`: **Optional**. String (hex for 4 bytes). Quote body length. Only quote format V5 contains this field.
- `tdx.td_attributes`: Object. Translated flags for `tdx.quote.body.td_attributes`.
  - `tdx.td_attributes.debug`: Boolean. Indicates whether the TD runs in TD debug mode (set to 1) or not (set to 0). In TD debug mode, the CPU state and private memory are accessible by the host VMM.
  - `tdx.td_attributes.key_locker`: Boolean. Indicates whether the TD is allowed to use Key Locker.
  - `tdx.td_attributes.perfmon`: Boolean. Indicates whether the TD is allowed to use Perfmon and PERF_METRICS capabilities.
  - `tdx.td_attributes.protection_keys`: Boolean. Indicates whether the TD is allowed to use Supervisor Protection Keys.
  - `tdx.td_attributes.septve_disable`: Boolean. Determines whether to disable EPT violation conversion to #VE on TD access of PENDING pages.
- `tdx.advisory_ids`: String List. Intel® Product Security Center Advisories.
- `tdx.collateral_expiration_status`: String. If none of the inputted collateral has expired as compared to the inputted `expiration_check_date`, it should be `"0"`.
- `tdx.earliest_expiration_date`: String. Date time value in RFC3339 format - The earliest nextUpdate value, or expiration date, among all collaterals.
- `tdx.earliest_issue_date`: String. Date time value in RFC3339 format - The earliest issueDate among all collaterals.
- `tdx.is_cached_keys`: Boolean. Indicates whether platform root keys are cached by SGX Registration Backend. _Note: this field is only provided if sgx_type is set to either "scalable" or "Scalable with Integrity"._
- `tdx.is_dynamic_platform`: Boolean. Indicates whether a platform can be extended with additional packages. _Note: this field is only provided if sgx_type is set to either "scalable" or "Scalable with Integrity"._
- `tdx.is_smt_enabled`: Boolean. Indicates whether a platform has SMT (simultaneous multithreading) enabled. _Note: this field is only provided if sgx_type is set to either "scalable" or "Scalable with Integrity"._
- `tdx.latest_issue_date`: String. Date time value in RFC3339 format - The latest issueDate value among all collaterals.
- `tdx.pck_crl_num`: Number. Indication of the freshness of the PCK cert used.
- `tdx.platform_instance_id`: **Optional**. String (hex for 16 bytes). Present only when certificates issued by PCK Platform CA; absent when certificates issued by PCK Processor CA. The certificates are PCK certs that link the platform's unique hardware identification to its TCB.
- `tdx.platform_provider_id`: String (hex for 16 bytes). The Platform Provisioning ID (PPID).
- `tdx.root_ca_crl_num`: Number. Indication of the freshness of the Root CA cert used.
- `tdx.root_key_id`: String (hex for 48 bytes). ID of the collateral’s root signer (hash of Root CA’s public key SHA-384).
- `tdx.sgx_type`: String. The type of memory used in SGX. Can be one of (`Standard`, `Scalable`, `Scalable with Integrity`).
- `tdx.tcb_date`: String. Date time value in RFC3339 format - Earliest date between tcbInfo and qeIdentity.
- `tdx.tcb_eval_num`: Number. Indication of the freshness of the reference values used.
- `tdx.tcb_status`: String. TCB Level Status can have any one of the following values:
  - `UpToDate` - The attesting platform is patched with the latest firmware and software and no known security advisories apply.
  - `SWHardeningNeeded` - The platform firmware and software are at the latest security patching level but there are vulnerabilities that can only be mitigated by software changes to the enclave or TD.
  - `ConfigurationNeeded` - The platform firmware and software are at the latest security patching level but there are platform hardware configurations required to mitigate vulnerabilities.
  - `ConfigurationAndSWHardeningNeeded` - This status is combination of `SWHardeningNeeded` and `ConfigurationNeeded`.
  - `OutOfDate` - The attesting platform software and/or firmware is not patched in accordance with the latest TCB Recovery (TCB-R).
  - `OutOfDateConfigurationNeeded` - The attesting platform is not patched in accordance with the latest TCB-R. Hardware configuration is needed.
  - `TDRelaunchAdvised` - The platform firmware and software are at the latest security patching level but the TD was launched prior to the application of new TDX TCB components using a TD Preserving update. Re-launching the TD will change the attestation result.
  - `TDRelaunchAdvisedConfigurationNeeded` - The platform firmware and software are at the latest security patching level but there are platform hardware configurations that may expose the TD to vulnerabilities. Re-launching the TD will change the attestation result.

## Intel SGX

- `sgx.header`: Object. SGX quote header.
  - `sgx.header.version`: String (hex for 2 bytes). The version this quote structure.
  - `sgx.header.att_key_type`: String (hex for 2 bytes). sgx_attestation_algorithm_id_t.  Describes the type of signature.
  - `sgx.header.att_key_data_0`: String (hex for 4 bytes). Type of Trusted Execution Environment. Always `00000000` for SGX.
  - `sgx.header.qe_svn`: String (hex for 2 bytes). The ISV_SVN of the Quoting Enclave when the quote was generated.
  - `sgx.header.pce_svn`: String (hex for 2 bytes). The ISV_SVN of the PCE when the quote was generated.
  - `sgx.header.vendor_id`: String (hex for 16 bytes). Unique identifier of QE Vendor.
  - `sgx.header.user_data`: String (hex for 20 bytes).  Custom attestation key owner data.
- `sgx.body`: Object. SGX quote body.
  - `sgx.body.cpu_svn`: String (hex for 16 bytes). Security Version of the CPU.
  - `sgx.body.misc_select`:  String (hex for 4 bytes). Which fields defined in SSA.MISC.
  - `sgx.body.reserved1`: String (hex for 12 bytes). Reserved.
  - `sgx.body.isv_ext_prod_id`:  String (hex for 16 bytes). ISV assigned Extended Product ID.
  - `sgx.body.attributes.flags`: String (hex for 8 bytes). special Capabilities the Enclave possess.
  - `sgx.body.attributes.xfrm`: String (hex for 8 bytes). XFRM the Enclave possess
  - `sgx.body.mr_enclave`: String (hex for 32 bytes). The value of the enclave's ENCLAVE measurement.
  - `sgx.body.reserved2`: String (hex for 32 bytes). Reserved.
  - `sgx.body.mr_signer`: String (hex for 32 bytes). The value of the enclave's SIGNER measurement.
  - `sgx.body.reserved3`: String (hex for 32 bytes). Reserved.
  - `sgx.body.config_id`: String (hex for 64 bytes). CONFIGID of the enclave.
  - `sgx.body.isv_prod_id`: String (hex for 2 bytes). Product ID of the Enclave.
  - `sgx.body.isv_svn`: String (hex for 2 bytes). Security Version of the Enclave.
  - `sgx.body.config_svn`: String (hex for 2 bytes). CONFIGSVN of the enclave.
  - `sgx.body.reserved4`: String (hex for 42 bytes). Reserved.
  - `sgx.body.isv_family_id`: String (hex for 16 bytes). ISV assigned Family ID.
  - `sgx.body.report_data`: String (hex for 64 bytes). Data provided by the user.
- `sgx.platform_instance_id`: **Optional**. String (hex for 16 bytes). Present only when certificates issued by PCK Platform CA; absent when certificates issued by PCK Processor CA. The certificates are PCK certs that link the platform's unique hardware identification to its TCB.

## Azure TDX Confidential VM (az-tdx-vtpm)

- `["az-tdx-vtpm"].*`: claims inherit the fields from the [TDX layout](#intel-tdx).
- `["az-tdx-vtpm"].tpm`: Object. TPM PCR values.
  - `["az-tdx-vtpm"].tpm.pcr{01,..,n}`: String (hex). SHA256 PCR registers for the TEE's vTPM quote.
  - `["az-tdx-vtpm"].tpm.init_data`: **Optional**. String (hex). The register used as initdata digest (PCR 8).

> [!NOTE]
> The TD Report and TD Quote are fetched during early boot in this TEE. Kernel, Initrd and rootfs are measured into the vTPM's registers.

## Azure SEV-SNP Confidential VM (az-snp-vtpm)

- `["az-snp-vtpm"].*`: claims inherit the fields from the [SEV-SNP](#amd-sev-snp) layout.
- `["az-tdx-vtpm"].tpm`: Object. TPM PCR values.
  - `["az-tdx-vtpm"].tpm.pcr{01,..,n}`: String (hex). SHA256 PCR registers for the TEE's vTPM quote.
  - `["az-tdx-vtpm"].tpm.init_data`: **Optional**. String (hex). The register used as initdata digest (PCR 8).

Note: The TD Report and TD Quote are fetched during early boot in this TEE. Kernel, Initrd and rootfs are measured into the vTPM's registers.

## IBM Secure Execution for Linux (SEL)

- `se.version`: Number. The version this quote structure.
- `se.cuid`: String (hex for 16 bytes). The unique ID of the attested guest (configuration uniqe ID).
- `se.tag`: String (hex for 16 bytes). SE header tag.
- `se.image_phkh`: String (hex). SE image public host key hash
- `se.attestation_phkh`: String (hex). SE attestation public host key hash
- `se.report_data`: String (hex for 64 bytes). Data provided by the user.

## Arm CCA

CCA claims are grouped into `cca.realm` and `cca.platform`:

- `cca.realm`: Object. CCA Realm token claims.
  - `cca.realm.cca_realm_personalization_value`: String (Base64 Standard). Per Realm defined personalized value.
  - `cca.realm.cca_realm_initial_measurement`: String (Base64 Standard). The initial measurement of the Realm.
  - `cca.realm.cca_realm_extensible_measurements`: String list. The extensible measurements of the Realm.
    - `cca.realm.cca_realm_extensible_measurements[i]`: String (Base64 Standard). The i-th extensible measurement of the Realm.
  - `cca.realm.cca_realm_hash_algo_id`: String (Base64 Standard). RMI hash algorithm.
  - `cca.realm.cca_realm_challenge`: String (Base64 Standard). The challenge to do the attestation.
- `cca.platform`: Object. CCA Platform token claims.
  - `cca.platform.cca_platform_instance_id`: String (Base64 Standard). Hardware platform instance ID.
  - `cca.platform.cca_platform_implementation_id`: String (Base64 Standard). Hardware implementation ID.
- `cca.report_data`: String (Base64 Standard). report data derived from realm challenge
- `cca.init_data`: String (Base64 Standard). init data digest field, the same as `cca.realm.cca_realm_personalization_value`.

## NVIDIA

The local verifier only supports Hopper and returns the following claims.

- `arch`: Device architecture. Only `Hopper` is supported
- `measurements`: List of measurements and its respective index
- `uuid`: Device UUID
- `config.board_id`: Board ID
- `config.chip_sku`: Chip SKU (Stock Keeping Unit)
- `config.chip_sku_mod`: Chip SKU mod
- `config.cpr_info`: Compute Protected Region info
- `config.driver_version`: NVIDIA driver version
- `config.fwid`: Firmware ID. Found in the report and the signing certificate
- `config.gpu_info`: GPU information
- `config.measurement_count`: One measurement_count for each entry in `measurements`. Each measurement_count indicates how many times the respective measurement was extended to get to its current value
- `config.nvdec0_status`: NVIDIA decoder status
- `config.project`: Project
- `config.project_sku`: Project SKU
- `config.project_sku_mod`: Project SKU mod
- `config.protected_pcie_status`: Protected PCIe status
- `config.vbios_version`: Device VBIOS version

The remote verifier exports the claims that come from NRAS, which are listed [here](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html).
Claims version 3 is used. The `x-nvidia-overall-att-result` from the overall claims is included
along with the full set of detached claims.

## NVIDIA DPU (DICE)

The NVIDIA DPU verifier validates attestation evidence using the TCG DICE
(Device Identifier Composition Engine) certificate chain from BlueField DPUs.

- `nvidia-dpu.device_serial`: Device serial number from DeviceID certificate
- `nvidia-dpu.device_class`: Device class identifier (e.g. "bluefield3") from Subject CN
- `nvidia-dpu.firmware_layers_count`: Number of FWID entries in TCG DICE TcbInfo extension
- `nvidia-dpu.accumulated_fwid`: SHA-384 hash of concatenated firmware layer digests (hex-encoded)
- `nvidia-dpu.alias_timestamp`: Alias certificate issuance timestamp (unix seconds)

Note: `FirmwareLayer.name` and `FirmwareLayer.version` are informational only —
not covered by TBS nor report_data_signature, thus not integrity-protected.

## AMD SEV-SNP

- `snp.chip_id`: Unique identifier for platform instance (field may be zero if masked)
- `snp.measurement` Launch Digest covering initial guest memory
- `snp.platform_smt_enabled`:  Whether Simultaneous Multithreading is enabled on the system
- `snp.platform_tsme_enabled`: Whether Transparent SME is enabled on the system
- `snp.policy_abi_major`: Minimum ABI major version allowed for guest
- `snp.policy_abi_minor`: Minimum ABI minor version allowed for guest
- `snp.policy_debug_allowed`: Whether SNP debug features are allowed for guest
- `snp.policy_migrate_ma`: Whether migration agent can be connected to guest
- `snp.policy_single_socket`: Whether guest can be activated only on one socket
- `snp.policy_smt_allowed`: Whether guest can run on a system with SMT enabled
- `snp.reported_tcb_bootloader`: Reported SVN of ASP bootloader
- `snp.reported_tcb_microcode`: Reported microcode version
- `snp.reported_tcb_snp`: Reported SVN of SNP Firmware
- `snp.reported_tcb_tee`: Reported SVN of ASP OS

The claims map only includes the reported TCB version.
An SEV-SNP Attestation Report contains four sets of TCB version information.
Often all four values are the same, but sometimes the reported TCB might lag
behind the true firmware version. This is done to minimize churn of policies
and certificates while the provider updates to provisional firmware.
The actual firmware must always be newer than or equal to the reported TCB.
Generally, policies should be evaluated against the reported TCB.

## TPM

- `tpm.init_data`: String (hex). SHA256 PCR[08] value (hex)
- `tpm.report_data`: String (hex). nonce from quote (hex)
- `tpm.pcr00` ... `tpm.pcr23`: String (hex). SHA256 PCR values (hex; index count depends on quote)
- `tpm.ak_public`: String (Base64 Standard). AK (Attestation Key) public key in PEM format (base64-encoded DER)

## Hygon DCU

Each attestation report produces one set of claims under `hygondcu`. Multiple DCUs are evaluated separately (EAR token submods `dcu0`, `dcu1`, ... in evidence list order):

- `hygondcu.body`: Object. The report body of Hygon DCU.
  - `hygondcu.body.version`: Number. Firmware version.
  - `hygondcu.body.chip_id`: String (hex for 16 bytes). DCU chip ID.
  - `hygondcu.body.user_data`: String (hex for 64 bytes). The challenge data for the attestation.
  - `hygondcu.body.measure`: String (hex for 32 bytes). measurement of the firmware.
  - `hygondcu.body.reserved`: String (hex for 128 bytes). Reserved field.
  - `hygondcu.body.sig_usage`: String (hex). The usage of the signature.
  - `hygondcu.body.sig_algo`: String (hex). The algorithm of the signature.
- `hygondcu.report_data`: String (hex for 64 bytes). Same value as `body.user_data`.

## Hygon CSV

- `csv.version`: String. The version of the quote. Now only `1` and `2` is legal.
- `csv.policy`: Object. CSV Guest policy.
  - `csv.policy.nodbg`: Number. Debugging of the guest is disallowed.
  - `csv.policy.noks`: Number. Sharing keys with other guests is disallowed.
  - `csv.policy.es`: Number. CSV2 is required when set.
  - `csv.policy.nosend`: Number. Sending the guest to another platform is disallowed.
  - `csv.policy.domain`: Number. The guest must not be transmitted to another platform that is not in the domain.
  - `csv.policy.csv`: Number. The guest must not be transmitted to another platform that is not CSV capable.
  - `csv.policy.csv3`: Number. CSV3 is required.
  - `csv.policy.asid_reuse`: Number. Sharing asids with other guests owned by same user is allowed.
  - `csv.policy.hsk_version`: Number. The guest must not be transmitted to another platform with a lower HSK version.
  - `csv.policy.cek_version`: Number. The guest must not be transmitted to another platform with a lower CEK version.
  - `csv.policy.api_major`: Number. The guest must not be transmitted to another platform with a lower platform version.
  - `csv.policy.api_minor`: Number. The guest must not be transmitted to another platform with a lower platform version.
- `csv.user_pubkey_digest`: String (hex for 32 bytes). Pubkey digest of the session used to secure communication between user/hypervisor and PSP.
- `csv.vm_id`: String (hex for 16 bytes). The identifier of the VM custommized by the guest owner.
- `csv.vm_version`: String (hex for 16 bytes). The version info of the VM customized by the guest owner.
- `csv.report_data`: String (hex for 64 bytes). The challenge data for the attestation.
- `csv.mnonce`: String (hex for 16 bytes). The random nonce generated by user to protect struct TeeInfoSigner.
- `csv.measure`: String (hex for 32 bytes). The launch digest of the VM.
- `csv.anonce`:  String (hex for 4 bytes). The signature for the fields above.
- `csv.sig_usage`:  String (hex for 4 bytes). The usage of the signature.
- `csv.sig_algo`:  String (hex for 4 bytes). The algorithm of the signature.
- `csv.serial_number`: String. CPU serial number.

If the quote version is `2`, it will have the following extra fiels.

- `csv.build`: Number. The version of the firmware's build.
- `csv.rtmr_version`: Number. The version of the VM's rtmr.
- `csv.reserved0`: String (hex for 14 bytes). A reserved field, for future use.
- `csv.rtmr0`: String (hex for 32 bytes). The rtmr register 0, it's always equals to @measure field.
- `csv.rtmr1`: String (hex for 32 bytes). The rtmr register 1.
- `csv.rtmr2`: String (hex for 32 bytes). The rtmr register 2.
- `csv.rtmr3`: String (hex for 32 bytes). The rtmr register 3.
- `csv.rtmr4`: String (hex for 32 bytes). The rtmr register 4.
- `csv.reserved1`: String (hex for 656 bytes). A reserved field, for future use.

## Appendix

### UEFI Eventlog

#### UEFI Eventlog Claims

UEFI event log is a list of event entries. Different event entry can be indexed by `[]` operator.
Each entry contains below fields:

- `uefi_event_logs[i]`: Object. The i-th eventlog entry.
- `uefi_event_logs[i].index`: Number. Measurement registry index.
- `uefi_event_logs[i].event_type`: String. See [Event Types](#event-types) section.
- `uefi_event_logs[i].digest_matches_event`: Boolean. Result of comparison between digest array and event data. List of events (`EV_EFI_ACTION`, `EV_SEPARATOR`, `EV_EFI_VARIABLE_AUTHORITY`, `EV_EFI_GPT_EVENT`, `EV_EVENT_TAG`, `EV_EFI_VARIABLE_DRIVER_CONFIG`) which can be checked in policy against being protected.
- `uefi_event_logs[i].digests[j]`: Object. The j-th digest array of the event.
  - `uefi_event_logs[i].digests[j].alg`: Hash algorithm (`RSA`, `TDES`, `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`, `SM3`).
  - `uefi_event_logs[i].digests[j].digest`: String (hex). Digest value calculated for hash defined in previous field.
- `uefi_event_logs[i].event`: String (Base64 Standard). Raw event data.
- `uefi_event_logs[i].details`: Object. List of attributes parsed from event data.
  - `uefi_event_logs[i].details.string`: **Optional**. String. Parsed UTF-8 value.
  - `uefi_event_logs[i].details.unicode_name`: **Optional**. String. Parsed Unicode name of the measurement event.
  - `uefi_event_logs[i].details.unicode_name_length`: **Optional**. Number. Unicode name length of the measurement event.
  - `uefi_event_logs[i].details.variable_data`: **Optional**. String (Base64 Standard). Event variable data.
  - `uefi_event_logs[i].details.variable_data_length`: **Optional**. Number. Length of the variable data.
  - `uefi_event_logs[i].details.variable_name`: **Optional**. String. Variable name.
  - `uefi_event_logs[i].details.device_paths`: **Optional**. String list. List of parsed device paths.
    - `uefi_event_logs[i].details.device_paths[j]`: String. The j-th parsed device path.
  - `uefi_event_logs[i].details.data`: **Optional**. Additional information processed from the event. Now it's only used in `EV_EVENT_TAG` event type for [AAEL](../../kbs/docs/confidential-containers-eventlog.md) entry.
    - `uefi_event_logs[i].details.data.domain`: String. The AAEL event domain name.
    - `uefi_event_logs[i].details.data.operation`: String. The AAEL event operation name.
    - `uefi_event_logs[i].details.data.content`: String or Object. The AAEL event content. AS will try to parse the original content field as JSON format. If succeed, the `content` field here will be a JSON Object. If failed, it will be a JSON String.

#### Event Types

Name of the measurement event from [TCG PC Client Platform Firmware Profile Specification Section 10.4.1](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v22_02dec2020.pdf). Now we have the following event types
- `EV_PREBOOT_CERT`
- `EV_POST_CODE`
- `EV_UNUSED`
- `EV_NO_ACTION`
- `EV_SEPARATOR`
- `EV_ACTION`
- `EV_EVENT_TAG`
- `EV_S_CRTM_CONTENTS`
- `EV_S_CRTM_VERSION`
- `EV_CPU_MICROCODE`
- `EV_PLATFORM_CONFIG_FLAGS`
- `EV_TABLE_OF_DEVICES`
- `EV_COMPACT_HASH`
- `EV_IPL`
- `EV_IPL_PARTITION_DATA`
- `EV_NONHOST_CODE`
- `EV_NONHOST_CONFIG`
- `EV_NONHOST_INFO`
- `EV_OMIT_BOOT_DEVICE_EVENTS`
- `EV_EFI_EVENT_BASE`
- `EV_EFI_VARIABLE_DRIVER_CONFIG`
- `EV_EFI_VARIABLE_BOOT`
- `EV_EFI_BOOT_SERVICES_APPLICATION`
- `EV_EFI_BOOT_SERVICES_DRIVER`
- `EV_EFI_RUNTIME_SERVICES_DRIVER`
- `EV_EFI_GPT_EVENT`
- `EV_EFI_ACTION`
- `EV_EFI_PLATFORM_FIRMWARE_BLOB`
- `EV_EFI_HANDOFF_TABLES`
- `EV_EFI_PLATFORM_FIRMWARE_BLOB2`
- `EV_EFI_HANDOFF_TABLES2`
- `EV_EFI_VARIABLE_BOOT2`
- `EV_EFI_HCRTM_EVENT`
- `EV_EFI_VARIABLE_AUTHORITY`
- `EV_EFI_SPDM_FIRMWARE_BLOB`
- `EV_EFI_SPDM_FIRMWARE_CONFIG`
