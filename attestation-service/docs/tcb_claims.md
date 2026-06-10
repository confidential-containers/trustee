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
- `sample.svn`: version of the quote.
- `sample.report_data`: report data when generating the evidence.
- `sample.init_data`: init data hash.
- `sample.launch_digest`: dummy launch digest used for policy testing.
- `sample.platform_version.major`: sample platform major version.
- `sample.platform_version.minor`: sample platform minor version.
- `sample.debug`: sample debug flag (always false in sample verifier).

## Sample Device

**This is only a test verifier for device-class attestation**.
- `sampledevice.svn`: version of the quote-like sample evidence.

## Intel TDX

The following fields are optional. Whether they appear depends on whether there is CCEL.
- `tdx.uefi_event_logs` list of objects parsed from ccel log file. Each event can be accessed using fields described below.

UEFI event log entry contains below fields:
- `tdx.uefi_event_logs[0].index`: Measurement registry index.
- `tdx.uefi_event_logs[0].event_type`: Name of the measurement event from [TCG PC Client Platform Firmware Profile Specification Section 10.4.1](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v22_02dec2020.pdf).
- `tdx.uefi_event_logs[0].digest_matches_event`: Boolean result of comparison between digest array and event data. List of events (`EV_EFI_ACTION`, `EV_SEPARATOR`, `EV_EFI_VARIABLE_AUTHORITY`, `EV_EFI_GPT_EVENT`, `EV_EVENT_TAG`, `EV_EFI_VARIABLE_DRIVER_CONFIG`) which can be checked in policy against being protected.
- `tdx.uefi_event_logs[0].digests[0].alg`: Hash algorithm (`RSA`, `TDES`, `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`).
- `tdx.uefi_event_logs[0].digests[0].digest`: Digest value calculated for hash defined in previous field.
- `tdx.uefi_event_logs[0].event`: Base64 encoded raw event data.
- `tdx.uefi_event_logs[0].details`: List of attributes parsed from event data. All details properties are optional.
- `tdx.uefi_event_logs[0].details.string`: Parsed UTF-8 value.
- `tdx.uefi_event_logs[0].details.unicode_name`: Parsed Unicode name of the measurement event.
- `tdx.uefi_event_logs[0].details.unicode_name_length`: Unicode name length of the measurement event.
- `tdx.uefi_event_logs[0].details.variable_data`: Base64 encoded event variable data.
- `tdx.uefi_event_logs[0].details.variable_data_length`: Length of the variable data.
- `tdx.uefi_event_logs[0].details.variable_name`: Variable name.
- `tdx.uefi_event_logs[0].details.device_paths`: List of parsed device paths.
- `tdx.uefi_event_logs[0].details.data`: Additional information processed from the event.

The following fields always exist.
- `tdx.quote.header.version`: The quote format version. Now supports 4 and 5.
- `tdx.quote.header.att_key_type`: Enum of the algorithm used in signature.
- `tdx.quote.header.tee_type`: TDX is always 0x81.
- `tdx.quote.header.reserved`: Reserved.
- `tdx.quote.header.vendor_id`: UID of QE Vendor. QE is a signed software component inside TEE to help to generate tdx quote.
- `tdx.quote.header.user_data`: Custom attestation key owner data.
- `tdx.quote.body.mr_config_id`: Software-defined ID for non-owner-defined configuration of the guest TD – e.g., run-time or OS configuration.
- `tdx.quote.body.mr_owner`: Software-defined ID for the guest TD’s owner.
- `tdx.quote.body.mr_owner_config`: Software-defined ID for owner-defined configuration of the guest TD – e.g., specific to the workload rather than the run-time or OS.
- `tdx.quote.body.mr_td`: Measurement of the initial contents of the TD.
- `tdx.quote.body.mrsigner_seam`: Measurement of a 3rd party tdx-module's signer (SHA384 hash). If it is 0, the tdx-module is from Intel.
- `tdx.quote.body.report_data`: Software defined ID for non-owner-defined configuration on the guest TD.
- `tdx.quote.body.seam_attributes`: For tdx1.0, must be 0.
- `tdx.quote.body.td_attributes`: TD's attributes.
- `tdx.quote.body.mr_seam`: Measurement of the SEAM module.
- `tdx.quote.body.tcb_svn`: TEE hardware tcb version, defined and meaningful to Intel. everytime firmware updates this field will change.
- `tdx.quote.body.xfam`: TD's XFAM.
- `tdx.quote.body.rtmr_0`: Runtime extendable measurement register 0.
- `tdx.quote.body.rtmr_1`: Runtime extendable measurement register 1.
- `tdx.quote.body.rtmr_2`: Runtime extendable measurement register 2.
- `tdx.quote.body.rtmr_3`: Runtime extendable measurement register 3.
- `tdx.quote.type`: Indicating quote v5 type. 2 means TDX 1.0 quote and 3 means TDX 1.5 quote. Only quote format V5 contains this field.
- `tdx.quote.size`: Quote body length. Only quote format V5 contains this field.
- `tdx.quote.body.tee_tcb_svn2`: Array of TEE TCB SVNs (for TD preserving).
- `tdx.quote.body.mr_servicetd`: If there is one or more bound or pre-bound service TDs, this field is the SHA384 hash of the `TDINFO`s of those service TDs bound. Else, this field is 0.
- `tdx.td_attributes.debug`: A boolean value that indicates whether the TD runs in TD debug mode (set to 1) or not (set to 0). In TD debug mode, the CPU state and private memory are accessible by the host VMM.
- `tdx.td_attributes.key_locker`: A boolean value that indicates whether the TD is allowed to use Key Locker.
- `tdx.td_attributes.perfmon`: A boolean value that indicates whether the TD is allowed to use Perfmon and PERF_METRICS capabilities.
- `tdx.td_attributes.protection_keys`: A boolean value that indicates whether the TD is allowed to use Supervisor Protection Keys.
- `tdx.td_attributes.septve_disable`: A boolean value that determines whether to disable EPT violation conversion to #VE on TD access of PENDING pages.
- `tdx.advisory_ids`: List of Intel® Product Security Center Advisories.
- `tdx.collateral_expiration_status`: Expected 0, if none of the inputted collateral has expired as compared to the inputted expiration_check_date.
- `tdx.earliest_expiration_date`: Date time value in RFC3339 format - The earliest nextUpdate value, or expiration date, among all collaterals.
- `tdx.earliest_issue_date`: Date time value in RFC3339 format - The earliest issueDate among all collaterals.
- `tdx.is_cached_keys`: A boolean value that indicates whether platform root keys are cached by SGX Registration Backend. _Note: this field is only provided if sgx_type is set to either "scalable" or "Scalable with Integrity"._
- `tdx.is_dynamic_platform`: A boolean value that indicates whether a platform can be extended with additional packages. _Note: this field is only provided if sgx_type is set to either "scalable" or "Scalable with Integrity"._
- `tdx.is_smt_enabled`: A boolean value that indicates whether a platform has SMT (simultaneous multithreading) enabled. _Note: this field is only provided if sgx_type is set to either "scalable" or "Scalable with Integrity"._
- `tdx.latest_issue_date`: Date time value in RFC3339 format - The latest issueDate value among all collaterals.
- `tdx.pck_crl_num`: Indication of the freshness of the PCK cert used.
- `tdx.platform_provider_id`: The Platform Provisioning ID.
- `tdx.root_ca_crl_num`: Indication of the freshness of the Root CA cert used.
- `tdx.root_key_id`: ID of the collateral’s root signer (hash of Root CA’s public key SHA-384).
- `tdx.sgx_type`: The type of memory used in SGX. Can be one of (`Standard`, `Scalable`, `Scalable with Integrity`).
- `tdx.tcb_date`: Date time value in RFC3339 format - Earliest date between tcbInfo and qeIdentity.
- `tdx.tcb_eval_num`: Indication of the freshness of the reference values used.
- `tdx.tcb_status`: TCB Level Status can have any one of the following values:
  - `UpToDate` - The attesting platform is patched with the latest firmware and software and no known security advisories apply.
  - `SWHardeningNeeded` - The platform firmware and software are at the latest security patching level but there are vulnerabilities that can only be mitigated by software changes to the enclave or TD.
  - `ConfigurationNeeded` - The platform firmware and software are at the latest security patching level but there are platform hardware configurations required to mitigate vulnerabilities.
  - `ConfigurationAndSWHardeningNeeded` - This status is combination of `SWHardeningNeeded` and `ConfigurationNeeded`.
  - `OutOfDate` - The attesting platform software and/or firmware is not patched in accordance with the latest TCB Recovery (TCB-R).
  - `OutOfDateConfigurationNeeded` - The attesting platform is not patched in accordance with the latest TCB-R. Hardware configuration is needed.
  - `TDRelaunchAdvised` - The platform firmware and software are at the latest security patching level but the TD was launched prior to the application of new TDX TCB components using a TD Preserving update. Re-launching the TD will change the attestation result.
  - `TDRelaunchAdvisedConfigurationNeeded` - The platform firmware and software are at the latest security patching level but there are platform hardware configurations that may expose the TD to vulnerabilities. Re-launching the TD will change the attestation result.

## Intel SGX

- `sgx.header.version`: The version this quote structure.
- `sgx.header.att_key_type`: sgx_attestation_algorithm_id_t.  Describes the type of signature.
- `sgx.header.att_key_data_0`: Optionally stores additional data associated with the att_key_type.
- `sgx.header.qe_svn`: The ISV_SVN of the Quoting Enclave when the quote was generated.
- `sgx.header.pce_svn`: The ISV_SVN of the PCE when the quote was generated.
- `sgx.header.vendor_id`: Unique identifier of QE Vendor.
- `sgx.header.user_data`: Custom attestation key owner data.
- `sgx.body.cpu_svn`: Security Version of the CPU.
- `sgx.body.misc_select`:  Which fields defined in SSA.MISC.
- `sgx.body.reserved1`: Reserved.
- `sgx.body.isv_ext_prod_id`:  ISV assigned Extended Product ID.
- `sgx.body.attributes.flags`: special Capabilities the Enclave possess.
- `sgx.body.attributes.xfrm`: XFRM the Enclave possess
- `sgx.body.mr_enclave`: The value of the enclave's ENCLAVE measurement.
- `sgx.body.reserved2`: Reserved.
- `sgx.body.mr_signer`: The value of the enclave's SIGNER measurement.
- `sgx.body.reserved3`: Reserved.
- `sgx.body.config_id`: CONFIGID of the enclave.
- `sgx.body.isv_prod_id`: Product ID of the Enclave.
- `sgx.body.isv_svn`: Security Version of the Enclave.
- `sgx.body.config_svn`: CONFIGSVN of the enclave.
- `sgx.body.reserved4`: Reserved.
- `sgx.body.isv_family_id`: ISV assigned Family ID.
- `sgx.body.report_data`: Data provided by the user.

## Azure TDX Confidential VM (az-tdx-vtpm)

Under the top-level key `az-tdx-vtpm`, claims inherit the fields from the TDX layout with an additional `tpm` hierarchy in which the TEE's PCR values are stored:

- `["az-tdx-vtpm"].tpm.pcr{01,..,n}`: SHA256 PCR registers for the TEE's vTPM quote.

Note: The TD Report and TD Quote are fetched during early boot in this TEE. Kernel, Initrd and rootfs are measured into the vTPM's registers.

## Azure SEV-SNP Confidential VM (az-snp-vtpm)

Under the top-level key `az-snp-vtpm`, claims inherit the fields from the SEV-SNP layout with an additional `tpm` hierarchy in which the TEE's PCR values are stored:

- `["az-snp-vtpm"].tpm.pcr{01,..,n}`: SHA256 PCR registers for the TEE's vTPM quote.

Note: The TD Report and TD Quote are fetched during early boot in this TEE. Kernel, Initrd and rootfs are measured into the vTPM's registers.

## IBM Secure Execution for Linux (SEL)
- `se.version`: The version this quote structure.
- `se.cuid`: The unique ID of the attested guest (configuration uniqe ID).
- `se.tag`: SE header tag.
- `se.image_phkh`: SE image public host key hash
- `se.attestation_phkh`: SE attestation public host key hash
- `se.user_data`: Optional custom attestation owner data collected on guest (e.g., `runtime_data_digest`)

## Arm CCA

CCA claims are grouped into `cca.realm` and `cca.platform`:

- `cca.realm.cca_realm_personalization_value`: Per Realm defined personalized value.
- `cca.realm.cca_realm_initial_measurement`: The initial measurement of the Realm.
- `cca.realm.cca_realm_extensible_measurements`: The extensible measurements of the Realm.
- `cca.realm.cca_realm_hash_algo_id`: RMI hash algorithm.
- `cca.realm.cca_realm_challenge`: The challenge to do the attestation.
- `cca.platform.cca_platform_instance_id`: Hardware platform instance ID.
- `cca.platform.cca_platform_implementation_id`: Hardware implementation ID.
- `cca.report_data`: report data derived from realm challenge
- `cca.init_data`: init data derived from realm personalization value

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

## AMD SEV-SNP


- `snp.generation`: string. Processor generation derived from the attestation report. One of `milan` (3rd Gen EPYC), `genoa` (4th Gen EPYC), or `turin` (5th Gen EPYC).

### Guest policy (`snp.evidence.policy`)

The guest policy is set by the guest owner at launch and cannot be changed for the lifetime of the guest.

- `snp.evidence.policy.abi_major`: u64. Minimum SNP firmware ABI major version required for this guest.
- `snp.evidence.policy.abi_minor`: u64. Minimum SNP firmware ABI minor version required for this guest.
- `snp.evidence.policy.smt_allowed`: Boolean. Whether the guest may run on a host with SMT enabled.
- `snp.evidence.policy.migrate_ma_allowed`: Boolean. Whether the guest may be associated with a migration agent.
- `snp.evidence.policy.debug_allowed`: Boolean. Whether SNP debug features are allowed for the guest.
- `snp.evidence.policy.single_socket_required`: Boolean. Whether the guest may be activated on multiple sockets. 
- `snp.evidence.policy.cxl_allowed`: Boolean. Whether CXL may be populated with devices or memory.
- `snp.evidence.policy.mem_aes_256_xts`: Boolean. Memory encryption mode requirement. `false`: AES-128-XEX or AES-256-XTS is allowed; `true`: AES-256-XTS is required.
- `snp.evidence.policy.rapl_dis`: Boolean. Running Average Power Limit (RAPL) requirement.
- `snp.evidence.policy.ciphertext_hiding`: Boolean. Ciphertext hiding requirement.
- `snp.evidence.policy.page_swap_disabled`: Boolean. Guest access to page-move/swap commands. `false`: SNP page-move/swap commands are allowed; `true`: guest access to `SNP_PAGE_MOVE`, `SNP_SWAP_OUT`, and `SNP_SWAP_IN` is disabled.

### Platform info (`snp.evidence.plat_info`)

- `snp.evidence.plat_info.smt_enabled`: Boolean. Whether Simultaneous Multithreading is enabled on the host.
- `snp.evidence.plat_info.tsme_enabled`: Boolean. Whether Transparent SME is enabled on the host.
- `snp.evidence.plat_info.ecc_enabled`: Boolean. Whether the platform is currently using ECC memory.
- `snp.evidence.plat_info.rapl_disabled`: Boolean. Whether the RAPL feature is disabled on the platform.
- `snp.evidence.plat_info.ciphertext_hiding_enabled`: Boolean. Whether ciphertext hiding is enabled on the platform.
- `snp.evidence.plat_info.alias_check_complete`: Boolean. Whether alias detection has completed since the last system reset with no aliasing addresses found.
- `snp.evidence.plat_info.tio_enabled`: Boolean. Whether SEV-TIO is enabled on the platform.

### Key info (`snp.evidence.key_info`)

- `snp.evidence.key_info.author_key_en`: Boolean. Whether the author key digest is present in `author_key_digest`. `true`: digest is present; `false`: digest is zero.
- `snp.evidence.key_info.mask_chip_key`: Boolean. Whether the report signature is masked. `false`: firmware signs with VCEK or VLEK; `true`: the signature field is zeroed instead of signing.
- `snp.evidence.key_info.signing_key`: u32. Key used to sign this report. `0`: VCEK; `1`: VLEK; `7`: none (unsigned report).

### TCB versions

Four TCB sets are exposed. Each is an object with the subfields below. The same subfields and types exist on `current_tcb`, `reported_tcb`, `committed_tcb`, and `launch_tcb`.

- `snp.evidence.current_tcb`: object. Current platform TCB at report generation time.
- `snp.evidence.reported_tcb`: object. TCB version used to derive the VCEK/VLEK that signed this report. **Policies should generally evaluate against this set.**
- `snp.evidence.committed_tcb`: object. Committed TCB version.
- `snp.evidence.launch_tcb`: object. Platform TCB at guest launch or import time.

Each TCB object contains the following fields (SVN / patch level):

- `fmc`: u8 | null. FMC firmware SVN. Present on Turin (`generation` = `turin`); `null` on Milan and Genoa.
- `bootloader`: u8. PSP bootloader SVN.
- `tee`: u8. PSP operating-system SVN.
- `snp`: u8. SNP firmware SVN.
- `microcode`: u8. Lowest current microcode patch level across all cores.

Often all four TCB values are the same, but the reported TCB may lag behind the true firmware version to minimize churn of policies and certificates while the provider updates to provisional firmware. The actual firmware must always be newer than or equal to the reported TCB.

Firmware version objects:

- `snp.evidence.current`: object. Current SNP firmware version.
- `snp.evidence.current.major`: u8. Major version component.
- `snp.evidence.current.minor`: u8. Minor version component.
- `snp.evidence.current.build`: u8. Build version component.
- `snp.evidence.committed`: object. Committed SNP firmware version.
- `snp.evidence.committed.major`: u8. Major version component.
- `snp.evidence.committed.minor`: u8. Minor version component.
- `snp.evidence.committed.build`: u8. Build version component.

### Measurements and identifiers

- `snp.evidence.version`: u32. Attestation report format version. Supported values are 3 through 5.
- `snp.evidence.guest_svn`: u32. Guest security version number provided at launch.
- `snp.evidence.family_id`: string (hex). Family ID provided at launch.
- `snp.evidence.image_id`: string (hex). Image ID provided at launch.
- `snp.evidence.vmpl`: u32. Requested VMPL for the attestation report. Guest attestation expects `0`.
- `snp.evidence.sig_algo`: u32. Signature algorithm identifier. `1`: ECDSA P-384 with SHA-384.
- `snp.evidence.measurement`: string (hex). Launch digest covering initial guest memory (48 bytes).
- `snp.evidence.report_data`: string (hex). Guest-provided report data from the attestation report (64 bytes). Also available at the policy root as `report_data`.
- `snp.evidence.host_data`: string (hex). Hypervisor-provided host data from launch (32 bytes). Also available at the policy root as `init_data`.
- `snp.evidence.id_key_digest`: string (hex). SHA-384 digest of the ID public key that signed the ID block.
- `snp.evidence.author_key_digest`: string (hex). SHA-384 digest of the author public key that certified the ID key. Zero when `key_info.author_key_en` is `false`.
- `snp.evidence.report_id`: string (hex). Report ID of this guest.
- `snp.evidence.report_id_ma`: string (hex). Report ID of this guest's migration agent, if applicable.
- `snp.evidence.chip_id`: string (hex). Unique chip identifier (64 bytes). Zero when `key_info.mask_chip_key` is `true`.
- `snp.evidence.cpu_id_fam_id`: u8 | null. CPUID family ID (combined extended family and family). Present in report version 3+; `null` on older reports.
- `snp.evidence.cpu_id_mod_id`: u8 | null. CPUID model ID (combined extended model and model). Present in report version 3+; `null` on older reports.
- `snp.evidence.cpu_id_step`: u8 | null. CPUID stepping. Present in report version 3+; `null` on older reports.
- `snp.evidence.launch_mit_vector`: u64 | null. Verified mitigation vector at guest launch. Present in report version 5+; `null` on older reports.
- `snp.evidence.current_mit_vector`: u64 | null. Current verified mitigation vector. Present in report version 5+; `null` on older reports.

## TPM

- `tpm.init_data`: SHA256 PCR[08] value (hex)
- `tpm.report_data`: nonce from quote (hex)
- `tpm.pcr00` ... `tpm.pcr23`: SHA256 PCR values (hex; index count depends on quote)
- `tpm.ak_public`: AK (Attestation Key) public key in PEM format (base64-encoded DER)

## Hygon DCU

Each attestation report produces one set of claims under `hygondcu`. Multiple DCUs are evaluated separately (EAR token submods `dcu0`, `dcu1`, ... in evidence list order):

- `hygondcu.body.version`: Firmware version.
- `hygondcu.body.chip_id`: DCU chip ID.
- `hygondcu.body.user_data`: The challenge data for the attestation.
- `hygondcu.body.measure`: measurement of the firmware.
- `hygondcu.body.reserved`: Reserved field.
- `hygondcu.body.sig_usage`: The usage of the signature.
- `hygondcu.body.sig_algo`: The algorithm of the signature.
- `hygondcu.report_data` (same value as `body.user_data`)

## Hygon CSV

- `csv.version`: The version of the quote. Now only `1` and `2` is legal.
- `csv.policy.nodbg`: Debugging of the guest is disallowed.
- `csv.policy.noks`: Sharing keys with other guests is disallowed.
- `csv.policy.es`: CSV2 is required when set.
- `csv.policy.nosend`: Sending the guest to another platform is disallowed.
- `csv.policy.domain`: The guest must not be transmitted to another platform that is not in the domain.
- `csv.policy.csv`: The guest must not be transmitted to another platform that is not CSV capable.
- `csv.policy.csv3`: CSV3 is required.
- `csv.policy.asid_reuse`: Sharing asids with other guests owned by same user is allowed.
- `csv.policy.hsk_version`: The guest must not be transmitted to another platform with a lower HSK version.
- `csv.policy.cek_version`: The guest must not be transmitted to another platform with a lower CEK version.
- `csv.policy.api_major`: The guest must not be transmitted to another platform with a lower platform version.
- `csv.policy.api_minor`: The guest must not be transmitted to another platform with a lower platform version.
- `csv.user_pubkey_digest`: Pubkey digest of the session used to secure communication between user/hypervisor and PSP.
- `csv.vm_id`:  The identifier of the VM custommized by the guest owner.
- `csv.vm_version`:  The version info of the VM customized by the guest owner.
- `csv.report_data`: The challenge data for the attestation.
- `csv.mnonce`: The random nonce generated by user to protect struct TeeInfoSigner.
- `csv.measure`: The launch digest of the VM.
- `csv.anonce`: The signature for the fields above.
- `csv.sig_usage`: The usage of the signature.
- `csv.sig_algo`: The algorithm of the signature.
- `csv.serial_number`: CPU serial number.

If the quote version is `2`, it will have the following extra fiels.

- `csv.build`: The version of the firmware's build.
- `csv.rtmr_version`: The version of the VM's rtmr.
- `csv.reserved0`: A reserved field, for future use.
- `csv.rtmr0`: The rtmr register 0, it's always equals to @measure field.
- `csv.rtmr1`: The rtmr register 1.
- `csv.rtmr2`: The rtmr register 2.
- `csv.rtmr3`: The rtmr register 3.
- `csv.rtmr4`: The rtmr register 4.
- `csv.reserved1`: A reserved field, for future use.
