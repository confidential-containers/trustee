# Parsed Claims

After CoCo-AS verifies every evidence, a token with _parsed claims_ will be returned.
_parsed claims_ is a key-value map inside the token, and it reflects the environment
information that the evidence contains. Different platforms will have different
key value members of the parsed claims. This document will show the whole key value
list of different platforms.

All platforms will by default have two fixed claims:
- `report_data`: report data when generating the evidence.
- `init_data`: Hostdata when creating the TEE instance.

## Sample

**This is only a test verifier**.
- `sample.svn`: version of the quote.
- `sample.report_data`: report data when generating the evidence.
- `sample.init_data`: init data hash.

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

The claim inherit the fields from the TDX claim with and additional `tpm` hierarchy in which the TEE's PCR values are stored:

- `tpm.pcr{01,..,n}`: SHA256 PCR registers for the TEE's vTPM quote.

Note: The TD Report and TD Quote are fetched during early boot in this TEE. Kernel, Initrd and rootfs are measured into the vTPM's registers.

## Azure SEV-SNP Confidential VM (az-snp-vtpm)

The claim inherit the fields from the SEV-SNP claim with and additional `tpm` hierarchy in which the TEE's PCR values are stored:

- `tpm.pcr{01,..,n}`: SHA256 PCR registers for the TEE's vTPM quote.

Note: The TD Report and TD Quote are fetched during early boot in this TEE. Kernel, Initrd and rootfs are measured into the vTPM's registers.

## IBM Secure Execution (SE)
- `se.version`: The version this quote structure.
- `se.cuid`: The unique ID of the attested guest (configuration uniqe ID).
- `se.tag`: SE header tag.
- `se.image_phkh`: SE image public host key hash
- `se.attestation_phkh`: SE attestation public host key hash
- `se.user_data`: Optional custom attestation owner data, could be key:value pairs collected on guest.

## NVIDIA

Hopper GPU H100

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

## AMD SEV-SNP

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
