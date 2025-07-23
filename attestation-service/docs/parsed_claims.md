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
- `tdx.quote.header.att_key_type`: enum of the algorithm used in signature.
- `tdx.quote.header.tee_type`: TDX is always 0x81.
- `tdx.quote.header.reserved`: reserved.
- `tdx.quote.header.vendor_id`: UID of QE Vendor. QE is a signed software component inside TEE to help to generate tdx quote.
- `tdx.quote.header.user_data`: Custom attestation key owner data.
- `tdx.quote.body.mr_config_id`: Software-defined ID for non-owner-defined configuration of the guest TD – e.g., run-time or OS configuration.
- `tdx.quote.body.mr_owner`: Software-defined ID for the guest TD’s owner.
- `tdx.quote.body.mr_owner_config`: Software-defined ID for owner-defined configuration of the guest TD – e.g., specific to the workload rather than the run-time or OS.
- `tdx.quote.body.mr_td`: Measurement of the initial contents of the TD.
- `tdx.quote.body.mrsigner_seam`: measurement of a 3rd party tdx-module's signer (SHA384 hash). If it is 0, the tdx-module is from Intel.
- `tdx.quote.body.report_data`: software defined ID for non-owner-defined configuration on the guest TD.
- `tdx.quote.body.seam_attributes`: for tdx1.0, must be 0.
- `tdx.quote.body.td_attributes`: TD's attributes.
- `tdx.quote.body.mr_seam`: Measurement of the SEAM module
- `tdx.quote.body.tcb_svn`: TEE hardware tcb version, defined and meaningful to Intel. everytime firmware updates this field will change.
- `tdx.quote.body.xfam`: TD's XFAM
- `tdx.quote.body.rtmr_0`: Runtime extendable measurement register 0.
- `tdx.quote.body.rtmr_1`: Runtime extendable measurement register 1.
- `tdx.quote.body.rtmr_2`: Runtime extendable measurement register 2.
- `tdx.quote.body.rtmr_3`: Runtime extendable measurement register 3.
- `tdx.quote.type`: Indicating quote v5 type. 2 means TDX 1.0 quote and 3 means TDX 1.5 quote. Only quote format V5 contains this field.
- `tdx.quote.size`: Quote body length. Only quote format V5 contains this field.
- `tdx.quote.body.tee_tcb_svn2`: Array of TEE TCB SVNs (for TD preserving).
- `tdx.quote.body.mr_servicetd`: If there is one or more bound or pre-bound service TDs, this field is the SHA384 hash of the `TDINFO`s of those service TDs bound. Else, this field is 0.
- `tdx.tcb_status`: TCB status which can be one of: OK, Min, OutOfDate, OutOfDateConfigurationNeeded, InvalidSignature, Revoked, Unspecified, SoftwareHardeningNeeded, ConfigurationAndSoftwareHardeningNeeded, TdRelaunchAdvised, TdRelaunchAdvisedConfigurationNeeded, Max
- `tdx.td_attributes.debug`: A boolean value that indicates whether the TD runs in TD debug mode (set to 1) or not (set to 0). In TD debug mode, the CPU state and private memory are accessible by the host VMM.
- `tdx.td_attributes.key_locker`: A boolean value that indicates whether the TD is allowed to use Key Locker.
- `tdx.td_attributes.perfmon`: A boolean value that indicates whether the TD is allowed to use Perfmon and PERF_METRICS capabilities.
- `tdx.td_attributes.protection_keys`: A boolean value that indicates whether the TD is allowed to use Supervisor Protection Keys.
- `tdx.td_attributes.septve_disable`:  A boolean value that determines whether to disable EPT violation conversion to #VE on TD access of PENDING pages.
- `tdx.advisory_ids`: List of Intel® Product Security Center Advisories
- `tdx.collateral_expiration_status`:  Expected 0, if none of the inputted collateral has expired as compared to the inputted expiration_check_date.

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
