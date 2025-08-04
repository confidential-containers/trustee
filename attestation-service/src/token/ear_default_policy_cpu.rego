package policy

import rego.v1

# This policy validates multiple TEE platforms
# The policy is meant to capture the TCB requirements
# for confidential containers.

# This policy is used to generate an EAR Appraisal.
# Specifically it generates an AR4SI result.
# More informatino on AR4SI can be found at
# <https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/>

# For the `executables` trust claim, the value 33 stands for
# "Runtime memory includes executables, scripts, files, and/or
#  objects which are not recognized."
default executables := 33

# For the `hardware` trust claim, the value 97 stands for
# "A Verifier does not recognize an Attester's hardware or
#  firmware, but it should be recognized."
default hardware := 97

# For the `configuration` trust claim the value 36 stands for
# "Elements of the configuration relevant to security are
#  unavailable to the Verifier."
default configuration := 36

##### Sample

# For the `executables` trust claim, the value 3 stands for
# "Only a recognized genuine set of approved executables have
#  been loaded during the boot process."
executables := 3 if {
	# Short circuit the rest of the conditions, if the platform is not set.
	# Creating a simple entry like this will skip executing the first
	# extension in the block.
	input.sample

	# The sample attester does not report any launch digest.
	# This is an example of how a real platform might validate executables.
	input.sample.launch_digest
}

# For the `hardware` trust claim, the value 2 stands for
# "An Attester has passed its hardware and/or firmware
#  verifications needed to demonstrate that these are genuine/
#  supported.
hardware := 2 if {
	input.sample
	input.sample.svn
	input.sample.platform_version.major
	input.sample.platform_version.minor
}

##### SNP
executables := 3 if {
	input.snp

	# In the future, we might calculate this measurement here various components
	input.snp.measurement
}

hardware := 2 if {
	input.snp

	# Check the reported TCB to validate the ASP FW
	input.snp.reported_tcb_bootloader
	input.snp.reported_tcb_microcode
	input.snp.reported_tcb_snp
	input.snp.reported_tcb_tee
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
configuration := 2 if {
	input.snp.policy_debug_allowed == false
	input.snp.policy_migrate_ma == false
	input.snp.platform_smt_enabled
	input.snp.policy_abi_major
	input.snp.policy_abi_minor
	input.snp.policy_single_socket
	input.snp.policy_smt_allowed
}

# For the `configuration` trust claim 3 stands for
# "The configuration includes or exposes no known
#  vulnerabilities."
#
# In this check, we do not specifically check every
# configuration value, but we make sure that some key
# configurations (like debug_allowed) are set correctly.
else := 3 if {
	input.snp.policy_debug_allowed == false
	input.snp.policy_migrate_ma == false
}

##### TDX
executables := 3 if {
	input.tdx

	# Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
	input.tdx.quote.body.rtmr_1
	input.tdx.quote.body.rtmr_2
	tdx_uefi_event_tdvfkernel_ok
	tdx_uefi_event_tdvfkernelparams_ok
}

# Support for Grub boot used by GKE
else := 4 if {
	input.tdx

	# Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
	input.tdx.quote.body.rtmr_1
	input.tdx.quote.body.rtmr_2
}

hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module version and its hash. Also check OVMF code hash.
	input.tdx.quote.body.mr_seam
	input.tdx.quote.body.tcb_svn
	input.tdx.quote.body.mr_td

	# Check TCB status
	# The possible values are:
	# OK - Quote verification passed and is at the latest TCB level
	# Min - The Quote verification passed and the platform is patched
	#	to the latest TCB level
	# OutOfDate - The Quote is good but TCB level of the platform is
	#	out of date. The platform needs patching to be at the latest TCB level
	# OutOfDateConfigurationNeeded - The Quote is good but the TCB level
	#	of the platform is out of date and additional configuration of the
	#	SGX Platform at its current patching level may be needed. The
	#	platform needs patching to be at the latest TCB level
	# SoftwareHardeningNeeded - The TCB level of the platform is up
	#	to date, but SGX SW Hardening is needed.
	# ConfigurationAndSoftwareHardeningNeeded - The TCB level of the
	#	platform is up to date, but additional configuration of the
	#	platform at its current patching level may be needed. Moreove,
	#	SGX SW Hardening is also needed
	#
	input.tdx.tcb_status

	# Check collateral expiration status
	input.tdx.collateral_expiration_status == "0"
	# Check against allowed advisory ids
	# allowed_advisory_ids := {"INTEL-SA-00837"}
	# attester_advisory_ids := {id | id := input.attester_advisory_ids[_]}
	# object.subset(allowed_advisory_ids, attester_advisory_ids)

	# Check against disallowed advisory ids
	# disallowed_advisory_ids := {"INTEL-SA-00837"}
	# attester_advisory_ids := {id | id := input.tdx.advisory_ids[_]} # convert array to set
	# intersection := attester_advisory_ids & disallowed_advisory_ids
	# count(intersection) == 0
}

configuration := 2 if {
	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	input.tdx.td_attributes.debug == false
	input.tdx.quote.body.xfam
}

tdx_uefi_event_tdvfkernel_ok if {
	event := input.tdx.uefi_event_logs[_]
	event.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	"File(kernel)"

	digest := event.digests[_]
	digest.digest
}

tdx_uefi_event_tdvfkernelparams_ok if {
	event := input.tdx.uefi_event_logs[_]
	event.type_name == "EV_EVENT_TAG"
	event.details.string == "LOADED_IMAGE::LoadOptions"

	digest := event.digests[_]
	digest.digest
}

##### Azure vTPM SNP
executables := 3 if {
	input.azsnptvpm
	input.azsnpvtpm.measurement
	input.azsnpvtpm.tpm.pcr11
}

hardware := 2 if {
	input.azsnptvpm

	# Check the reported TCB to validate the ASP FW
	input.azsnpvtpm.reported_tcb_bootloader
	input.azsnpvtpm.reported_tcb_microcode
	input.azsnpvtpm.reported_tcb_snp
	input.azsnpvtpm.reported_tcb_tee
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
configuration := 2 if {
	input.azsnptvpm
	input.azsnpvtpm.platform_smt_enabled
	input.azsnpvtpm.platform_tsme_enabled
	input.azsnpvtpm.policy_abi_major
	input.azsnpvtpm.policy_abi_minor
	input.azsnpvtpm.policy_single_socket
	input.azsnpvtpm.policy_smt_allowed
}

##### Azure vTPM TDX
executables := 3 if {
	input.azsnptvpm
	input.aztdxvtpm.tpm.pcr11
}

hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.aztdxvtpm.quote.header.tee_type == "81000000"
	input.aztdxvtpm.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module version and its hash. Also check OVMF code hash.
	input.aztdxvtpm.quote.body.mr_seam
	input.aztdxvtpm.quote.body.tcb_svn
	input.aztdxvtpm.quote.body.mr_td
}

configuration := 2 if {
	input.azsnptvpm
	input.aztdxvtpm.quote.body.xfam
}

##### SE TODO
