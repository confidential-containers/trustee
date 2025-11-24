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

# For the `filesystem` trust claim, the value 0 stands for
# "No assertion."
default file_system := 0

# For the `instance_identity` trust claim, the value 0 stands for
# "No assertion."
default instance_identity := 0

# For the `runtime_opaque` trust claim, the value 0 stands for
# "No assertion."
default runtime_opaque := 0

# For the `storage_opaque` trust claim, the value 0 stands for
# "No assertion."
default storage_opaque := 0

# For the `sourced_data` trust claim, the value 0 stands for
# "No assertion."
default sourced_data := 0

trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": file_system,
	"instance-identity": instance_identity,
	"runtime-opaque": runtime_opaque,
	"storage-opaque": storage_opaque,
	"sourced-data": sourced_data,
}

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
	input.sample.launch_digest in query_reference_value("launch_digest")
}

# For the `hardware` trust claim, the value 2 stands for
# "An Attester has passed its hardware and/or firmware
#  verifications needed to demonstrate that these are genuine/
#  supported.
hardware := 2 if {
	input.sample

	input.sample.svn in query_reference_value("svn")
	input.sample.platform_version.major == query_reference_value("major_version")
	input.sample.platform_version.minor >= query_reference_value("minimum_minor_version")
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# In this case, check that debug mode isn't turned on.
# The sample platform is just an example.
# For the sample platform, the debug claim is always false.
# The sample platform should only be used for testing.
configuration := 2 if {
	input.sample

	input.sample.debug == false
}

##### SNP
executables := 3 if {
	input.snp

	# In the future, we might calculate this measurement here various components
	input.snp.measurement in query_reference_value("snp_launch_measurement")
}

hardware := 2 if {
	input.snp

	# Check the reported TCB to validate the ASP FW
	input.snp.reported_tcb_bootloader in query_reference_value("snp_bootloader")
	input.snp.reported_tcb_microcode in query_reference_value("snp_microcode")
	input.snp.reported_tcb_snp in query_reference_value("snp_snp_svn")
	input.snp.reported_tcb_tee in query_reference_value("snp_tee_svn")
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
configuration := 2 if {
	input.snp

	input.snp.policy_debug_allowed == false
	input.snp.policy_migrate_ma == false
	input.snp.platform_smt_enabled == query_reference_value("snp_smt_enabled")
	input.snp.platform_tsme_enabled == query_reference_value("snp_tsme_enabled")
	input.snp.policy_abi_major == query_reference_value("snp_guest_abi_major")
	input.snp.policy_abi_minor == query_reference_value("snp_guest_abi_minor")
	input.snp.policy_single_socket == query_reference_value("snp_single_socket")
	input.snp.policy_smt_allowed == query_reference_value("snp_smt_allowed")
}

# For the `configuration` trust claim 3 stands for
# "The configuration includes or exposes no known
#  vulnerabilities."
#
# In this check, we do not specifically check every
# configuration value, but we make sure that some key
# configurations (like debug_allowed) are set correctly.
else := 3 if {
	input.snp

	input.snp.policy_debug_allowed == false
	input.snp.policy_migrate_ma == false
}

##### TDX
executables := 3 if {
	input.tdx

	# Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
	input.tdx.quote.body.rtmr_1 in query_reference_value("rtmr_1")
	input.tdx.quote.body.rtmr_2 in query_reference_value("rtmr_2")
	tdx_uefi_event_tdvfkernel_ok
	tdx_uefi_event_tdvfkernelparams_ok
}

# Support for Grub boot used by GKE
else := 4 if {
	input.tdx

	# Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
	input.tdx.quote.body.rtmr_1 in query_reference_value("rtmr_1")
	input.tdx.quote.body.rtmr_2 in query_reference_value("rtmr_2")
}

hardware := 2 if {
	input.tdx

	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module version and its hash. Also check OVMF code hash.
	input.tdx.quote.body.mr_seam in query_reference_value("mr_seam")
	input.tdx.quote.body.tcb_svn in query_reference_value("tcb_svn")
	input.tdx.quote.body.mr_td in query_reference_value("mr_td")

	# Check TCB status
	input.tdx.tcb_status == "UpToDate"

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
	input.tdx

	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	input.tdx.td_attributes.debug == false
	input.tdx.quote.body.xfam in query_reference_value("xfam")
}

tdx_uefi_event_tdvfkernel_ok if {
	event := input.tdx.uefi_event_logs[_]
	event.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	"File(kernel)" in event.details.device_paths

	digest := event.digests[_]
	digest.digest == query_reference_value("tdvfkernel")
}

tdx_uefi_event_tdvfkernelparams_ok if {
	event := input.tdx.uefi_event_logs[_]
	event.type_name == "EV_EVENT_TAG"
	event.details.string == "LOADED_IMAGE::LoadOptions"

	digest := event.digests[_]
	digest.digest == query_reference_value("tdvfkernelparams")
}

##### Azure vTPM SNP
executables := 3 if {
	input.az_snp_vtpm

	input.az_snp_vtpm.measurement in query_reference_value("measurement")
	input.az_snp_vtpm.tpm.pcr11 in query_reference_value("snp_pcr11")
}

hardware := 2 if {
	input.az_snp_vtpm

	# Check the reported TCB to validate the ASP FW
	input.az_snp_vtpm.reported_tcb_bootloader in query_reference_value("tcb_bootloader")
	input.az_snp_vtpm.reported_tcb_microcode in query_reference_value("tcb_microcode")
	input.az_snp_vtpm.reported_tcb_snp in query_reference_value("tcb_snp")
	input.az_snp_vtpm.reported_tcb_tee in query_reference_value("tcb_tee")
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
configuration := 2 if {
	input.az_snp_vtpm

	input.az_snp_vtpm.platform_smt_enabled in query_reference_value("smt_enabled")
	input.az_snp_vtpm.platform_tsme_enabled in query_reference_value("tsme_enabled")
	input.az_snp_vtpm.policy_abi_major in query_reference_value("abi_major")
	input.az_snp_vtpm.policy_abi_minor in query_reference_value("abi_minor")
	input.az_snp_vtpm.policy_single_socket in query_reference_value("single_socket")
	input.az_snp_vtpm.policy_smt_allowed in query_reference_value("smt_allowed")
}

##### Azure vTPM TDX
executables := 3 if {
	input.az_tdx_vtpm

	input.az_tdx_vtpm.tpm.pcr11 in query_reference_value("tdx_pcr11")
}

hardware := 2 if {
	input.az_tdx_vtpm

	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.az_tdx_vtpm.quote.header.tee_type == "81000000"
	input.az_tdx_vtpm.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module version and its hash. Also check OVMF code hash.
	input.az_tdx_vtpm.quote.body.mr_seam in query_reference_value("mr_seam")
	input.az_tdx_vtpm.quote.body.tcb_svn in query_reference_value("tcb_svn")
	input.az_tdx_vtpm.quote.body.mr_td in query_reference_value("mr_td")
}

configuration := 2 if {
	input.az_tdx_vtpm

	input.az_tdx_vtpm.quote.body.xfam in query_reference_value("xfam")
}

##### TPM
hardware := 2 if {
	input.tpm
}

executables := 3 if {
	input.tpm

	input.tpm.pcr11 in query_reference_value("tpm_pcr11")
}

configuration := 0 if {
	input.tpm
}

##### SE TODO


#################################
# EXTENSIONS
#
# Extensions are added to the EAR Appraisal
#
# The identifiers extension contains information that
# describes the workload.
#
# In Confidential Containers many of these identifiers
# are bootstrapped from the Kata Agent Policy or some
# other config provided in the InitData.
#
# Other runtimes may provide identifiers in other ways,
# such as via the event log.
extensions := [
	{"name": "ear.trustee.identifiers",
		 "key": -18,
		 "value": {
			"validated": validated_identifiers
		}
	}
]

# Validated identifiers are information that describes a workload
# that are bound to the hardware evidence via attesation
# and bound to the workload by the guest runtime.
validated_identifiers := object.union_n([
    container_images_id,
    container_uids_id,
])

# Use list comprehension to parse all of the images specified in the policy.
container_images := [img |
    container := input["init_data_claims"]["agent_policy_claims"]["containers"][_]
    img := container["OCI"]["Annotations"]["io.kubernetes.cri.image-name"]
]

container_images_id := {"container_images": container_images} if {
    count(container_images) > 0
} else := {}

# UIDs
container_uids := [img |
    container := input["init_data_claims"]["agent_policy_claims"]["containers"][_]
    img := container["OCI"]["Process"]["User"]["UID"]
]

container_uids_id := {"container_uids": container_uids} if {
    count(container_uids) > 0
} else := {}

