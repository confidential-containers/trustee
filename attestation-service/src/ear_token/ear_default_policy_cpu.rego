package policy

import rego.v1

# The results of these devices are judged by this policy. All of them are
# passed to the policy together as `input.devices`, one entry per result.
# Every entry has a `device` field with the name of the device, a `tee` field with
# the name of the TEE, and the verifier claims under `claims`,
# e.g. `input.devices[_].claims`.
devices := [
	"sample",
	"tdx",
	"snp",
	"az-snp-vtpm",
	"az-tdx-vtpm",
	"tpm",
	"se",
	"cca",
	"sgx",
	"csv",
]

# The name of the entry this policy produces in the token.
submod := "cpu0"

# Note that the rules below are satisfied by any result in `input.devices`.
# If one attestation carries several CPU results that disagree on a claim,
# evaluation fails instead of picking one of them. Use dedicated policies
# to judge such combinations.

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
	some d in input.devices
	# Short circuit the rest of the conditions, if the platform is not set.
	# Creating a simple entry like this will skip executing the first
	# extension in the block.
	d.tee == "sample"
	# The sample attester does not report any launch digest.
	# This is an example of how a real platform might validate executables.
	d.claims.launch_digest in query_reference_value("launch_digest")
}

# For the `hardware` trust claim, the value 2 stands for
# "An Attester has passed its hardware and/or firmware
#  verifications needed to demonstrate that these are genuine/
#  supported.
hardware := 2 if {
	some d in input.devices
	d.tee == "sample"
	d.claims.svn in query_reference_value("svn")
	d.claims.platform_version.major == query_reference_value("major_version")
	d.claims.platform_version.minor >= query_reference_value("minimum_minor_version")
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# In this case, check that debug mode isn't turned on.
# The sample platform is just an example.
# For the sample platform, the debug claim is always false.
# The sample platform should only be used for testing.
configuration := 2 if {
	some d in input.devices
	d.tee == "sample"
	d.claims.debug == false
}

##### SNP
executables := 3 if {
	some d in input.devices
	d.tee == "snp"
	# In the future, we might calculate this measurement here various components
	d.claims.measurement in query_reference_value("snp_launch_measurement")
}

hardware := 2 if {
	some d in input.devices
	d.tee == "snp"
	# Check the reported TCB to validate the ASP FW
	d.claims.reported_tcb_bootloader in query_reference_value("snp_bootloader")
	d.claims.reported_tcb_microcode in query_reference_value("snp_microcode")
	d.claims.reported_tcb_snp in query_reference_value("snp_snp_svn")
	d.claims.reported_tcb_tee in query_reference_value("snp_tee_svn")
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
configuration := 2 if {
	some d in input.devices
	d.tee == "snp"
	d.claims.policy_debug_allowed == false
	d.claims.policy_migrate_ma == false
	d.claims.platform_smt_enabled == query_reference_value("snp_smt_enabled")
	d.claims.platform_tsme_enabled == query_reference_value("snp_tsme_enabled")
	d.claims.policy_abi_major == query_reference_value("snp_guest_abi_major")
	d.claims.policy_abi_minor == query_reference_value("snp_guest_abi_minor")
	d.claims.policy_single_socket == query_reference_value("snp_single_socket")
	d.claims.policy_smt_allowed == query_reference_value("snp_smt_allowed")
}

# For the `configuration` trust claim 3 stands for
# "The configuration includes or exposes no known
#  vulnerabilities."
#
# In this check, we do not specifically check every
# configuration value, but we make sure that some key
# configurations (like debug_allowed) are set correctly.
else := 3 if {
	some d in input.devices
	d.tee == "snp"
	d.claims.policy_debug_allowed == false
	d.claims.policy_migrate_ma == false
}

##### TDX
executables := 3 if {
	some d in input.devices
	d.tee == "tdx"
	# Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
	d.claims.quote.body.rtmr_1 in query_reference_value("rtmr_1")
	d.claims.quote.body.rtmr_2 in query_reference_value("rtmr_2")
	tdx_uefi_event_tdvfkernel_ok(d)
	tdx_uefi_event_tdvfkernelparams_ok(d)
}

# Support for Grub boot used by GKE
else := 4 if {
	some d in input.devices
	d.tee == "tdx"
	# Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
	d.claims.quote.body.rtmr_1 in query_reference_value("rtmr_1")
	d.claims.quote.body.rtmr_2 in query_reference_value("rtmr_2")
}

hardware := 2 if {
	some d in input.devices
	d.tee == "tdx"
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	d.claims.quote.header.tee_type == "81000000"
	d.claims.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module hash
	# d.claims.quote.body.mr_seam in query_reference_value("mr_seam")
	#
	# Check OVMF code hash
	d.claims.quote.body.mr_td in query_reference_value("mr_td")

	# Check TCB status (covers quote.body.tcb_svn claim check)
	d.claims.tcb_status == "UpToDate"

	# Check minimum TCB date
	# An alternative check to tcb_status is to define a minimum acceptable
	# TCB date. TCB dates are associated with TCB Recovery events to which
	# the platforms are certified.
	#
	# Available TCB dates can be checked using:
	# curl -s https://api.trustedservices.intel.com/tdx/certification/v4/tcbevaluationdatanumbers | jq
	#
	# Example: in some cases, "OutOfDate" tcb_status can be accepted as long as
	# the tcb_date is not older than a given date from a past TCB Recovery event:
	# min_tcb_date := "2025-08-13T00:00:00Z"
	# attester_tcb_date_ns := time.parse_rfc3339_ns(d.claims.tcb_date)
	# min_tcb_date_ns := time.parse_rfc3339_ns(min_tcb_date)
	# attester_tcb_date_ns >= min_tcb_date_ns

	# Check collateral expiration status
	d.claims.collateral_expiration_status == "0"
	# Check against allowed advisory ids
	# allowed_advisory_ids := {"INTEL-SA-00837"}
	# attester_advisory_ids := {id | id := d.attester_advisory_ids[_]}
	# object.subset(allowed_advisory_ids, attester_advisory_ids)

	# Check against disallowed advisory ids
	# disallowed_advisory_ids := {"INTEL-SA-00837"}
	# attester_advisory_ids := {id | id := d.claims.advisory_ids[_]} # convert array to set
	# intersection := attester_advisory_ids & disallowed_advisory_ids
	# count(intersection) == 0
}

configuration := 2 if {
	some d in input.devices
	d.tee == "tdx"
	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	d.claims.td_attributes.debug == false
	d.claims.quote.body.xfam in query_reference_value("xfam")
}

tdx_uefi_event_tdvfkernel_ok(d) if {
	event := d.claims.uefi_event_logs[_]
	event.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	"File(kernel)" in event.details.device_paths

	digest := event.digests[_]
	digest.digest == query_reference_value("tdvfkernel")
}

tdx_uefi_event_tdvfkernelparams_ok(d) if {
	event := d.claims.uefi_event_logs[_]
	event.type_name == "EV_EVENT_TAG"
	event.details.string == "LOADED_IMAGE::LoadOptions"

	digest := event.digests[_]
	digest.digest == query_reference_value("tdvfkernelparams")
}

##### Azure vTPM SNP
executables := 3 if {
	some d in input.devices
	d.tee == "az-snp-vtpm"
	d.claims.measurement in query_reference_value("measurement")
	d.claims.tpm.pcr11 in query_reference_value("snp_pcr11")
}

hardware := 2 if {
	some d in input.devices
	d.tee == "az-snp-vtpm"
	# Check the reported TCB to validate the ASP FW
	d.claims.reported_tcb_bootloader in query_reference_value("tcb_bootloader")
	d.claims.reported_tcb_microcode in query_reference_value("tcb_microcode")
	d.claims.reported_tcb_snp in query_reference_value("tcb_snp")
	d.claims.reported_tcb_tee in query_reference_value("tcb_tee")
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
configuration := 2 if {
	some d in input.devices
	d.tee == "az-snp-vtpm"
	d.claims.platform_smt_enabled in query_reference_value("smt_enabled")
	d.claims.platform_tsme_enabled in query_reference_value("tsme_enabled")
	d.claims.policy_abi_major in query_reference_value("abi_major")
	d.claims.policy_abi_minor in query_reference_value("abi_minor")
	d.claims.policy_single_socket in query_reference_value("single_socket")
	d.claims.policy_smt_allowed in query_reference_value("smt_allowed")
}

##### Azure vTPM TDX
executables := 3 if {
	some d in input.devices
	d.tee == "az-tdx-vtpm"
	d.claims.tpm.pcr11 in query_reference_value("tdx_pcr11")
}

hardware := 2 if {
	some d in input.devices
	d.tee == "az-tdx-vtpm"
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	d.claims.quote.header.tee_type == "81000000"
	d.claims.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module hash
	# d.claims.quote.body.mr_seam in query_reference_value("mr_seam")
	#
	# Check OVMF code hash
	d.claims.quote.body.mr_td in query_reference_value("mr_td")

	# Check TCB status (covers quote.body.tcb_svn claim check)
	d.claims.tcb_status == "UpToDate"

	# Check minimum TCB date (See TDX section for details.)
}

configuration := 2 if {
	some d in input.devices
	d.tee == "az-tdx-vtpm"
	d.claims.quote.body.xfam in query_reference_value("xfam")
}

##### TPM
hardware := 2 if {
	some d in input.devices
	d.tee == "tpm"
}

executables := 3 if {
	some d in input.devices
	d.tee == "tpm"
	d.claims.pcr11 in query_reference_value("tpm_pcr11")

	d.claims.ak_public in query_reference_value("trusted_aks")
}

configuration := 0 if {
	some d in input.devices
	d.tee == "tpm"
}

##### IBM Secure Execution for Linux (SEL)
# Only field existence is checked. No value check is necessary.
# The SE verifier performs cryptographic verification including
# measurements, signatures, and user_data binding.
# If the field exists, it means the verifaction is successful.
# This is a 'trust-the-verifier' approach.
executables := 3 if {
	some d in input.devices
	d.tee == "se"
}

hardware := 2 if {
	some d in input.devices
	d.tee == "se"
}

configuration := 2 if {
	some d in input.devices
	d.tee == "se"
}

##### Arm CCA
# CCA evidence (RMM signing chain, platform and realm certificate chain) is fully
# cryptographically verified by the verifier before this policy runs, so hardware,
# instance identity, and runtime opacity are implied by a successful appraisal.
hardware := 2 if {
	some d in input.devices
	d.tee == "cca"
}

instance_identity := 2 if {
	some d in input.devices
	d.tee == "cca"
}

runtime_opaque := 2 if {
	some d in input.devices
	d.tee == "cca"
}

# For the `executables` trust claim, the value 3 stands for
# "Only a recognized genuine set of approved executables have
#  been loaded during the boot process."
# the RIM (realm initial measurement) must match
executables := 3 if {
	some d in input.devices
	d.tee == "cca"
	d.claims.realm["cca-realm-initial-measurement"] in query_reference_value("cca.rim/digests")
}

configuration := 0 if {
	some d in input.devices
	d.tee == "cca"
}

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
    container_uids_id,
    pod_image_id,
    pod_image_count_id,
])

# The init data claims. They are derived from the init data of the request,
# so every device of the request reports the same ones.
init_data_claims := claims if {
	some d in input.devices
	claims := d.init_data_claims
}

# Container images used in a pod.
# For now, take whatever reference is in the policy data.
# In the future, this should be coupled to an image signature policy.
container_images := [img |
    container := init_data_claims.agent_policy_claims.containers[_]
    img := container["OCI"]["Annotations"]["io.kubernetes.cri.image-name"]
]

pod_image_id := {"pod-image": container_images} if {
    count(container_images) > 0
} else := {}

pod_image_count_id := {"pod-image-count": count(container_images)} if {
    count(container_images) > 0
} else := {}

# The UID that each container runs with
container_uids := [img |
    container := init_data_claims.agent_policy_claims.containers[_]
    img := container["OCI"]["Process"]["User"]["UID"]
]

container_uids_id := {"container_uids": container_uids} if {
    count(container_uids) > 0
} else := {}

