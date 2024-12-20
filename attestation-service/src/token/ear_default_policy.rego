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
default sample_executables := 33

default snp_executables := 33

default tdx_executables := 33

default az_snp_executables := 33

default az_tdx_executables := 33

default se_executables := 33

# For the `hardware` trust claim, the value 97 stands for
# "A Verifier does not recognize an Attester's hardware or
#  firmware, but it should be recognized."
default sample_hardware := 97

default snp_hardware := 97

default tdx_hardware := 97

default az_snp_hardware := 97

default az_tdx_hardware := 97

default se_hardware := 97

# For the `configuration` trust claim the value 36 stands for
# "Elements of the configuration relevant to security are
#  unavailable to the Verifier."
default sample_configuration := 36

default snp_configuration := 36

default tdx_configuration := 36

default az_snp_configuration := 36

default az_tdx_configuration := 36

default se_configuration := 36

executables := min({sample_executables, snp_executables, tdx_executables, az_snp_executables, az_tdx_executables, se_executables})

hardware := min({sample_hardware, snp_hardware, tdx_hardware, az_snp_hardware, az_tdx_hardware, se_hardware})

configuration := min({sample_configuration, snp_configuration, tdx_configuration, az_snp_configuration, az_tdx_configuration, se_configuration})

##### Sample

# For the `executables` trust claim, the value 3 stands for
# "Only a recognized genuine set of approved executables have
#  been loaded during the boot process."
sample_executables := 3 if {
	# The sample attester does not report any launch digest.
	# This is an example of how a real platform might validate executables.
	input.sample.launch_digest in data.reference.launch_digest
}

# For the `hardware` trust claim, the value 2 stands for
# "An Attester has passed its hardware and/or firmware
#  verifications needed to demonstrate that these are genuine/
#  supported.
sample_hardware := 2 if {
	input.sample.svn in data.reference.svn
}

##### SNP
snp_executables := 3 if {
	# In the future, we might calculate this measurement here various components
	input.snp.launch_measurement in data.reference.snp_launch_measurement
}

snp_hardware := 2 if {
	# Check the reported TCB to validate the ASP FW
	input.snp.reported_tcb_bootloader in data.reference.snp_bootloader
	input.snp.reported_tcb_microcode in data.reference.snp_microcode
	input.snp.reported_tcb_snp in data.reference.snp_snp_svn
	input.snp.reported_tcb_tee in data.reference.snp_tee_svn
}

# For the 'configuration' trust claim 2 stands for
# "The configuration is a known and approved config."
#
# For this, we compare all the configuration fields.
snp_configuration := 2 if {
	input.snp.policy_debug_allowed == 0
	input.snp.policy_migrate_ma == 0
	input.snp.platform_smt_enabled in data.reference.snp_smt_enabled
	input.snp.platform_tsme_enabled in data.reference.snp_tsme_enabled
	input.snp.policy_abi_major in data.reference.snp_guest_abi_major
	input.snp.policy_abi_minor in data.reference.snp_guest_abi_minor
	input.snp.policy_single_socket in data.reference.snp_single_socket
	input.snp.policy_smt_allowed in data.reference.snp_smt_allowed
}

# For the `configuration` trust claim 3 stands for
# "The configuration includes or exposes no known
#  vulnerabilities."
#
# In this check, we do not specifically check every
# configuration value, but we make sure that some key
# configurations (like debug_allowed) are set correctly.
else := 3 if {
	input.snp.policy_debug_allowed == 0
	input.snp.policy_migrate_ma == 0
}

##### TDX TODO
##### AZ SNP TODO
##### AZ TDX TODO
##### SE TODO
