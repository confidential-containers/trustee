package policy

import rego.v1

default hardware := 97

default executables := 33

default configuration := 36

default file_system := 0

default instance_identity := 0

default runtime_opaque := 0

default storage_opaque := 0

default sourced_data := 0

hardware := 2 if {
	input.sampledevice.svn in data.reference.device_svn
}

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

# Switches verified by the NVIDIA remote (NRAS) verifier.
#
# Certificate chains, report/RIM signatures, measurement comparison, nonce
# match, arch check, and similar fixed checks are already enforced inside the
# verifier. This policy only evaluates variable claims (configuration /
# allowlists). See deps/verifier/src/nvidia/claims.rs.
hardware := 2 if {
	input.nvidia.verifier == "remote"
}

configuration := 2 if {
	input.nvidia.verifier == "remote"
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
	input.nvidia["x-nvidia-switch-bios-version"] in query_reference_value("allowed_switch_bios_versions")
}

else := 3 if {
	input.nvidia.verifier == "remote"
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
}

executables := 3 if {
	input.nvidia.verifier == "remote"
}
