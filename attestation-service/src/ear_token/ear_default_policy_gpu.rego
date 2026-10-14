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

# GPUs verified by the NVIDIA remote (NRAS) verifier.
hardware := 2 if {
	input.nvidia.verifier == "remote"
}

configuration := 2 if {
	input.nvidia.verifier == "remote"
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
	input.nvidia.vbios_version in query_reference_value("allowed_vbios_versions")
	input.nvidia.driver_version in query_reference_value("allowed_driver_versions")
}

else := 3 if {
	input.nvidia.verifier == "remote"
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
}

executables := 3 if {
	input.nvidia.verifier == "remote"
}
