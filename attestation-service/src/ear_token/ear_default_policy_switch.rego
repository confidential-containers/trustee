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

# Switches verified by NRAS
hardware := 2 if {
	input.nvidia

	input.nvidia["x-nvidia-switch-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
	input.nvidia["x-nvidia-switch-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"

	input.nvidia["x-nvidia-switch-attestation-report-cert-chain-fwid-match"]
	input.nvidia["x-nvidia-switch-attestation-report-parsed"]
	input.nvidia["x-nvidia-switch-attestation-report-signature-verified"]

	input.nvidia["x-nvidia-switch-arch-check"]
}

configuration := 2 if {
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
	input.nvidia["x-nvidia-switch-bios-version"] in query_reference_value("allowed_switch_bios_versions")
} 

else := 3 if {
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
}

executables := 3 if {
	input.nvidia["x-nvidia-switch-bios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
	input.nvidia["x-nvidia-switch-bios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"

	input.nvidia["x-nvidia-switch-bios-rim-fetched"]
	input.nvidia["x-nvidia-switch-bios-rim-measurements-available"]
	input.nvidia["x-nvidia-switch-bios-rim-schema-validated"]
	input.nvidia["x-nvidia-switch-bios-rim-signature-verified"]
	input.nvidia["x-nvidia-switch-bios-rim-version-match"]

	input.nvidia.measres == "success"
}
