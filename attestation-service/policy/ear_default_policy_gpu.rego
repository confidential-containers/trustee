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

result := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": file_system,
	"instance-identity": instance_identity,
	"runtime-opaque": runtime_opaque,
	"storage-opaque": storage_opaque,
	"sourced-data": sourced_data,
}

# GPUs verified by NRAS
hardware := 2 if {
	input.nvidia.x_nvidia_gpu_attestation_report_cert_chain.x_nvidia_cert_ocsp_status == "good"
	input.nvidia.x_nvidia_gpu_attestation_report_cert_chain.x_nvidia_cert_status == "valid"

	input.nvidia.x_nvidia_gpu_attestation_report_cert_chain_fwid_match
	input.nvidia.x_nvidia_gpu_attestation_report_parsed
	input.nvidia.x_nvidia_gpu_attestation_report_signature_verified

	input.nvidia.x_nvidia_gpu_arch_check
}

configuration := 2 if {
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
	input.nvidia.x_nvidia_gpu_vbios_version in data.reference.allowed_vbios_versions
	input.nvidia.x_nvidia_gpu_driver_version in data.reference.allowed_driver_versions
}

else := 3 if {
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
}

executables := 3 if {
	input.nvidia.x_nvidia_gpu_vbios_rim_cert_chain.x_nvidia_cert_ocsp_status == "good"
	input.nvidia.x_nvidia_gpu_vbios_rim_cert_chain.x_nvidia_cert_status == "valid"

	input.nvidia.x_nvidia_gpu_driver_rim_fetched
	input.nvidia.x_nvidia_gpu_driver_rim_measurements_available
	input.nvidia.x_nvidia_gpu_driver_rim_schema_validated
	input.nvidia.x_nvidia_gpu_driver_rim_signature_verified
	input.nvidia.x_nvidia_gpu_driver_rim_version_match

	input.nvidia.x_nvidia_gpu_vbios_rim_fetched
	input.nvidia.x_nvidia_gpu_vbios_rim_measurements_available
	input.nvidia.x_nvidia_gpu_vbios_rim_schema_validated
	input.nvidia.x_nvidia_gpu_vbios_rim_signature_verified
	input.nvidia.x_nvidia_gpu_vbios_rim_version_match

	input.nvidia.measres
}
