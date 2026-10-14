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

local_nvidia_evidence if {
	input.nvidia.verifier == "local"
	input.nvidia.arch in {"Hopper", "Blackwell"}
	is_object(input.nvidia.config)
	is_object(input.nvidia.measurements)
}

remote_nvidia_evidence if {
	input.nvidia.verifier == "remote"
}

# Local verification rejects the report before policy evaluation unless its
# signature, certificate chain, FWID, and nonce are valid.
hardware := 2 if {
	local_nvidia_evidence
}

nonempty_string_array(values) if {
	is_array(values)
	count(values) > 0
	every value in values {
		is_string(value)
	}
}

reference_value_matches(actual, reference_id) if {
	is_string(actual)
	allowed := query_reference_value(reference_id)
	nonempty_string_array(allowed)
	actual in allowed
}

configuration := 2 if {
	local_nvidia_evidence
	reference_value_matches(input.nvidia.config.driver_version, "allowed_driver_versions")
	reference_value_matches(input.nvidia.config.vbios_version, "allowed_vbios_versions")
	reference_value_matches(input.nvidia.config.fwid, "allowed_gpu_fwids")
}

valid_measurement_reference(expected) if {
	is_string(expected)
}

valid_measurement_reference(expected) if {
	nonempty_string_array(expected)
}

measurement_matches(actual, expected) if {
	is_string(actual)
	is_string(expected)
	actual == expected
}

measurement_matches(actual, expected) if {
	is_string(actual)
	nonempty_string_array(expected)
	actual in expected
}

reference_measurements_match if {
	reference_measurements := query_reference_value("allowed_gpu_measurements")
	is_object(reference_measurements)
	count(reference_measurements) > 0
	every index, expected in reference_measurements {
		valid_measurement_reference(expected)
		measurement_matches(input.nvidia.measurements[index], expected)
	}
}

executables := 3 if {
	local_nvidia_evidence
	reference_measurements_match
}

# GPUs verified by NRAS
hardware := 2 if {
	remote_nvidia_evidence

	input.nvidia["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
	input.nvidia["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"

	input.nvidia["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"]
	input.nvidia["x-nvidia-gpu-attestation-report-parsed"]
	input.nvidia["x-nvidia-gpu-attestation-report-signature-verified"]

	input.nvidia["x-nvidia-gpu-arch-check"]
}

configuration := 2 if {
	remote_nvidia_evidence
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
	input.nvidia["x-nvidia-gpu-vbios-version"] in query_reference_value("allowed_vbios_versions")
	input.nvidia["x-nvidia-gpu-driver-version"] in query_reference_value("allowed_driver_versions")
} 

else := 3 if {
	remote_nvidia_evidence
	input.nvidia.secboot
	input.nvidia.dbgstat == "disabled"
}

executables := 3 if {
	remote_nvidia_evidence
	input.nvidia["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
	input.nvidia["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"

	input.nvidia["x-nvidia-gpu-driver-rim-fetched"]
	input.nvidia["x-nvidia-gpu-driver-rim-measurements-available"]
	input.nvidia["x-nvidia-gpu-driver-rim-schema-validated"]
	input.nvidia["x-nvidia-gpu-driver-rim-signature-verified"]
	input.nvidia["x-nvidia-gpu-driver-rim-version-match"]

	input.nvidia["x-nvidia-gpu-vbios-rim-fetched"]
	input.nvidia["x-nvidia-gpu-vbios-rim-measurements-available"]
	input.nvidia["x-nvidia-gpu-vbios-rim-schema-validated"]
	input.nvidia["x-nvidia-gpu-vbios-rim-signature-verified"]
	input.nvidia["x-nvidia-gpu-vbios-rim-version-match"]

	input.nvidia.measres == "success"
}
