package policy

import rego.v1

# The results of these devices are judged by this policy. All of them are
# passed to the policy together as `input.devices`, one entry per result.
# Every entry has a `device` field with the name of the device, a `tee` field with
# the name of the TEE, and the verifier claims under `claims`,
# e.g. `input.devices[_].claims`.
devices := ["nvidia-gpu", "sample-device"]

# The name of the entry this policy produces in the token.
submod := "gpu0"

default hardware := 97

default executables := 33

default configuration := 36

default file_system := 0

default instance_identity := 0

default runtime_opaque := 0

default storage_opaque := 0

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

# All GPUs of the attestation are judged together. A claim is only
# granted if every one of them satisfies it.
hardware := 2 if {
	count(input.devices) > 0
	count([d | some d in input.devices; not gpu_hardware_ok(d)]) == 0
}

configuration := 2 if {
	count(input.devices) > 0
	count([d | some d in input.devices; not gpu_configuration_approved(d)]) == 0
} else := 3 if {
	count(input.devices) > 0
	count([d | some d in input.devices; not gpu_configuration_secure(d)]) == 0
}

executables := 3 if {
	count(input.devices) > 0
	count([d | some d in input.devices; not gpu_executables_ok(d)]) == 0
}

# The sample device is only meant for testing.
gpu_hardware_ok(d) if {
	d.tee == "sampledevice"
	d.claims.svn in query_reference_value("device_svn")
}

# GPUs verified by NRAS
gpu_hardware_ok(d) if {
	d.tee == "nvidia"
	d.claims["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
	d.claims["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"

	d.claims["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"]
	d.claims["x-nvidia-gpu-attestation-report-parsed"]
	d.claims["x-nvidia-gpu-attestation-report-signature-verified"]

	d.claims["x-nvidia-gpu-arch-check"]
}

gpu_configuration_approved(d) if {
	d.claims.secboot
	d.claims.dbgstat == "disabled"
	d.claims["x-nvidia-gpu-vbios-version"] in query_reference_value("allowed_vbios_versions")
	d.claims["x-nvidia-gpu-driver-version"] in query_reference_value("allowed_driver_versions")
}

gpu_configuration_secure(d) if {
	d.claims.secboot
	d.claims.dbgstat == "disabled"
}

gpu_executables_ok(d) if {
	d.claims["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] == "good"
	d.claims["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"

	d.claims["x-nvidia-gpu-driver-rim-fetched"]
	d.claims["x-nvidia-gpu-driver-rim-measurements-available"]
	d.claims["x-nvidia-gpu-driver-rim-schema-validated"]
	d.claims["x-nvidia-gpu-driver-rim-signature-verified"]
	d.claims["x-nvidia-gpu-driver-rim-version-match"]

	d.claims["x-nvidia-gpu-vbios-rim-fetched"]
	d.claims["x-nvidia-gpu-vbios-rim-measurements-available"]
	d.claims["x-nvidia-gpu-vbios-rim-schema-validated"]
	d.claims["x-nvidia-gpu-vbios-rim-signature-verified"]
	d.claims["x-nvidia-gpu-vbios-rim-version-match"]

	d.claims.measres == "success"
}
