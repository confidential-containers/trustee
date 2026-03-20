package policy

import rego.v1

default hardware := 0

default executables := 0

# Currently, the PPCIE device class is only added
# when a valid PPCIE topology is found.
# Thus, the configuration is known to be valid.
# For information about the switches and gpus used
# in PPCIE, refer to the individual device submods.
default configuration := 2

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
