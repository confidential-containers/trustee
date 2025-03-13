package policy

import rego.v1

# This policy is used to generate an EAR Appraisal for Arm CCA Realms
# See https://github.com/veraison/docs/blob/ar4si/ar4si/arm-cca.md

# For the `hardware` trust claim, the value 2 stands for
# "An Attester has passed its hardware and/or firmware
#  verifications needed to demonstrate that these are genuine/
#  supported."
# Since platform appraisal is successful, this is implied.
default hardware := 2

# The value 2 stands for
# "The Attesting Environment is recognized, and the associated
# instance of the Attester is not known to be compromised."
# Since platform appraisal is successful and the RAK binding is confirmed,
# the instance is known and in good shape.
default instance_identity := 2

# The value 2 stands for
# "The Attester's executing Target Environment and Attesting
#  Environments are encrypted and within Trusted Execution
#  Environment(s) opaque to the operating system, virtual machine
#  manager, and peer applications."
# Since platform appraisal is successful, this is implied.
default runtime_opaque := 2

# For the `executables` trust claim, the value 33 stands for
# "Runtime memory includes executables, scripts, files, and/or
#  objects which are not recognized."
# This is the default, unless the RIM claim matches one of the configured
# reference values.
default executables := 33
# The value 3 stands for
# "Only a recognized genuine set of approved executables have
#  been loaded during the boot process."
# the RIM (realm initial measurement) must match
executables := 3 if {
	input.cca.realm["cca-realm-initial-measurement"] in data.reference["cca.realm.cca-realm-initial-measurement"]
}
