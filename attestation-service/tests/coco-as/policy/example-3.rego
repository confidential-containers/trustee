package policy
import rego.v1
default executables := 33

converted_version := sprintf("%v", [input["se.version"]])

executables := 3 if {
	converted_version == "256"
	input["se.user_data"] == "00"
	input["se.tag"] == "773780962a7350165054673b6c54235d"
	input["se.image_phkh"] == "92d0aff6eb86719b6b1ea0cb98d2c99ff2ec693df3efff2158f54112f6961508"
	input["se.attestation_phkh"] == "92d0aff6eb86719b6b1ea0cb98d2c99ff2ec693df3efff2158f54112f6961508"
}
