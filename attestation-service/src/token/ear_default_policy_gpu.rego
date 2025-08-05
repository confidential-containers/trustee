package policy

import rego.v1

default hardware := 97

hardware := 2 if {
	input.sampledevice.svn in data.reference.device_svn
}
