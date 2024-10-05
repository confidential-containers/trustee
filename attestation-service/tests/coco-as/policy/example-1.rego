package policy

import rego.v1

default executables := 33

executables := 3 if {
	input["sgx.body.mr_enclave"] == "8f173e4613ff05c52aaf04162d234edae8c9977eae47eb2299ae16a553011c68"
	input["sgx.body.mr_signer"] == "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e"
}
