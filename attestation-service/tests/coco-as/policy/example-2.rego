package policy

import rego.v1

default executables := 33

executables := 3 if {
	input["tdx.quote.body.mr_td"] == "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031"
	input["tdx.quote.body.mr_seam"] == "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656"
	input["tdx.ccel.kernel"] == "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa"
}
