package policy

default allow = false

plugin = data.plugin

allow if {
	plugin == "resource"
}

