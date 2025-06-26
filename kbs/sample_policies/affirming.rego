package policy
import rego.v1

default allow = false

allow if {
    input["submods"]["cpu0"]["ear.status"] == "affirming"
}
