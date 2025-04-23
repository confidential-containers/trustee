package policy
import rego.v1

default allow = false

allow if {
    input["submods"]["cpu"]["ear.status"] == "affirming"
}
