package policy
import rego.v1

default allow = false

allow if {
    not any_not_affirming
    count(input.submods) > 0

}

any_not_affirming if {
    some _, submod in input.submods
    submod["ear.status"] != "affirming"
}
