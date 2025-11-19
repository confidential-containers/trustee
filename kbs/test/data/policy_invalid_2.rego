package policy

default allowed = false

path := split(data["resource-path"], "/")
input_tcb := input["tcb-status"]

allowed if {
    count(path) == 3
    input_tcb.productId == path[1]
}
