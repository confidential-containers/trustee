package policy

default allow = false

path := split(data["resource-path"], "/")
input_tcb := input["tcb-status"]

allow {
    count(path) == 3
    input_tcb.productId == path[1]
}