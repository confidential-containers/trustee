# Test policy to make sure that extra lines do not break the KBS






package policy

default allow = false

path := split(data["resource-path"], "/")
input_tcb := input["tcb-status"]

allow {
    count(path) == 3






    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == path[1]
}







