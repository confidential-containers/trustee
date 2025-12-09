# Test policy to make sure that extra lines do not break the KBS






package policy

default allow = false

input_tcb := input["tcb-status"]
subpaths := split(data["resource-path"], "/")

allow if {
    count(subpaths) == 4
    data.plugin == "resource"






    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == subpaths[2]
}







