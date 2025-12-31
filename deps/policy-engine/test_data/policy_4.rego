# Test policy to make sure that extra lines do not break the KBS






package policy

default allow = false

input_tcb := input["tcb-status"]

allow if {
    count(data["resource-path"]) == 3
    data.plugin == "resource"






    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == data["resource-path"][1]
}







