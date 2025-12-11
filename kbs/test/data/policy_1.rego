package policy

default allow = false

allow if {
    count(data["resource-path"]) == 3
    data.plugin == "resource"
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == data["resource-path"][1]
}
