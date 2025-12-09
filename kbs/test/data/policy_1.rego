package policy

default allow = false

subpaths := split(data["resource-path"], "/")

allow if {
    count(subpaths) == 4
    data.plugin == "resource"
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == subpaths[2]
}
