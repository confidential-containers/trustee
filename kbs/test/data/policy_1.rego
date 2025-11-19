package policy

default allow = false

path := split(data["resource-path"], "/")

allow if {
    count(path) == 3
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == path[1]
}
