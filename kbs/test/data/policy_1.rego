package policy

default allow = false

path := split(data["resource-path"], "/")

allow {
    count(path) == 3
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == path[1]
}
