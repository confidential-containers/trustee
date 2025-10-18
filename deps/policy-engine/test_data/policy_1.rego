package policy

default result = false

path := split(data["resource-path"], "/")

result {
    count(path) == 3
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["productId"] == path[1]
}
