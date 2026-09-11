package policy

default allow = false

allow if {
    count(data["resource-path"]) == 3
    data.plugin == "resource"
    input["submods"]["cpu0"]["ear_attester_claims"]["claims"]["productId"] == data["resource-path"][1]
}
