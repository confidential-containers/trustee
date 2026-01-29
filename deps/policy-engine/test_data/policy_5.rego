package policy

# Opt-in to the breaking changes coming in rego v1
import rego.v1

default allow := false


# mapping of resource ids to minimum SVNs
resources := {"secret1": 2, "secret2": 3}

allow if {
    # check that evidence comes from expected platform
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]

    # check repository_name and resource_type
    data.plugin == "resource"

    data["resource-path"][0] == "myrepo"
    data["resource-path"][1] == "secret"
    # check that the secret name exists and tht the minimum svn is met
    resources[data["resource-path"][2]] <= input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["svn"]
    
}
