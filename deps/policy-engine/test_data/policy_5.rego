package policy

# Opt-in to the breaking changes coming in rego v1
import rego.v1

default result := false

# path should be of form `repository_name/resource_type/resource_name`
path := split(data["resource-path"], "/")

# mapping of resource ids to minimum SVNs
resources := {"secret1": 2, "secret2": 3}

result if {
    # check that evidence comes from expected platform
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]

    # check tht resource path is valid
    count(path) == 3

    # check repository_name and resource_type
    path[0] == "myrepo"
    path[1] == "secret"

    # check that the secret name exists and tht the minimum svn is met
    resources[path[2]] <= input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]["svn"]
    
}
