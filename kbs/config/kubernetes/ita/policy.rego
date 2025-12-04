# KBS Request Policy
# ==================
#
# Purpose
# -------
# This policy makes strategic decisions on whether a requester has access to
# plugin based on:
#   - Input Attestation Claims (including tee-pubkey, tcb-status, and other information)
#   - The plugin name, sub path and http query fields
#
# Input Data Format
# -----------------
#
# 1. Attestation Claims Input
#    The format is defined by the attestation service. Example:
#    ```
#    {
#        "submods": {
#            "cpu0": {
#                "ear.veraison.annotated-evidence": {
#                    "sample": {
#                        "productId": "",
#                        "svn": ""
#                    }
#                }
#            }
#        }
#    }
#    ```
#
# 2. Resource Path Data (available via data.plugin)
#    The resource path is parsed into a structured format:
#    ```
#    {
#        "plugin": <plugin-name>,
#        "subpath": </.../<END>>,
#        "query": {
#            "a": "b",
#            ...
#        }
#    }
#    ```
#
#    The original path string format is: <plugin-name>/.../<END>[?a=b&...&<QUERY>]
#    Examples:
#      - "resource/myrepo/License/key"
#      - "<plugin-name>/para/meters?version=1.0.0"
#
#    For the "resource" plugin specifically:
#      - subpath format: /<repo>/<type>/<tag>
#      - query: {}
#
# Policy Rules
# ------------
# The policy evaluates access based on the above inputs. See the allow rules
# below for specific conditions.

package policy

default allow = false

allow if {
	data.plugin == "resource"
	input["tdx"]["attester_type"] != "sample"
}
