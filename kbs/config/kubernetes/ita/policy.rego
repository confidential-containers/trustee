# KBS Resource Policy
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
# 2. Resource Path data
#    A KBS plugin call upon <plugin-name> to KBS server's path usually has format
#    `/kbs/v0/<plugin-name>/.../<END>[?a=b&...&<QUERY>]`
#    It will be parsed into three parts in a structured format as policy data:
#    ```
#    {
#        "plugin": <plugin-name>,
#        "resource-path": [<...>, <sections>, <END>],
#        "query": {
#            "a": "b",
#            ...
#        }
#    }
#    ```
#    Examples:
#    1. "resource/myrepo/License/key"
#    ```
#    {
#        "plugin": "resource",
#        "resource-path": ["myrepo", "License", "key"],
#        "query": {}
#    }
#    ```
#    2. "plugin1/para/meters?version=1.0.0"
#    ```
#    {
#        "plugin": "plugin1",
#        "resource-path": ["para", "meters"],
#        "query": {
#           "version": "1.0.0"
#        }	
#    }
#    ```
#
#    For the "resource" plugin specifically:
#      - resource-path format: three items slice
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
