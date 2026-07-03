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
# 1. Trust Context Input
#    A backend-agnostic representation of the attestation result produced by
#    KBS. Example:
#    ```
#    {
#        "trust_context": {
#            "attestation_summary": {
#                "tee_type": ["tdx"],
#                "policy_ids": ["default"],
#                "issuer": "https://as.operator-a.example",
#                "verification_result": true,
#                "claims": { ... AS backend token claims ... }
#            },
#            "tee_pubkey": { ... },
#            "custom_claims": { ... AS side user defined runtime data claims ... }
#        }
#    }
#    ```
#    Field notes:
#      - `verification_result`: the backend attestation service affirmed the
#        evidence. This is the single flag most policies need.
#      - `issuer`: identity of the attestation service that issued the result,
#        taken from the verified token. Use it to distinguish different
#        operators of the same kind of attestation service.
#      - `claims`: the backend token claims, available for advanced
#        policies that need to inspect TEE-specific details (e.g. measurements).
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
# 
# This default policy will only allow accesses to the "resource" plugin if the
# backend attestation service affirmed the evidence, as reflected in the trust
# context's attestation summary.

package policy

default allow = false

plugin = data.plugin

allow if {
	plugin == "resource"
	input.trust_context.attestation_summary.verification_result == true
}

# Example: scope access to a specific attestation service operator.
#
# Beyond simply requiring that the evidence was affirmed, a deployment can
# restrict a plugin to results issued by a trusted operator by matching on the
# `issuer`. Uncomment and adapt as needed:
#
# allow if {
# 	plugin == "resource"
# 	input.trust_context.attestation_summary.verification_result == true
# 	input.trust_context.attestation_summary.issuer == "https://as.operator-a.example"
# }
