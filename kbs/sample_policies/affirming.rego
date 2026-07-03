package policy
import rego.v1

default allow = false

allow if {
    # verification_result is true means the all submodules in the attestation token are affirming
    input.trust_context.attestation_summary.verification_result == true
    count(input.trust_context.attestation_summary.claims) > 0
}
