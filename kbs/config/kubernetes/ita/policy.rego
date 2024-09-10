# Resource Policy
# ---------------
#
# The resource policy of KBS is to make a strategic decision on
# whether the requester has access to resources based on the
# input Attestation Claims (including tee-pubkey, tcb-status, and other information)
# and KBS Resource Path.
#
# The format of the resource path data is:
# ```
# {
# 	  "resource-path": <PATH>
# }
# ```
#
# The <PATH> variable is a KBS resource path,
# which is required to be a string in three segment path format:<TOP>/<MIDDLE>/<TAIL>,
# for example: "my'repo/License/key".
#
# The format of Attestation Claims Input is defined by the attestation service,
# and its format may look like the following:
# ```
# {
#     "tee-pubkey": "",
#     "tcb-status": {
#         "productId": “”,
#         "svn": “”,
# 		  ……
#     }
#	  ……
# }
# ```
# NB: beware of the differences when re-using CoCo-AS rego policies with ITA
# tokens.

package policy

default allow = false

allow {
	input["attester_type"] != "sample"
}
