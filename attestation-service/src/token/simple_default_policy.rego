# Attestation Service Default Policy
#
# The function of this policy is to adopt the default policy when no custom policy
# is provided in the attestation request of Attestation Service.
#
# - The input data required by this default policy is a set of key value pairs:
#
#	{
#		"sample1": "112233",
#		"sample2": "332211",
#		...
#	}
#
# - The format of reference data required by this default policy is defined as follows:
#
#	{
#		"reference": {
#			"sample1": ["112233", "223311"],
#			"sample2": "332211",
#			"sample3": [],
#			...
#		}
#	}
#
# If the default policy is used for verification, the reference meeting the above format
# needs to be provided in the attestation request, otherwise the Attestation Service will
# automatically generate a reference data meeting the above format.
package policy

import future.keywords.every
import future.keywords.if

default allow := false

allow if {
	every k, v in input {
		# `judge_field`: Traverse each key value pair in the input and make policy judgments on it.
		#
		# For each key value pair:
		#	* If there isn't a corresponding key in the reference:
		#		It is considered that the current key value pair has passed the verification.
		#	* If there is a corresponding key in the reference:
		#		Call `match_value` to further judge the value in input with the value in reference.
		judge_field(k, v)
	}
}

judge_field(input_key, input_value) if {
	has_key(data.reference, input_key)
	reference_value := data.reference[input_key]

	# `match_value`: judge the value in input with the value in reference.
	#
	# * If the type of reference value is not array:
	#		Judge whether input value and reference value are equal。
	# * If the type of reference value is array:
	#		Call `array_include` to further judge the input value with the values in the array.
	match_value(reference_value, input_value)
}

judge_field(input_key, input_value) if {
	not has_key(data.reference, input_key)
}

match_value(reference_value, input_value) if {
	not is_array(reference_value)
	input_value == reference_value
}

match_value(reference_value, input_value) if {
	is_array(reference_value)

	# `array_include`: judge the input value with the values in the array.
	#
	# * If the reference value array is empty:
	#		It is considered that the current input value has passed the verification.
	# * If the reference value array is not empty:
	#		Judge whether there is a value equal to input value in the reference value array.
	array_include(reference_value, input_value)
}

array_include(reference_value_array, input_value) if {
	reference_value_array == []
}

array_include(reference_value_array, input_value) if {
	reference_value_array != []
	some i
	reference_value_array[i] == input_value
}

has_key(m, k) if {
	_ = m[k]
}
