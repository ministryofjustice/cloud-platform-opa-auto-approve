package test.terraform.analysis

import data.terraform.analysis

test_allow_if_no_hmpps_module if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": [],
		"configuration": {"root_module": {"module_calls": {"hmpps-tier-api": {"expressions": {"namespace": {"references": ["var.namespace"]}}}}}},
	}

	res.valid
	res.msg == "Valid hmpps template related terraform changes"
}

test_allow_if_hmpps_module_create if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"hmpps-tier-api": {"expressions": {"namespace": {"references": ["var.namespace"]}}}}}},
	}

	res.valid
	res.msg == "Valid hmpps template related terraform changes"
}

test_allow_if_secret_ns_correct_hardcoded if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"hmpps-tier-api": {"expressions": {"namespace": {"constant_value": "jaskaran-dev"}}}}}},
	}

	res.valid
	res.msg == "Valid hmpps template related terraform changes"
}

test_allow_if_secret_ns_incorrect_hardcoded if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"hmpps-tier-api": {"expressions": {"namespace": {"constant_value": "WRONG"}}}}}},
	}

	not res.valid
	res.msg == "We can't auto approve these hmpps template terraform changes as they make changes in another namespace. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}
