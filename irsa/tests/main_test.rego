package test.terraform.analysis

import data.terraform.analysis

test_allow if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"ap_irsa": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}}}}},
	}
	result.valid
	result.msg == "Valid irsa related terraform changes"
}

test_allow_multiple_irsa if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_multiple_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {
			"ap_irsa": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}},
			"foobar": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}},
		}}},
	}
	result.valid
	result.msg == "Valid irsa related terraform changes"
}

test_allow_multiple_roles if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_multiple_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {
			"ap_irsa": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}},
			"foobar": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}},
		}}},
	}
	result.valid
	result.msg == "Valid irsa related terraform changes"
}

test_deny_hard_coded_arn if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_multiple_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {
			"ap_irsa": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"constant_value": {"s3": "arn:aws:iam::992382429243:role/foobar"}}}},
			"foobar": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}},
		}}},
	}
	not result.valid
	result.msg == "We can't auto approve these irsa terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_deny_mismatched_irsa_and_iam_assumable_role if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_mismatch_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"ap_irsa": {"expressions": {"namespace": {"references": ["var.namespace"]}, "role_policy_arns": {"references": ["var.foobar"]}}}}}},
	}
	not result.valid
	result.msg == "We can't auto approve these irsa terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_deny_is_namespace_var_incorrect if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"ap_irsa": {"expressions": {"namespace": {"references": ["WRONG"]}, "role_policy_arns": {"references": ["var.foobar"]}}}}}},
	}
	not result.valid
	result.msg == "We can't auto approve these irsa terraform changes. Your are trying to modify resources in a different namespace. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_deny_hard_coded_incorrect_ns if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"ap_irsa": {"expressions": {"namespace": {"constant_value": "WRONG"}, "role_policy_arns": {"references": ["var.foobar"]}}}}}},
	}
	not result.valid
	result.msg == "We can't auto approve these irsa terraform changes. Your are trying to modify resources in a different namespace. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_hard_coded_correct_ns if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": irsa_create_mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"ap_irsa": {"expressions": {"namespace": {"constant_value": "testing-ns"}, "role_policy_arns": {"references": ["var.foobar"]}}}}}},
	}
	result.valid
	result.msg == "Valid irsa related terraform changes"
}

test_allow_irsa_if_called_by_another_module if {
	result := analysis.allow with input as {
		"variables": {"namespace": {"value": "testing-ns"}},
		"resource_changes": submodule_irsa.resource_changes,
		"configuration": {"root_module": {"module_calls": {"ap_irsa": {"expressions": {"namespace": {"constant_value": "testing-ns"}, "role_policy_arns": {"references": ["var.foobar"]}}}}}},
	}
	result.valid
	result.msg == "Valid irsa related terraform changes"
}
