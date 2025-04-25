package test.terraform.analysis

import data.terraform.analysis

test_allow_if_no_sns_module if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": [],
		"configuration": {"root_module": {"module_calls": {"offender_events": {"expressions": {"namespace": {"references": ["var.namespace"]}, "topic_arn": {"references": ["var.foobar"]}, "endpoint": {"references": ["var.namespace"]}}}}}},
	}

	res.valid
	res.msg == "Valid sns related terraform changes"
}

test_allow_if_sns_module_create if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"offender_events": {"expressions": {"namespace": {"references": ["var.namespace"]}, "topic_arn": {"references": ["var.foobar"]}, "endpoint": {"references": ["var.namespace"]}}}}}},
	}

	res.valid
	res.msg == "Valid sns related terraform changes"
}

test_allow_if_sns_ns_correct_hardcoded if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"offender_events": {"expressions": {"namespace": {"constant_value": "jaskaran-dev"}, "topic_arn": {"references": ["var.foobar"]}, "endpoint": {"references": ["var.namespace"]}}}}}},
	}

	res.valid
	res.msg == "Valid sns related terraform changes"
}

test_allow_if_sns_ns_incorrect_hardcoded if {
	res := analysis.allow with input as {
		"variables": mock_tfplan.variables,
		"resource_changes": mock_tfplan.resource_changes,
		"configuration": {"root_module": {"module_calls": {"offender_events": {"expressions": {"namespace": {"constant_value": "WRONG"}, "topic_arn": {"references": ["var.foobar"]}, "endpoint": {"references": ["var.namespace"]}}}}}},
	}

	not res.valid
	res.msg == "We can't auto approve these sns terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_with_note_if_sns_update_rename if {
	res := analysis.allow with input as {
		"variables": mock_tfplan_update.variables,
		"resource_changes": mock_tfplan_update.resource_changes,
		"configuration": {"root_module": {"module_calls": {"offender_events": {"expressions": {"namespace": {"references": ["var.namespace"]}, "topic_arn": {"references": ["var.foobar"]}, "endpoint": {"references": ["var.namespace"]}}}}}},
	}

	res.valid
	res.msg == "NOTE: Terraform topic name change detected. [See here for more info](https://github.com/ministryofjustice/cloud-platform-terraform-sns-topic?tab=readme-ov-file#team-name-caveat)"
}
