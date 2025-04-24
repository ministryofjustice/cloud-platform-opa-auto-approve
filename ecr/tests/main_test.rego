package test.terraform.analysis

import data.terraform.analysis

test_allow_default if {
	result := analysis.allow with input as {
		"variables": {"team_name": {"value": "mikebell-test"}, "namespace": {"value": "mikebell-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": ecr_create_mock_tfplan.resource_changes,
	}

	result.valid
	result.msg == "Valid ECR related terraform changes"
}

test_allow_if_op_update if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test/jazz-test"},
		},
	}
	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": [modified_plan],
	}

	res.msg == "Valid ECR related terraform changes"
	res.valid == true
}

test_allow_if_op_update_changes_name if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test-changed"},
		},
	}

	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "var.namespace"}, "namespace": {"value": "wrong-one"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": [modified_plan, ecr_create_mock_tfplan.resource_changes],
	}

	res.msg == "NOTE: Terraform `team_name` / `repo_name` change detected. ECR repository names cannot be updated in place to reflect these changes. [See here](https://user-guide.cloud-platform.service.justice.gov.uk/documentation/other-topics/aws-resource-naming-issue.html)"
	res.valid == true
}

test_allow_if_op_update_multiple_ecr if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test/jazz-test"},
		},
	}

	modified_plan_2 := {
		"module_address": "module.ecr2",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test/jazz-test"},
		},
	}

	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr2": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}, "ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": [modified_plan],
	}

	res.msg == "Valid ECR related terraform changes"
	res.valid == true
}

test_allow_if_op_destroy if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["delete"],
			"before": {"name": "this", "force_delete": true},
			"after": {"name": "jazz-test/jazz-test", "force_delete": true},
		},
	}

	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": [modified_plan, ecr_create_mock_tfplan.resource_changes],
	}
	res.msg == "Valid ECR related terraform changes"
	res.valid == true
}

test_allow_if_op_destroy_with_no_protect if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["delete"],
			"before": {"name": "this", "force_delete": true},
			"after": {"name": "jazz-test/jazz-test", "force_delete": true},
		},
	}

	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": [modified_plan, ecr_create_mock_tfplan.resource_changes],
	}
	res.valid == true
	res.msg == "Valid ECR related terraform changes"
}

test_deny_if_op_destroy if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["delete"],
			"after": {"force_delete": false},
			"name": "jazz-test/jazz-test",
		},
	}

	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"], "namespace": {"references": ["var.namespace"]}}}}}}},
		"resource_changes": [modified_plan, ecr_create_mock_tfplan.resource_changes],
	}

	res.valid == false
	res.msg == "We can't auto approve these ECR terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_if_op_module_rename if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["create", "delete"],
			"before": {"name": "jazz-test"},
			"after": {
				"name": "jazz-test/jazz-test",
				"force_delete": true,
			},
		},
	}

	res := analysis.allow with input as {
		"variables": {"team_name": {"value": "changed"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"references": ["var.namespace"]}}}}}},
		"resource_changes": [modified_plan, ecr_create_mock_tfplan.resource_changes],
	}

	res.valid == true
	res.msg == "NOTE: Terraform `team_name` / `repo_name` change detected. ECR repository names cannot be updated in place to reflect these changes. [See here](https://user-guide.cloud-platform.service.justice.gov.uk/documentation/other-topics/aws-resource-naming-issue.html)"
}

test_allow_if_does_not_contain_ecr if {
	analysis.allow.valid with input as {"resource_changes": []}
}

test_allow_if_hardcoded_namespace_var if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test/jazz-test"},
			"after": {"name": "jazz-test/jazz-test"},
		},
	}

	result := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"constant_value": "jazz-test"}}}}}},
		"resource_changes": [modified_plan],
	}

	result.valid
	result.msg == "Valid ECR related terraform changes"
}

test_deny_if_hardcoded_namespace_var if {
	modified_plan := {
		"module_address": "module.ecr",
		"type": "aws_ecr_repository",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test/jazz-test"},
			"after": {"name": "jazz-test/jazz-test"},
		},
	}

	result := analysis.allow with input as {
		"variables": {"team_name": {"value": "jazz-test"}, "namespace": {"value": "jazz-test"}},
		"configuration": {"root_module": {"module_calls": {"ecr": {"expressions": {"repo_name": {"references": ["var.namespace"]}, "namespace": {"constant_value": "wrong"}}}}}},
		"resource_changes": [modified_plan],
	}

	not result.valid
	result.msg == "We can't auto approve these ECR terraform changes. You're trying to modify a ECR not in your namespace. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}
