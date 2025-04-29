package test.terraform.analysis

import data.terraform.analysis

test_deny_only_noop_sns if {
	modified_plan := [
	{
		"address": "module.foobar.aws_sns_topic.new_topic",
		"module_address": "module.foobar",
		"change": {
			"actions": ["no-op"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	},
	{
		"address": "module.barbuzz.fake_topic",
		"module_address": "module.barbuzz",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	},
	]

	res := analysis.allow with input as {"resource_changes": modified_plan}
	not res.valid
	res.msg == "This PR includes changes to modules / resources which are not on the allowlist, so we can't auto approve these changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_sns if {
	modified_plan := {
		"address": "module.foobar.aws_sns_topic.new_topic",
		"module_address": "module.foobar",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	}

	res := analysis.allow with input as {"resource_changes": [modified_plan]}
	res.valid
	res.msg == "Valid changes the PR meets the module allowlist criteria for auto approval"
}

test_deny_only_noop_sns_sub if {
	modified_plan := [{
		"address": "module.foobar.aws_sns_topic.new_topic",
		"type": "aws_sns_topic_subscription",
		"change": {
			"actions": ["no-op"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	},

	{
		"address": "module.barbuzz.fake_topic",
		"module_address": "module.barbuzz",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	},]

	res := analysis.allow with input as {"resource_changes": modified_plan}
	not res.valid
	res.msg == "This PR includes changes to modules / resources which are not on the allowlist, so we can't auto approve these changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_sns_sub if {
	modified_plan := {
		"address": "module.foobar.aws_sns_topic.new_topic",
		"type": "aws_sns_topic_subscription",
		"change": {
			"actions": ["update"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	}

	res := analysis.allow with input as {"resource_changes": [modified_plan]}
	res.valid
	res.msg == "Valid changes the PR meets the module allowlist criteria for auto approval"
}

