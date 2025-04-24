package test.terraform.analysis

import data.terraform.analysis

test_deny_only_noop_sm if {
	modified_plan := {
		"address": "module.foobar.kubernetes_manifest.secret_store",
    "module_address": "module.foobar",
		"change": {
			"actions": ["no-op"],
			"before": {"name": "jazz-test"},
			"after": {"name": "jazz-test"},
		},
	}

	res := analysis.allow with input as {"resource_changes": [modified_plan]}
	not res.valid
	res.msg == "This PR includes changes to modules / resources which are not on the allowlist, so we can't auto approve these changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_sm if {
	modified_plan := {
		"address": "module.foobar.kubernetes_manifest.secret_store",
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

