package test.terraform.analysis

import data.terraform.analysis

test_deny_only_noop_irsa if {
	modified_plan := [
{
			"address": "module.ap_irsa.kubernetes_service_account.fake",
			"module_address": "module.irsa_fake",
			"mode": "managed",
			"type": "kubernetes_service_account",
			"name": "generated_sa",
			"provider_name": "registry.terraform.io/hashicorp/kubernetes",
			"change": {
				"actions": ["create"],
				"before": null,
			},
		},
		{
			"address": "module.ap_irsa.kubernetes_service_account.generated_sa",
			"module_address": "module.ap_irsa",
			"mode": "managed",
			"type": "kubernetes_service_account",
			"name": "generated_sa",
			"provider_name": "registry.terraform.io/hashicorp/kubernetes",
			"change": {
				"actions": ["no-op"],
				"before": null,
			},
		},
		{
			"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role.this[0]",
			"module_address": "module.ap_irsa.module.iam_assumable_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "this",
			"change": {
				"actions": ["no-op"],
				"before": null,
			},
		},
	]

	res := analysis.allow with input as {"resource_changes": modified_plan}
	not res.valid
	res.msg == "This PR includes changes to modules / resources which are not on the allowlist, so we can't auto approve these changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_irsa if {
	modified_plan := [
		{
			"address": "module.ap_irsa.kubernetes_service_account.generated_sa",
			"module_address": "module.ap_irsa",
			"mode": "managed",
			"type": "kubernetes_service_account",
			"name": "generated_sa",
			"provider_name": "registry.terraform.io/hashicorp/kubernetes",
			"change": {
				"actions": ["create"],
				"before": null,
			},
		},
		{
			"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role.this[0]",
			"module_address": "module.ap_irsa.module.iam_assumable_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "this",
			"change": {
				"actions": ["create"],
				"before": null,
			},
		},
	]

	res := analysis.allow with input as {"resource_changes": modified_plan}
	res.valid
	res.msg == "Valid changes the PR meets the module allowlist criteria for auto approval"
}
