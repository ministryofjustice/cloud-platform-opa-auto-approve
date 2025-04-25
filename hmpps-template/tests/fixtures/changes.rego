package test.terraform.analysis

mock_tfplan := {
	"variables": {"namespace": {"value": "jaskaran-dev"}},
	"resource_changes": [{
		"address": "module.hmpps-tier-api.module.service_account.kubernetes_role.github_actions_role",
		"module_address": "module.hmpps-tier-api.module.service_account",
		"mode": "managed",
		"type": "kubernetes_role",
		"name": "github_actions_role",
		"provider_name": "registry.terraform.io/hashicorp/kubernetes",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {},
			"before_sensitive": false,
		},
	}],
}
