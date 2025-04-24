package test.terraform.analysis

mock_tfplan := {
	"variables": {"namespace": {"value": "jaskaran-dev"}},
	"resource_changes": [{
		"address": "module.secrets_manager.kubernetes_manifest.secret_store",
		"module_address": "module.secrets_manager",
		"mode": "managed",
		"type": "kubernetes_manifest",
		"name": "secret_store",
		"provider_name": "registry.terraform.io/hashicorp/kubernetes",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"computed_fields": null,
				"field_manager": [],
				"timeouts": [],
				"wait": [],
				"wait_for": null,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"field_manager": [],
				"manifest": {
					"metadata": {"labels": {}},
					"spec": {"provider": {"aws": {"auth": {"jwt": {"serviceAccountRef": {}}}}}},
				},
				"object": {
					"metadata": {
						"annotations": {},
						"finalizers": [],
						"labels": {},
						"managedFields": [],
						"ownerReferences": [],
					},
					"spec": {},
				},
				"timeouts": [],
				"wait": [],
			},
		},
	}],
}
