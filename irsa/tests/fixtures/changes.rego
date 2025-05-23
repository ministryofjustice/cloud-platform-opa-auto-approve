package test.terraform.analysis

irsa_create_mock_tfplan := {"resource_changes": [
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
			"after": {
				"automount_service_account_token": true,
				"image_pull_secret": [],
				"metadata": [{
					"generate_name": null,
					"labels": null,
					"namespace": "jaskaran-dev",
				}],
				"secret": [],
				"timeouts": null,
			},
			"after_unknown": {
				"default_secret_name": true,
				"id": true,
				"image_pull_secret": [],
				"metadata": [{
					"annotations": true,
					"generation": true,
					"name": true,
					"resource_version": true,
					"uid": true,
				}],
				"secret": [],
			},
			"before_sensitive": false,
			"after_sensitive": {
				"image_pull_secret": [],
				"metadata": [{"annotations": {}}],
				"secret": [],
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"description": null,
				"force_detach_policies": true,
				"max_session_duration": 3600,
				"path": "/",
				"permissions_boundary": null,
				"tags": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
				"tags_all": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
			},
			"after_unknown": {
				"arn": true,
				"assume_role_policy": true,
				"create_date": true,
				"id": true,
				"inline_policy": true,
				"managed_policy_arns": true,
				"name": true,
				"name_prefix": true,
				"tags": {},
				"tags_all": {},
				"unique_id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"inline_policy": [],
				"managed_policy_arns": [],
				"tags": {},
				"tags_all": {},
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role_policy_attachment.this[\"s3\"]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role_policy_attachment",
		"name": "this",
		"index": "s3",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {},
			"after_unknown": {
				"id": true,
				"policy_arn": true,
				"role": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.data.aws_iam_policy_document.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "data",
		"type": "aws_iam_policy_document",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["read"],
			"before": null,
			"after": {
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": ["sts:AssumeRoleWithWebIdentity"],
					"condition": [
						{
							"test": "StringEquals",
							"values": ["sts.amazonaws.com"],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:aud",
						},
						{
							"test": "StringEquals",
							"values": [null],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:sub",
						},
					],
					"effect": "Allow",
					"not_actions": null,
					"not_principals": [],
					"not_resources": null,
					"principals": [{
						"identifiers": ["arn:aws:iam::754256621582:oidc-provider/oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09"],
						"type": "Federated",
					}],
					"resources": null,
					"sid": null,
				}],
				"version": null,
			},
			"after_unknown": {
				"id": true,
				"json": true,
				"minified_json": true,
				"statement": [{
					"actions": [false],
					"condition": [
						{"values": [false]},
						{"values": [true]},
					],
					"not_principals": [],
					"principals": [{"identifiers": [false]}],
				}],
			},
			"before_sensitive": false,
			"after_sensitive": {"statement": [{
				"actions": [false],
				"condition": [
					{"values": [false]},
					{"values": [false]},
				],
				"not_principals": [],
				"principals": [{"identifiers": [false]}],
			}]},
		},
		"action_reason": "read_because_config_unknown",
	},
	{
		"address": "module.ap_irsa.random_id.id",
		"module_address": "module.ap_irsa",
		"mode": "managed",
		"type": "random_id",
		"name": "id",
		"provider_name": "registry.terraform.io/hashicorp/random",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"byte_length": 8,
				"keepers": null,
				"prefix": null,
			},
			"after_unknown": {
				"b64_std": true,
				"b64_url": true,
				"dec": true,
				"hex": true,
				"id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
]}

irsa_multiple_create_mock_tfplan := {"resource_changes": [
	{
		"address": "module.foobar.kubernetes_service_account.generated_sa",
		"module_address": "module.foobar",
		"mode": "managed",
		"type": "kubernetes_service_account",
		"name": "generated_sa",
		"provider_name": "registry.terraform.io/hashicorp/kubernetes",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"automount_service_account_token": true,
				"image_pull_secret": [],
				"metadata": [{
					"generate_name": null,
					"labels": null,
					"namespace": "jaskaran-dev",
				}],
				"secret": [],
				"timeouts": null,
			},
			"after_unknown": {
				"default_secret_name": true,
				"id": true,
				"image_pull_secret": [],
				"metadata": [{
					"annotations": true,
					"generation": true,
					"name": true,
					"resource_version": true,
					"uid": true,
				}],
				"secret": [],
			},
			"before_sensitive": false,
			"after_sensitive": {
				"image_pull_secret": [],
				"metadata": [{"annotations": {}}],
				"secret": [],
			},
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
			"actions": ["create"],
			"before": null,
			"after": {
				"automount_service_account_token": true,
				"image_pull_secret": [],
				"metadata": [{
					"generate_name": null,
					"labels": null,
					"namespace": "jaskaran-dev",
				}],
				"secret": [],
				"timeouts": null,
			},
			"after_unknown": {
				"default_secret_name": true,
				"id": true,
				"image_pull_secret": [],
				"metadata": [{
					"annotations": true,
					"generation": true,
					"name": true,
					"resource_version": true,
					"uid": true,
				}],
				"secret": [],
			},
			"before_sensitive": false,
			"after_sensitive": {
				"image_pull_secret": [],
				"metadata": [{"annotations": {}}],
				"secret": [],
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"description": null,
				"force_detach_policies": true,
				"max_session_duration": 3600,
				"path": "/",
				"permissions_boundary": null,
				"tags": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
				"tags_all": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
			},
			"after_unknown": {
				"arn": true,
				"assume_role_policy": true,
				"create_date": true,
				"id": true,
				"inline_policy": true,
				"managed_policy_arns": true,
				"name": true,
				"name_prefix": true,
				"tags": {},
				"tags_all": {},
				"unique_id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"inline_policy": [],
				"managed_policy_arns": [],
				"tags": {},
				"tags_all": {},
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role_policy_attachment.this[\"s3\"]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role_policy_attachment",
		"name": "this",
		"index": "s3",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {},
			"after_unknown": {
				"id": true,
				"policy_arn": true,
				"role": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.data.aws_iam_policy_document.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "data",
		"type": "aws_iam_policy_document",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["read"],
			"before": null,
			"after": {
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": ["sts:AssumeRoleWithWebIdentity"],
					"condition": [
						{
							"test": "StringEquals",
							"values": ["sts.amazonaws.com"],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:aud",
						},
						{
							"test": "StringEquals",
							"values": [null],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:sub",
						},
					],
					"effect": "Allow",
					"not_actions": null,
					"not_principals": [],
					"not_resources": null,
					"principals": [{
						"identifiers": ["arn:aws:iam::754256621582:oidc-provider/oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09"],
						"type": "Federated",
					}],
					"resources": null,
					"sid": null,
				}],
				"version": null,
			},
			"after_unknown": {
				"id": true,
				"json": true,
				"minified_json": true,
				"statement": [{
					"actions": [false],
					"condition": [
						{"values": [false]},
						{"values": [true]},
					],
					"not_principals": [],
					"principals": [{"identifiers": [false]}],
				}],
			},
			"before_sensitive": false,
			"after_sensitive": {"statement": [{
				"actions": [false],
				"condition": [
					{"values": [false]},
					{"values": [false]},
				],
				"not_principals": [],
				"principals": [{"identifiers": [false]}],
			}]},
		},
		"action_reason": "read_because_config_unknown",
	},
	{
		"address": "module.ap_irsa.random_id.id",
		"module_address": "module.ap_irsa",
		"mode": "managed",
		"type": "random_id",
		"name": "id",
		"provider_name": "registry.terraform.io/hashicorp/random",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"byte_length": 8,
				"keepers": null,
				"prefix": null,
			},
			"after_unknown": {
				"b64_std": true,
				"b64_url": true,
				"dec": true,
				"hex": true,
				"id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
]}

irsa_multiple_roles_create_mock_tfplan := {"resource_changes": [
	{
		"address": "module.foobar.kubernetes_service_account.generated_sa",
		"module_address": "module.foobar",
		"mode": "managed",
		"type": "kubernetes_service_account",
		"name": "generated_sa",
		"provider_name": "registry.terraform.io/hashicorp/kubernetes",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"automount_service_account_token": true,
				"image_pull_secret": [],
				"metadata": [{
					"generate_name": null,
					"labels": null,
					"namespace": "jaskaran-dev",
				}],
				"secret": [],
				"timeouts": null,
			},
			"after_unknown": {
				"default_secret_name": true,
				"id": true,
				"image_pull_secret": [],
				"metadata": [{
					"annotations": true,
					"generation": true,
					"name": true,
					"resource_version": true,
					"uid": true,
				}],
				"secret": [],
			},
			"before_sensitive": false,
			"after_sensitive": {
				"image_pull_secret": [],
				"metadata": [{"annotations": {}}],
				"secret": [],
			},
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
			"actions": ["create"],
			"before": null,
			"after": {
				"automount_service_account_token": true,
				"image_pull_secret": [],
				"metadata": [{
					"generate_name": null,
					"labels": null,
					"namespace": "jaskaran-dev",
				}],
				"secret": [],
				"timeouts": null,
			},
			"after_unknown": {
				"default_secret_name": true,
				"id": true,
				"image_pull_secret": [],
				"metadata": [{
					"annotations": true,
					"generation": true,
					"name": true,
					"resource_version": true,
					"uid": true,
				}],
				"secret": [],
			},
			"before_sensitive": false,
			"after_sensitive": {
				"image_pull_secret": [],
				"metadata": [{"annotations": {}}],
				"secret": [],
			},
		},
	},
	{
		"address": "module.foobar.module.iam_assumable_role.aws_iam_role.this[0]",
		"module_address": "module.foobar.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"description": null,
				"force_detach_policies": true,
				"max_session_duration": 3600,
				"path": "/",
				"permissions_boundary": null,
				"tags": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
				"tags_all": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
			},
			"after_unknown": {
				"arn": true,
				"assume_role_policy": true,
				"create_date": true,
				"id": true,
				"inline_policy": true,
				"managed_policy_arns": true,
				"name": true,
				"name_prefix": true,
				"tags": {},
				"tags_all": {},
				"unique_id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"inline_policy": [],
				"managed_policy_arns": [],
				"tags": {},
				"tags_all": {},
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"description": null,
				"force_detach_policies": true,
				"max_session_duration": 3600,
				"path": "/",
				"permissions_boundary": null,
				"tags": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
				"tags_all": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
			},
			"after_unknown": {
				"arn": true,
				"assume_role_policy": true,
				"create_date": true,
				"id": true,
				"inline_policy": true,
				"managed_policy_arns": true,
				"name": true,
				"name_prefix": true,
				"tags": {},
				"tags_all": {},
				"unique_id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"inline_policy": [],
				"managed_policy_arns": [],
				"tags": {},
				"tags_all": {},
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role_policy_attachment.this[\"s3\"]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role_policy_attachment",
		"name": "this",
		"index": "s3",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {},
			"after_unknown": {
				"id": true,
				"policy_arn": true,
				"role": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.data.aws_iam_policy_document.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "data",
		"type": "aws_iam_policy_document",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["read"],
			"before": null,
			"after": {
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": ["sts:AssumeRoleWithWebIdentity"],
					"condition": [
						{
							"test": "StringEquals",
							"values": ["sts.amazonaws.com"],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:aud",
						},
						{
							"test": "StringEquals",
							"values": [null],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:sub",
						},
					],
					"effect": "Allow",
					"not_actions": null,
					"not_principals": [],
					"not_resources": null,
					"principals": [{
						"identifiers": ["arn:aws:iam::754256621582:oidc-provider/oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09"],
						"type": "Federated",
					}],
					"resources": null,
					"sid": null,
				}],
				"version": null,
			},
			"after_unknown": {
				"id": true,
				"json": true,
				"minified_json": true,
				"statement": [{
					"actions": [false],
					"condition": [
						{"values": [false]},
						{"values": [true]},
					],
					"not_principals": [],
					"principals": [{"identifiers": [false]}],
				}],
			},
			"before_sensitive": false,
			"after_sensitive": {"statement": [{
				"actions": [false],
				"condition": [
					{"values": [false]},
					{"values": [false]},
				],
				"not_principals": [],
				"principals": [{"identifiers": [false]}],
			}]},
		},
		"action_reason": "read_because_config_unknown",
	},
	{
		"address": "module.ap_irsa.random_id.id",
		"module_address": "module.ap_irsa",
		"mode": "managed",
		"type": "random_id",
		"name": "id",
		"provider_name": "registry.terraform.io/hashicorp/random",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"byte_length": 8,
				"keepers": null,
				"prefix": null,
			},
			"after_unknown": {
				"b64_std": true,
				"b64_url": true,
				"dec": true,
				"hex": true,
				"id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
]}

irsa_mismatch_create_mock_tfplan := {"resource_changes": [
	{
		"address": "module.wrong.kubernetes_service_account.generated_sa",
		"module_address": "module.wrong",
		"mode": "managed",
		"type": "kubernetes_service_account",
		"name": "generated_sa",
		"provider_name": "registry.terraform.io/hashicorp/kubernetes",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"automount_service_account_token": true,
				"image_pull_secret": [],
				"metadata": [{
					"generate_name": null,
					"labels": null,
					"namespace": "jaskaran-dev",
				}],
				"secret": [],
				"timeouts": null,
			},
			"after_unknown": {
				"default_secret_name": true,
				"id": true,
				"image_pull_secret": [],
				"metadata": [{
					"annotations": true,
					"generation": true,
					"name": true,
					"resource_version": true,
					"uid": true,
				}],
				"secret": [],
			},
			"before_sensitive": false,
			"after_sensitive": {
				"image_pull_secret": [],
				"metadata": [{"annotations": {}}],
				"secret": [],
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"description": null,
				"force_detach_policies": true,
				"max_session_duration": 3600,
				"path": "/",
				"permissions_boundary": null,
				"tags": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
				"tags_all": {
					"application": "get familiar with cloud platform",
					"business-unit": "Platforms",
					"environment-name": "development",
					"infrastructure-support": "jaskaran.sarkaria@digital.justice.gov.uk",
					"is-production": "false",
					"namespace": "jaskaran-dev",
					"owner": "webops",
				},
			},
			"after_unknown": {
				"arn": true,
				"assume_role_policy": true,
				"create_date": true,
				"id": true,
				"inline_policy": true,
				"managed_policy_arns": true,
				"name": true,
				"name_prefix": true,
				"tags": {},
				"tags_all": {},
				"unique_id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"inline_policy": [],
				"managed_policy_arns": [],
				"tags": {},
				"tags_all": {},
			},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.aws_iam_role_policy_attachment.this[\"s3\"]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "managed",
		"type": "aws_iam_role_policy_attachment",
		"name": "this",
		"index": "s3",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {},
			"after_unknown": {
				"id": true,
				"policy_arn": true,
				"role": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
	{
		"address": "module.ap_irsa.module.iam_assumable_role.data.aws_iam_policy_document.this[0]",
		"module_address": "module.ap_irsa.module.iam_assumable_role",
		"mode": "data",
		"type": "aws_iam_policy_document",
		"name": "this",
		"index": 0,
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["read"],
			"before": null,
			"after": {
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": ["sts:AssumeRoleWithWebIdentity"],
					"condition": [
						{
							"test": "StringEquals",
							"values": ["sts.amazonaws.com"],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:aud",
						},
						{
							"test": "StringEquals",
							"values": [null],
							"variable": "oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09:sub",
						},
					],
					"effect": "Allow",
					"not_actions": null,
					"not_principals": [],
					"not_resources": null,
					"principals": [{
						"identifiers": ["arn:aws:iam::754256621582:oidc-provider/oidc.eks.eu-west-2.amazonaws.com/id/DF366E49809688A3B16EEC29707D8C09"],
						"type": "Federated",
					}],
					"resources": null,
					"sid": null,
				}],
				"version": null,
			},
			"after_unknown": {
				"id": true,
				"json": true,
				"minified_json": true,
				"statement": [{
					"actions": [false],
					"condition": [
						{"values": [false]},
						{"values": [true]},
					],
					"not_principals": [],
					"principals": [{"identifiers": [false]}],
				}],
			},
			"before_sensitive": false,
			"after_sensitive": {"statement": [{
				"actions": [false],
				"condition": [
					{"values": [false]},
					{"values": [false]},
				],
				"not_principals": [],
				"principals": [{"identifiers": [false]}],
			}]},
		},
		"action_reason": "read_because_config_unknown",
	},
	{
		"address": "module.ap_irsa.random_id.id",
		"module_address": "module.ap_irsa",
		"mode": "managed",
		"type": "random_id",
		"name": "id",
		"provider_name": "registry.terraform.io/hashicorp/random",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"byte_length": 8,
				"keepers": null,
				"prefix": null,
			},
			"after_unknown": {
				"b64_std": true,
				"b64_url": true,
				"dec": true,
				"hex": true,
				"id": true,
			},
			"before_sensitive": false,
			"after_sensitive": {},
		},
	},
]}

submodule_irsa := {"resource_changes": [{
	"address": "module.secrets_manager.module.irsa.kubernetes_service_account.generated_sa",
	"module_address": "module.secrets_manager.module.irsa",
	"mode": "managed",
	"type": "kubernetes_service_account",
	"name": "generated_sa",
	"provider_name": "registry.terraform.io/hashicorp/kubernetes",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"automount_service_account_token": true,
			"image_pull_secret": [],
			"metadata": [{
				"generate_name": null,
				"labels": null,
				"namespace": "jaskaran-dev",
			}],
			"secret": [],
			"timeouts": null,
		},
		"after_unknown": {
			"default_secret_name": true,
			"id": true,
			"image_pull_secret": [],
			"metadata": [{
				"annotations": true,
				"generation": true,
				"name": true,
				"resource_version": true,
				"uid": true,
			}],
			"secret": [],
		},
		"before_sensitive": false,
		"after_sensitive": {
			"image_pull_secret": [],
			"metadata": [{"annotations": {}}],
			"secret": [],
		},
	},
}]}
