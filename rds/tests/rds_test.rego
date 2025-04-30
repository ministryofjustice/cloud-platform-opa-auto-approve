package test.terraform.analysis

import data.terraform.analysis

test_allow_var_vpc_security_ids_as_refs if {
	false
}

test_deny_var_vpc_security_ids_as_literal if {
	false
}

test_deny_if_gp3_has_low_allocated_storage if {
	low_storage := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"allocated_storage": 19,
				"storage_type": "gp3",
			},
		},
	}

	res := analysis.allow with input as {"resource_changes": [low_storage]}

	not res.valid
	res.msg == "We can't auto approve these rds terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_allow_if_gp3_has_enough_allocated_storage if {
	enough_storage := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"allocated_storage": 20,
				"storage_type": "gp3",
			},
		},
	}

	res := analysis.allow with input as {"resource_changes": [enough_storage]}

	res.valid
	res.msg == "Valid RDS module related terraform changes"
}

test_allow_db_engine_version_major_upgrade_with_correct_prepare_flag if {
	false
}

test_deny_db_engine_version_major_upgrade_with_incorrect_prepare_flag if {
	false
}

test_deny_if_db_engine_is_changed if {
	false
}

test_allow_if_db_instance_class_is_not_xlarge if {
	not_xlarge_class := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {"instance_class": "db.t3.medium"},
		},
	}
	res := analysis.allow with input as {"resource_changes": [not_xlarge_class]}

	res.valid
	res.msg == "Valid RDS module related terraform changes"
}

test_deny_if_db_instance_class_is_Nxlarge if {
	xlarge_class := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {"instance_class": "db.t3.48xlarge"},
		},
	}
	res := analysis.allow with input as {"resource_changes": [xlarge_class]}

	not res.valid
	res.msg == "We can't auto approve these rds terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_deny_if_local_db_name_changes if {
	false
}

test_deny_create_storage_type_eq_io if {
	false
}

test_deny_update_storage_type_eq_io if {
	false
}

test_deny_if_var_is_production_is_true_is_destroyed if {
	false
}

test_allow_non_prod_rds_destroy_with_deletion_protection_false if {
	false
}

test_deny_non_prod_rds_destroy_with_deletion_protection_true if {
	false
}
