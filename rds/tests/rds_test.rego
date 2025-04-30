package test.terraform.analysis

import data.terraform.analysis

test_deny_var_vpc_security_group_ids_as_constants if {

	module := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		}
	configuration := {"root_module": {"module_calls": {"rds": {"expressions": {"vpc_security_group_ids": {"constant_value": "sg-0123456"}}}}}}

	res := analysis.allow with input as {
		"resource_changes": [module],
		"configuration": configuration
}

not res.valid

res.msg == "VPC security group ids must be passed as resource references not string literals"
	
}

test_allow_var_vpc_security_group_ids_as_refs if {

	module := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		}
	configuration := {"root_module": {"module_calls": {"rds": {"expressions": {"vpc_security_group_ids": {"references": ["my_vpc_id"]}}}}}}

	res := analysis.allow with input as {
		"resource_changes": [module],
		"configuration": configuration
}

res.valid

res.msg == "Valid RDS module related terraform changes"
	
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
	res.msg == "gp3 storage class disk size must be at least 20Gb."
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

	res := analysis.allow with input as {"resource_changes": [xlarge_class],
 		"variables": mock_tfplan.variables,}

	not res.valid
	res.msg == "instance classes of size xlarge or greater require a Cloud Platform review. Please consider using a smaller class, or contact Cloud Platform in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_deny_create_storage_type_eq_io1 if {
	io1_storage_type := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {"storage_type": "io1"},
		},
	}

	res := analysis.allow with input as {"resource_changes": [io1_storage_type],
 		"variables": mock_tfplan.variables,}

	not res.valid
	res.msg == "io1 storage class based instances are expensive. Please consider using gp3, or contact Cloud Platform in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_deny_create_storage_type_eq_io2 if {
	io2_storage_type := {
		"address": "module.rds.aws_db_instance.rds",
		"module_address": "module.rds",
		"mode": "managed",
		"type": "aws_db_instance",
		"name": "rds",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {"storage_type": "io2"},
		},
	}

	res := analysis.allow with input as {"resource_changes": [io2_storage_type],
 		"variables": mock_tfplan.variables,}

	not res.valid
	res.msg == "io2 storage class based instances are expensive. Please consider using gp3, or contact Cloud Platform in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"
}

test_major_upgrade_prepare_flag_is_set if {
	major_upgrade := {
      "address": "module.rds.aws_db_parameter_group.custom_parameters",
      "module_address": "module.rds",
      "mode": "managed",
      "type": "aws_db_parameter_group",
      "name": "custom_parameters",
      "change": {
        "actions": [
          "create",
          "delete"
        ],
        "before": {
          "family": "postgres16",
        },
        "after": {
          "family": "postgres17",
          }
        },
    }


configuration := {"root_module": {"module_calls": {"rds": {"expressions": {"prepare_for_major_upgrade": {"constant_value": true}}}}}}

res := analysis.allow with input as {
	"resource_changes": [major_upgrade],
	"configuration": configuration
}

res.valid

res.msg == "Valid RDS module related terraform changes"
}


test_major_upgrade_prepare_flag_not_set if {
	major_upgrade := {
      "address": "module.rds.aws_db_parameter_group.custom_parameters",
      "module_address": "module.rds",
      "mode": "managed",
      "type": "aws_db_parameter_group",
      "name": "custom_parameters",
      "change": {
        "actions": [
          "create",
          "delete"
        ],
        "before": {
          "family": "postgres16",
        },
        "after": {
          "family": "postgres17",
          }
        },
    }


configuration := {"root_module": {"module_calls": {"rds": {"expressions": {"prepare_for_major_upgrade": {"constant_value": false}}}}}}

res := analysis.allow with input as {
	"resource_changes": [major_upgrade],
	"configuration": configuration
}

not res.valid

res.msg == "RDS family has changed but prepare_for_major_upgrade flag is false."
}
