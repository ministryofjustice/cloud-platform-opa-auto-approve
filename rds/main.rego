package terraform.analysis

import input as tfplan

import future.keywords.every

default rds_ok := false

default res := false

ns := tfplan.variables.namespace.value

rds_modules_addrs := [
addr |
	res := tfplan.resource_changes[_]
	regex.match(`^module\..*\.aws_db_instance.rds$`, res.address)
	addr := res.module_address
]

all_rds_resources := [
res |
	res := tfplan.resource_changes[_]
	res.change.actions[_] != "no-op"
]


all_rds_instances := [
res |
	res := all_rds_resources[_]
	# res.change.actions[_] != "no-op"
	regex.match(`^module\..*\.aws_db_instance.rds$`, res.address)
]


allow := {
	"valid": res,
	"msg": msg,
}

res if {
	io1_ok
	io2_ok
	gp3_ok
	instance_class_ok
	major_upgrade_ok
	vpc_sg_ids_ok
}

msg := "Valid RDS module related terraform changes" if {
	io1_ok
	io2_ok
	gp3_ok
	instance_class_ok
	major_upgrade_ok
	vpc_sg_ids_ok
} else := "io1 storage class based instances are expensive. Please consider using gp3, or contact Cloud Platform in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	not io1_ok
} else := "io2 storage class based instances are expensive. Please consider using gp3, or contact Cloud Platform in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	not io2_ok
} else := "gp3 storage class disk size must be at least 20Gb." if {
	not gp3_ok
} else := "instance classes of size xlarge or greater require a Cloud Platform review. Please consider using a smaller class, or contact Cloud Platform in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	not instance_class_ok
} else := "RDS family has changed but prepare_for_major_upgrade flag is false." if {
	not major_upgrade_ok
} else := "VPC security group ids must be passed as resource references not string literals" if {
	not vpc_sg_ids_ok
}

gp3_ok if {

	invalid_allocated_storage := [
	res |
		res := all_rds_instances[_]
		res.change.after.allocated_storage < 20
		res.change.after.storage_type == "gp3"
	]

	count(invalid_allocated_storage) == 0
}

instance_class_ok if {
	invalid_instance_class := [
	res |
		res := all_rds_instances[_]
		contains(res.change.after.instance_class, "xlarge")
	]

	count(invalid_instance_class) == 0

}

io1_ok if {
	invalid_storage_type_io1 := [
	res |
		res := all_rds_resources[_]
		res.change.after.storage_type == "io1"
	]

	count(invalid_storage_type_io1) == 0

}

io2_ok if {
	invalid_storage_type_io2 := [
	res |
		res := all_rds_resources[_]
		res.change.after.storage_type == "io2"
	]

	count(invalid_storage_type_io2) == 0
}

major_upgrade_ok if {
	prepare_upgrade_flag_not_set := [
		res |
		res := all_rds_resources[_]
		res.name == "custom_parameters"
		res.change.actions[_] == "create"
		res.change.actions[_] == "delete" 
		res.change.before.family != res.change.after.family		
		
		trimmed_addr := trim_left(res.module_address, "module.")
		not tfplan.configuration.root_module.module_calls[trimmed_addr].expressions.prepare_for_major_upgrade.constant_value
		
	]
	count(prepare_upgrade_flag_not_set) == 0
}

vpc_sg_ids_ok if {
	security_group_ids_is_constant := [
		res |
		res := rds_modules_addrs[_]
		trimmed_addr := trim_left(res, "module.")
		tfplan.configuration.root_module.module_calls[trimmed_addr].expressions.vpc_security_group_ids.constant_value

	]
	count(security_group_ids_is_constant) == 0
}