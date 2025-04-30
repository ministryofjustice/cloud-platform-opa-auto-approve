package terraform.analysis

import input as tfplan

import future.keywords.every

default rds_ok := false

default res := false

ns := tfplan.variables.namespace.value

allow := {
	"valid": res,
	"msg": msg,
}

res if {
	rds_ok
}

msg := "Valid RDS module related terraform changes" if {
	rds_ok
} else := "We can't auto approve these rds terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

rds_ok if {
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

	# print(all_rds_resources)

	all_rds_instances := [
	res |
		res := all_rds_resources[_]
		regex.match(`^module\..*\.aws_db_instance.rds$`, res.address)
	]

	invalid_allocated_storage := [
	res |
		res := all_rds_instances[_]
		res.change.after.allocated_storage < 20
		res.change.after.storage_type == "gp3"
	]

	count(invalid_allocated_storage) == 0

	invalid_instance_class := [
	res |
		res := all_rds_instances[_]
		contains(res.change.after.instance_class, "xlarge")
	]

	count(invalid_instance_class) == 0
	# print(all_rds_instances)

}
