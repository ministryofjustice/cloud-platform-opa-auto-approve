package terraform.analysis

import input as tfplan

allowed_resources contains r if {
	r := tfplan.resource_changes[_]
	r.change.actions[_] != "no-op"
	r.type == `kubernetes_secret`
}

allowed_resources contains r if {
	r := tfplan.resource_changes[_]
	r.change.actions[_] != "no-op"
	r.type == `kubernetes_secret_v1`
}

allowed_resources contains r if {
	r := tfplan.resource_changes[_]
	r.change.actions[_] != "no-op"
	r.type == `pingdom_check`
}

allowed_resources contains r if {
	r := tfplan.resource_changes[_]
	r.change.actions[_] != "no-op"
	r.type == `random_id`
}

allowed_resources_addrs := {arr | arr := allowed_resources[_].address}
