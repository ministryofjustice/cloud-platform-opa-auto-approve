package terraform.analysis

import input as tfplan

import future.keywords.every

default sns_ok := false

default res := false

default team_name_renamed := false

allow := {
	"valid": res,
	"msg": msg,
}

res if {
	sns_ok
}

msg := "Valid sns related terraform changes" if {
	sns_ok
	not is_team_name_renamed
} else := "NOTE: Terraform topic name change detected. [See here for more info](https://github.com/ministryofjustice/cloud-platform-terraform-sns-topic?tab=readme-ov-file#team-name-caveat)" if {
	sns_ok
	is_team_name_renamed
} else := "We can't auto approve these sns terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

sns_modules := [
addr |
	res := tfplan.resource_changes[_]
	regex.match(`^module\..*\.aws_sns_topic.new_topic$`, res.address)
	res.change.actions[_] != "no-op"
	addr := res.module_address
]

sns_resource_addrs := [
type |
	res := tfplan.resource_changes[_]
	res.change.actions[_] != "no-op"
	res.type == "aws_sns_topic_subscription"
	type := res.address
]

sns_ok if {
	every m in sns_modules {
		trimmed_addr := trim_left(m, "module")

		trim_dot := trim_left(trimmed_addr, `\.`)

		namespace_var(trim_dot) == tfplan.variables.namespace.value
	}

	root_sns_resources := [
	res |
		all := tfplan.configuration.root_module.resources[_]

		some addr in sns_resource_addrs

		addr == all.address

		res := all
	]

	every r in root_sns_resources {
		count(r.expressions.endpoint.references) > 0
		count(r.expressions.topic_arn.references) > 0
	}
}

is_team_name_renamed if {
	sns_updates := [
	topic |
		res := tfplan.resource_changes[_]
		regex.match(`^module\..*\.aws_sns_topic.new_topic$`, res.address)
		res.change.actions[_] == "update"
		topic := res
	]

	count(sns_updates) > 0

	every t in sns_updates {
		t.change.before.display_name != t.change.after.display_name
	}
}

namespace_var(addr) := tfplan.variables.namespace.value if {
	tfplan.configuration.root_module.module_calls[addr].expressions.namespace.references[0] == "var.namespace"
} else := tfplan.configuration.root_module.module_calls[addr].expressions.namespace.constant_value
