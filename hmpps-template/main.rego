package terraform.analysis

import input as tfplan

import future.keywords.every

default hmpps_template_ok := false

default res := false

allow := {
	"valid": res,
	"msg": msg,
}

res if {
	hmpps_template_ok
}

msg := "Valid hmpps template related terraform changes" if {
	hmpps_template_ok
} else := "We can't auto approve these hmpps template terraform changes as they make changes in another namespace. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

hmpps_template_modules := [
addr |
	res := tfplan.resource_changes[_]
	regex.match(`^module\..*\.module.service_account.kubernetes_role.github_actions_role$`, res.address)
	res.change.actions[_] != "no-op"
	full_addr := res.module_address
	addr := trim_suffix(full_addr, ".module.service_account")
]

hmpps_template_ok if {
	every sm in hmpps_template_modules {
		trimmed_addr := trim_left(sm, "module.")

		namespace_var(trimmed_addr) == tfplan.variables.namespace.value
	}
}

namespace_var(addr) := tfplan.variables.namespace.value if {
	tfplan.configuration.root_module.module_calls[addr].expressions.namespace.references[0] == "var.namespace"
} else := tfplan.configuration.root_module.module_calls[addr].expressions.namespace.constant_value
