package terraform.analysis

import input as tfplan

import future.keywords.every

default secrets_manager_ok := false

default res := false

allow := {
	"valid": res,
	"msg": msg,
}

res if {
	secrets_manager_ok
}

msg := "Valid secrets manager related terraform changes" if {
	secrets_manager_ok
} else := "We can't auto approve these secrets manager terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

secrets_manager_modules := [
addr |
	res := tfplan.resource_changes[_]
	regex.match(`^module\..*\.aws_secretsmanager_secret.secret.*$`, res.address)
	res.change.actions[_] != "no-op"
	addr := res.module_address
]

secrets_manager_ok if {
	every sm in secrets_manager_modules {
		trimmed_addr := trim_left(sm, "module.")

		namespace_var(trimmed_addr) == tfplan.variables.namespace.value
	}
}

namespace_var(addr) := tfplan.variables.namespace.value if {
	tfplan.configuration.root_module.module_calls[addr].expressions.namespace.references[0] == "var.namespace"
} else := tfplan.configuration.root_module.module_calls[addr].expressions.namespace.constant_value
