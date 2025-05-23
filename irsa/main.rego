package terraform.analysis

import input as tfplan

import future.keywords

default irsa_ok := false

default res := false

allow := {
	"valid": res,
	"msg": msg,
}

res if {
	irsa_ok
	namespace_ok
}

res if {
	irsa_submodule_ok
}

msg := "Valid irsa related terraform changes" if {
	irsa_ok
	namespace_ok
} else := "Valid irsa related terraform changes" if {
	irsa_submodule_ok
} else := "We can't auto approve these irsa terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	not irsa_ok
	namespace_ok
} else := "We can't auto approve these irsa terraform changes. Your are trying to modify resources in a different namespace. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	irsa_ok
	not namespace_ok
} else := "We can't auto approve these irsa terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

irsa := [
addr |
	res := tfplan.resource_changes[_]
	regex.match(`^module\..*\.kubernetes_service_account\.generated_sa$`, res.address)
	res.change.actions[_] != "no-op"
	addr := res.module_address
]

irsa_iam_assumable_role_module := [
res |
	res := tfplan.resource_changes[_]
	regex.match(`^module\..*\.module\.iam_assumable_role\.aws_iam_role\.this\[0\]$`, res.address)
	res.change.actions[_] != "no-op"
]

irsa_ok if {
	every ma in irsa {
		trimmed_addr := regex.split(`\.`, ma)[1]

		expressions := tfplan.configuration.root_module.module_calls[trimmed_addr].expressions

		role_policy_arns := expressions.role_policy_arns.references

		count(role_policy_arns) > 0
	}

	some a in irsa_iam_assumable_role_module
	some addr in irsa

	regex.match(addr, a.module_address)
}

irsa_submodule_ok if {
	every ma in irsa {
		trimmed_addr := regex.split(`\.`, ma)
		filtered_mod_arr := [
		mod |
			mod := trimmed_addr[_]
			mod == "module"
		]
		count(filtered_mod_arr) > 1
	}
}

irsa_ok if {
	count(irsa) == 0
	count(irsa_iam_assumable_role_module) == 0
}

namespace_ok if {
	every ma in irsa {
		trimmed_addr := trim_left(ma, "module.")

		namespace_var(trimmed_addr) == tfplan.variables.namespace.value
	}
}

namespace_var(addr) := tfplan.variables.namespace.value if {
	tfplan.configuration.root_module.module_calls[addr].expressions.namespace.references[0] == "var.namespace"
} else := tfplan.configuration.root_module.module_calls[addr].expressions.namespace.constant_value
