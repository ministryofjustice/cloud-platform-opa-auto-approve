package terraform.analysis

import future.keywords.every
import input as tfplan

default res := false

allow := {
	"valid": res,
	"msg": msg,
}

res if {
	touches_some_allowed
	doesnt_touch_other_resources
	doesnt_touch_other_modules
	not touches_iam_create
	not touches_iam_update
}

msg := "Valid changes the PR meets the module allowlist criteria for auto approval" if {
	touches_some_allowed
	doesnt_touch_other_resources
	doesnt_touch_other_modules
	not touches_iam_create
	not touches_iam_update
} else := "This PR includes create changes to IAM that are not covered by our module allowlist, so we can't auto approve this PR. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	touches_iam_create
} else := "This PR includes update changes to IAM that are not covered by our module allowlist, so we can't auto approve this PR. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)" if {
	touches_iam_update
} else := "This PR includes changes to modules / resources which are not on the allowlist, so we can't auto approve these changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

touches_some_allowed if {
	count(allowed_modules_addrs) > 0
}

touches_some_allowed if {
	count(allowed_resources_addrs) > 0
}

doesnt_touch_other_modules if {
	all_module_addrs := [
	addr |
		res := tfplan.resource_changes[_]
		res.change.actions[_] != "no-op"
		regex.match(`module\.`, res.module_address)
		addr := res.module_address
	]

	every m in all_module_addrs {
		print(m in allowed_modules_addrs)
		m in allowed_modules_addrs
	}
}

doesnt_touch_other_resources if {
	all_resource_addrs := [
	addr |
		res := tfplan.resource_changes[_]
		res.change.actions[_] != "no-op"
		not res.module_address
		addr := res.address
	]

	every r in all_resource_addrs {
		r in allowed_resources_addrs
	}
}

touches_iam_create if {
	all_iam_addrs := [
	addr |
		p := tfplan.resource_changes[_]
		p.type in {"aws_iam_policy", "aws_iam_role_policy_attachment"}
		change := p.change.actions[_]
		change == "create"
		addr := p.module_address
	]

	count(all_iam_addrs) > 0

	every m in all_iam_addrs {
		not m in allowed_modules_addrs
	}
}

touches_iam_update if {
	all_iam_addrs := [
	addr |
		p := tfplan.resource_changes[_]
		p.type in {"aws_iam_policy", "aws_iam_role_policy_attachment"}
		change := p.change.actions[_]
		change == "update"
		addr := p.module_address
	]

	count(all_iam_addrs) > 0

	every m in all_iam_addrs {
		not m in allowed_modules_addrs
	}
}
