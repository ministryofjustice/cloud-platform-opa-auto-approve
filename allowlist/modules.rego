package terraform.analysis

import input as tfplan

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	regex.match(`^module\..*\.kubernetes_deployment\.service_pod$`, m.address)
}

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	m.type == `aws_ecr_repository`
}

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	regex.match(`^module\..*\.kubernetes_service_account\.generated_sa$`, m.address)
}

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	regex.match(`^module\..*\.module\.iam_assumable_role\.aws_iam_role\.this\[0\]$`, m.address)
}

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	regex.match(`^module\..*\.aws_secretsmanager_secret.secret.*$`, m.address)
}

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	regex.match(`^module\..*\.module.service_account.kubernetes_role.github_actions_role$`, m.address)
}

allowed_modules contains m if {
	m := tfplan.resource_changes[_]
	regex.match(`^module\..*\.aws_sns_topic.new_topic$`, m.address)
}

allowed_modules_addrs := {arr | arr := allowed_modules[_].module_address}
