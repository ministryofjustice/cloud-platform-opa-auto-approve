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

msg := "Valid K8s secret related terraform changes" if {
	rds_ok
} else := "We can't auto approve these kubernetes secret terraform changes. Please request a Cloud Platform team member's review in [#ask-cloud-platform](https://moj.enterprise.slack.com/archives/C57UPMZLY)"

rds_ok if {
	k8s_secrets := [
	res |
		res := tfplan.resource_changes[_]
		res.type == "kubernetes_secret"
		res.change.actions[_] != "no-op"
		res.change.actions[_] != "delete"
	]

	every s in k8s_secrets {
		s.change.after.metadata[0].namespace == ns
	}
}

