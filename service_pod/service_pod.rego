package terraform.analysis

import input as tfplan

is_service_pod_valid(service_pod) if {
	is_correct_ns(service_pod)

	all_irsa_account_names := [
	name |
		res := tfplan.resource_changes[_]
		regex.match(`^module\..*\.kubernetes_service_account\.generated_sa$`, res.address)
		name := res.change.after.metadata[_].name
	]

	service_pods_sa := [
	res |
		res := service_pod.change.after.spec[_].template[_].spec[_].service_account_name
	]

	count(service_pods_sa) > 0

	every sa in service_pods_sa {
		sa in all_irsa_account_names
	}
}

is_correct_ns(service_pod) if {
	actual_ns := [
	ns |
		ns := service_pod.change.after.metadata[_].namespace
	]

	is_correct_namespace := tfplan.variables.namespace.value
	every ns in actual_ns {
		ns == is_correct_namespace
	}
}
