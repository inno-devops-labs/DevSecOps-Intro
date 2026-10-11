package main

containers := input.spec.template.spec.containers

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

container_run_as_non_root(container) if {
	object.get(object.get(container, "securityContext", {}), "runAsNonRoot", false) == true
}

pod_run_as_non_root if {
	object.get(pod_security_context, "runAsNonRoot", false) == true
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	not pod_run_as_non_root
	not container_run_as_non_root(container)

	msg := sprintf("container %q must set runAsNonRoot=true at pod or container securityContext", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false

	msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	drops := object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
	not "ALL" in drops

	msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := containers[_]
	not object.get(object.get(object.get(container, "resources", {}), "limits", {}), "memory", false)

	msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
