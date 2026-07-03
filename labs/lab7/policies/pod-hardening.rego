package main

import rego.v1

pod_spec := input.spec.template.spec if {
	input.kind == "Deployment"
}

workload_containers contains container if {
	container := pod_spec.containers[_]
}

workload_containers contains container if {
	container := pod_spec.initContainers[_]
}

deny contains msg if {
	input.kind == "Deployment"
	object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
	msg := "pod spec must set securityContext.runAsNonRoot: true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
	msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := workload_containers[_]
	object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false
	msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := workload_containers[_]
	not "ALL" in object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
	msg := sprintf("container %q must drop all Linux capabilities with capabilities.drop: [\"ALL\"]", [container.name])
}
