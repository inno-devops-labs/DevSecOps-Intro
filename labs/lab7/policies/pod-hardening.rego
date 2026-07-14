package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not pod_run_as_nonroot
	msg := "Pod must set securityContext.runAsNonRoot: true"
}

pod_run_as_nonroot if {
	input.spec.template.spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container_readonly_fs(container)
	msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

container_readonly_fs(container) if {
	container.securityContext.readOnlyRootFilesystem == true
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container_no_privesc(container)
	msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

container_no_privesc(container) if {
	container.securityContext.allowPrivilegeEscalation == false
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container_drops_all(container)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

container_drops_all(container) if {
	container.securityContext.capabilities.drop[_] == "ALL"
}
