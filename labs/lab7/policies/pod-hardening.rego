package main

capabilities_drop_all(container) if {
	some i
	container.securityContext.capabilities.drop[i] == "ALL"
}

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext must set runAsNonRoot: true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container %q must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not capabilities_drop_all(container)
	msg := sprintf("container %q must drop ALL capabilities", [container.name])
}
