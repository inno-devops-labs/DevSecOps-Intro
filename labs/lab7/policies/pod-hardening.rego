package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be set to true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not drops_all_capabilities(container)
	msg := sprintf("container '%s' must drop ALL capabilities", [container.name])
}

drops_all_capabilities(container) if {
	"ALL" in container.securityContext.capabilities.drop
}
