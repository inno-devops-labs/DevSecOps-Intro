package main

import rego.v1

# Pod-level: runAsNonRoot must be true (PSS restricted)
deny contains msg if {
	input.kind == "Deployment"
	pod_spec := input.spec.template.spec
	not pod_spec.securityContext.runAsNonRoot
	msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot to true"
}

# Container-level hardening checks
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem
	msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not capabilities_drop_all(container)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

capabilities_drop_all(container) if {
	container.securityContext.capabilities.drop[_] == "ALL"
}
