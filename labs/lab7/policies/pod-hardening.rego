package main

import rego.v1

# Deny pods (via Deployment) that don't set runAsNonRoot
deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "Pod securityContext.runAsNonRoot must be true"
}

# Deny containers missing readOnlyRootFilesystem
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

# Deny containers that allow privilege escalation
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

# Deny containers that don't drop ALL capabilities
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not has_drop_all(container)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

has_drop_all(container) if {
	container.securityContext.capabilities.drop[_] == "ALL"
}
