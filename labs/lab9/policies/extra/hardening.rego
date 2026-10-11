package main

import rego.v1

# Iterate containers of a Deployment
container := input.spec.template.spec.containers[_]

# 1. runAsNonRoot must be true
deny contains msg if {
	input.kind == "Deployment"
	not container.securityContext.runAsNonRoot == true
	msg := sprintf("container %q must set securityContext.runAsNonRoot: true", [container.name])
}

# 2. allowPrivilegeEscalation must be false
deny contains msg if {
	input.kind == "Deployment"
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

# 3. capabilities.drop must include ALL
deny contains msg if {
	input.kind == "Deployment"
	not "ALL" in container.securityContext.capabilities.drop
	msg := sprintf("container %q must drop ALL capabilities", [container.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
	input.kind == "Deployment"
	not container.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

# 5. image must not use the mutable :latest tag
deny contains msg if {
	input.kind == "Deployment"
	endswith(container.image, ":latest")
	msg := sprintf("container %q must not use the mutable :latest tag", [container.name])
}