package main

import rego.v1

# Helper: the pod spec inside a Deployment
podspec := input.spec.template.spec

# 1. Pod must run as non-root
deny contains msg if {
	input.kind == "Deployment"
	not podspec.securityContext.runAsNonRoot == true
	msg := "Pod securityContext.runAsNonRoot must be true"
}

# 2. Every container must have a read-only root filesystem
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("Container %q must set readOnlyRootFilesystem: true", [c.name])
}

# 3. Every container must disallow privilege escalation
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 4. Every container must drop ALL capabilities
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not drops_all(c)
	msg := sprintf("Container %q must drop ALL capabilities", [c.name])
}

drops_all(c) if {
	some cap in c.securityContext.capabilities.drop
	cap == "ALL"
}