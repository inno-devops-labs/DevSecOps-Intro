package main

import rego.v1

# Conftest policy gate for Kubernetes Deployments.
# Refuses a Deployment whose pod template is missing key hardening controls.
# Run: conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies

# The pod spec lives under spec.template.spec for a Deployment.
podspec := input.spec.template.spec

# 1. Pod must run as a non-root user.
deny contains msg if {
	input.kind == "Deployment"
	not podspec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be true"
}

# 2. Every container must have a read-only root filesystem.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s' must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

# 3. Every container must disable privilege escalation.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s' must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# 4. Every container must drop ALL Linux capabilities.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not drops_all(c)
	msg := sprintf("container '%s' must drop ALL capabilities", [c.name])
}

drops_all(c) if {
	c.securityContext.capabilities.drop[_] == "ALL"
}
