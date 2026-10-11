# Conftest gate — refuse Deployments whose pod template is not hardened.
# Run:  conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
#
# Conftest looks for `package main` by default. Written in Rego v1 syntax
# (if/contains), matching labs/lab9/policies/k8s-security.rego.
package main

# Helper: true if array arr contains value v
has_value(arr, v) if {
	some i
	arr[i] == v
}

# 1) pod-level runAsNonRoot must be true
deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be set to true"
}

# 2) every container must set readOnlyRootFilesystem: true
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container %q must set readOnlyRootFilesystem: true", [c.name])
}

# 3) every container must set allowPrivilegeEscalation: false
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 4) every container must drop ALL capabilities
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not has_value(c.securityContext.capabilities.drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
