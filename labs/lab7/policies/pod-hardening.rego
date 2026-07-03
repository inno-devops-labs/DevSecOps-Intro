package main

import rego.v1

# Gate Deployments that miss the core container-hardening controls.
# Run: conftest test labs/lab7/k8s/deployment.yaml --policy labs/lab7/policies
#
# The `not <field> == <value>` form (rather than `<field> != <value>`) is deliberate:
# it also fires when the field is *entirely absent* (undefined), which is exactly the
# case for a manifest that ships no securityContext at all.

podspec := input.spec.template.spec

# 1. Pod must run as non-root
deny contains msg if {
	input.kind == "Deployment"
	not podspec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be true"
}

# 2. Every container must have a read-only root filesystem
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container %q: securityContext.readOnlyRootFilesystem must be true", [c.name])
}

# 3. Every container must forbid privilege escalation
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q: securityContext.allowPrivilegeEscalation must be false", [c.name])
}

# 4. Every container must drop ALL capabilities
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not drops_all(c)
	msg := sprintf("container %q: securityContext.capabilities.drop must include \"ALL\"", [c.name])
}

drops_all(c) if {
	"ALL" in c.securityContext.capabilities.drop
}
