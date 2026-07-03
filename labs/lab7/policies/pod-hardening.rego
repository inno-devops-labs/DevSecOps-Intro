package main

import rego.v1

# Deny if pod-level securityContext.runAsNonRoot is not true
deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod securityContext.runAsNonRoot must be true"
}

# Deny if any container is missing readOnlyRootFilesystem: true
deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

# Deny if any container is missing allowPrivilegeEscalation: false
deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

# Deny if any container does not drop ALL capabilities
# Uses object.get with a default of [] so this rule still fires even when
# securityContext (or capabilities, or drop) is missing entirely from the
# container spec -- otherwise "ALL" in undefined is undefined and the rule
# silently never triggers.
deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	drop := object.get(container, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drop
	msg := sprintf("container '%s' must drop ALL capabilities", [container.name])
}
