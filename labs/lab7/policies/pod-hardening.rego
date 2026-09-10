package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "Policy Violation [PSS-Restricted]: Pod template specification must explicitly set 'securityContext.runAsNonRoot: true' to prevent container execution under the root user."
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("Policy Violation [PSS-Restricted]: Container '%s' must enforce an immutable filesystem by explicitly configuring 'securityContext.readOnlyRootFilesystem: true'.", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Policy Violation [PSS-Restricted]: Container '%s' must explicitly prevent privilege escalation vectors by setting 'securityContext.allowPrivilegeEscalation: false'.", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	drop := object.get(container, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drop
	msg := sprintf("Policy Violation [PSS-Restricted]: Container '%s' must drop all default Linux kernel capabilities via 'securityContext.capabilities.drop: [\"ALL\"]'.", [container.name])
}