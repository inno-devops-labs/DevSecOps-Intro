package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "Deployment must explicitly set securityContext.runAsNonRoot: true"
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Container '%s' must explicitly set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	drop := object.get(container, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drop
	msg := sprintf("Container '%s' must drop ALL capabilities via capabilities.drop", [container.name])
}
