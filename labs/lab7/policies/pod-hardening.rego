package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "pod spec.securityContext.runAsNonRoot must be true"
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s': readOnlyRootFilesystem must be true", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container '%s': allowPrivilegeEscalation must be false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not drops_all(c)
	msg := sprintf("container '%s': capabilities must drop ALL", [c.name])
}

drops_all(c) if {
	c.securityContext.capabilities.drop[_] == "ALL"
}
