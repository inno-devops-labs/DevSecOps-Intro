package main

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot == true
	msg := "Pod must set runAsNonRoot: true in pod-level securityContext"
}

deny contains msg if {
	input.kind == "Deployment"
	some container
	c := input.spec.template.spec.containers[container]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("Container %v must set readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container
	c := input.spec.template.spec.containers[container]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("Container %v must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container
	c := input.spec.template.spec.containers[container]
	not c.securityContext.capabilities
	msg := sprintf("Container %v must define capabilities.drop (missing entirely)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container
	c := input.spec.template.spec.containers[container]
	c.securityContext.capabilities
	every cap in c.securityContext.capabilities.drop {
		cap != "ALL"
	}
	msg := sprintf("Container %v must drop ALL capabilities", [c.name])
}
