package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	pod_sec := object.get(input.spec.template.spec, "securityContext", {})
	not pod_sec.runAsNonRoot

	some container in input.spec.template.spec.containers
	cont_sec := object.get(container, "securityContext", {})
	not cont_sec.runAsNonRoot

	msg := sprintf("Container '%v' must have runAsNonRoot=true", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	cont_sec := object.get(container, "securityContext", {})
	not cont_sec.allowPrivilegeEscalation == false

	msg := sprintf("Container '%v' must have allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	cont_sec := object.get(container, "securityContext", {})
	caps := object.get(cont_sec, "capabilities", {})
	drop := object.get(caps, "drop", [])
	not "ALL" in drop

	msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}
