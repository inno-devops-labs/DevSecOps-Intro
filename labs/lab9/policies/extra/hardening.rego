package main

has_value(arr, v) if {
	some i
	arr[i] == v
}

runs_as_non_root(c) if {
	c.securityContext.runAsNonRoot == true
}

runs_as_non_root(c) if {
	input.spec.template.spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not runs_as_non_root(c)
	msg := sprintf("container %q must set runAsNonRoot: true (pod- or container-level securityContext)", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	drop := object.get(c, ["securityContext", "capabilities", "drop"], [])
	not has_value(drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin its image by sha256 digest, not a mutable tag", [c.name])
}
