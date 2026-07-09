package main

import rego.v1

has_value(arr, v) if {
	some i
	arr[i] == v
}

# 1. runAsNonRoot must be true (pod-level or container-level)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not run_as_non_root(c)
	msg := sprintf("container %q must set runAsNonRoot: true (pod or container securityContext)", [c.name])
}

run_as_non_root(c) if {
	c.securityContext.runAsNonRoot == true
}

run_as_non_root(c) if {
	input.spec.template.spec.securityContext.runAsNonRoot == true
}

# 2. allowPrivilegeEscalation must be false (every container)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" (every container)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not has_value(c.securityContext.capabilities.drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# 5. image must use sha256 digest, not :tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q image must use @sha256: digest pinning, not tag", [c.name])
}
