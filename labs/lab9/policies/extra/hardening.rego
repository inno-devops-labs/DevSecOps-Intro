package main

import rego.v1

# 1. runAsNonRoot must be true (pod-level OR container-level securityContext)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not container_runs_non_root(c)
	msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

container_runs_non_root(c) if c.securityContext.runAsNonRoot == true

container_runs_non_root(c) if input.spec.template.spec.securityContext.runAsNonRoot == true

# 2. allowPrivilegeEscalation must be false on every container
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" on every container
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not drops_all_caps(c)
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

drops_all_caps(c) if "ALL" in c.securityContext.capabilities.drop

# 4. resources.limits.memory must be set
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. image must be pinned by sha256 digest, not a tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin image by @sha256: digest, not a tag", [c.name])
}
