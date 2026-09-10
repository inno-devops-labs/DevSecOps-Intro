package main

import rego.v1

# Lab 9 Task 2 — CI-time hardening gate for K8s Deployments.
# `not <field> == <value>` (rather than `!=`) so an entirely-absent field also trips the rule.

podspec := input.spec.template.spec

# 1. Pod must run as non-root (accept it set at pod OR container level).
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not runs_non_root(c)
	msg := sprintf("container %q: must run as non-root (securityContext.runAsNonRoot: true)", [c.name])
}

runs_non_root(c) if c.securityContext.runAsNonRoot == true
runs_non_root(_) if podspec.securityContext.runAsNonRoot == true

# 2. No privilege escalation.
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q: securityContext.allowPrivilegeEscalation must be false", [c.name])
}

# 3. Drop ALL capabilities.
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("container %q: securityContext.capabilities.drop must include \"ALL\"", [c.name])
}

# 4. Memory limit must be set (prevents node-level resource exhaustion / noisy-neighbour).
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not c.resources.limits.memory
	msg := sprintf("container %q: resources.limits.memory must be set", [c.name])
}

# 5. Image must be pinned by digest, not a mutable tag.
deny contains msg if {
	input.kind == "Deployment"
	some c in podspec.containers
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q: image must be pinned by @sha256 digest, not a tag (%s)", [c.name, c.image])
}
