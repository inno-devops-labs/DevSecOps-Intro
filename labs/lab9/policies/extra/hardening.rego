package main

import rego.v1

# Lab 9 Task 2 — K8s Deployment hardening gate (CI-time Conftest).
# Runs in the default `main` namespace, so: conftest test <manifest> --policy labs/lab9/policies/extra/

# The pod template spec of a Deployment.
podspec := input.spec.template.spec if input.kind == "Deployment"

# A container is "non-root" if runAsNonRoot is set true at pod OR container level.
container_nonroot(c) if podspec.securityContext.runAsNonRoot == true
container_nonroot(c) if c.securityContext.runAsNonRoot == true

# 1. Must run as non-root.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not container_nonroot(c)
	msg := sprintf("container %q must run as non-root (securityContext.runAsNonRoot: true)", [c.name])
}

# 2. Must not allow privilege escalation.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. Must drop ALL Linux capabilities.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. Must set a memory limit (prevents node-level resource exhaustion).
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. Must pin the image by digest, not a mutable tag.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin image by digest (@sha256:), not a tag", [c.name])
}
