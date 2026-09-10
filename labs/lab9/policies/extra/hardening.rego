package main

# Custom K8s hardening policy for Lab 9 (Task 2).
# Package "main" is Conftest's default namespace, so these run with a plain
# `conftest test --policy labs/lab9/policies/extra/` (no --namespace needed).
# Complements the shipped k8s.security starter policy with the same deny[msg] idiom.

# Helper: true if array arr contains value v
has_value(arr, v) if {
	some i
	arr[i] == v
}

# ---------------------------------------------------------------------------
# Rule 1 (required): runAsNonRoot must be true.
# Accepts either a pod-level OR container-level securityContext setting, so a
# manifest that hardens once at the pod level still passes.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.runAsNonRoot
	not input.spec.template.spec.securityContext.runAsNonRoot
	msg := sprintf("container %q must run as non-root (set runAsNonRoot: true at pod or container level)", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 2 (required): allowPrivilegeEscalation must be false on every container.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 3 (required): every container must drop ALL capabilities.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not has_value(c.securityContext.capabilities.drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 4 (optional): memory limit must be set (prevents noisy-neighbor OOM).
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 5 (optional): image must not use the mutable :latest tag.
# A pinned version tag (e.g. :v19.0.0) is acceptable; :latest is not, because
# it makes deployments non-reproducible and silently drift on every pull.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	endswith(c.image, ":latest")
	msg := sprintf("container %q must not use the mutable :latest tag; pin a version", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 6 (optional): image must carry an explicit tag at all (no bare name,
# which implicitly resolves to :latest).
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, ":")
	msg := sprintf("container %q image must carry an explicit version tag", [c.name])
}
