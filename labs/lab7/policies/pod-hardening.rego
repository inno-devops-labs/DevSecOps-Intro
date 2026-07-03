package main

import future.keywords.in

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

is_deployment {
	input.kind == "Deployment"
}

pod_spec := input.spec.template.spec

containers[container] {
	is_deployment
	container := pod_spec.containers[_]
}

# ---------------------------------------------------------------------------
# Rule: pods must not run as root
# ---------------------------------------------------------------------------

deny[msg] {
	is_deployment
	not pod_spec.securityContext.runAsNonRoot
	msg := sprintf(
		"[PSS-01] Deployment '%s': spec.template.spec.securityContext.runAsNonRoot must be true",
		[input.metadata.name],
	)
}

# ---------------------------------------------------------------------------
# Rule: every container needs a read-only root filesystem
# ---------------------------------------------------------------------------

deny[msg] {
	is_deployment
	container := containers[_]
	not container.securityContext.readOnlyRootFilesystem
	msg := sprintf(
		"[PSS-02] Deployment '%s': container '%s' is missing securityContext.readOnlyRootFilesystem",
		[input.metadata.name, container.name],
	)
}

# ---------------------------------------------------------------------------
# Rule: privilege escalation must be disabled
# ---------------------------------------------------------------------------

deny[msg] {
	is_deployment
	container := containers[_]
	container.securityContext.allowPrivilegeEscalation != false
	msg := sprintf(
		"[PSS-03] Deployment '%s': container '%s' must set allowPrivilegeEscalation to false",
		[input.metadata.name, container.name],
	)
}

# ---------------------------------------------------------------------------
# Rule: all capabilities must be dropped
# ---------------------------------------------------------------------------

deny[msg] {
	is_deployment
	container := containers[_]
	not "ALL" in container.securityContext.capabilities.drop
	msg := sprintf(
		"[PSS-04] Deployment '%s': container '%s' must drop ALL capabilities",
		[input.metadata.name, container.name],
	)
}
