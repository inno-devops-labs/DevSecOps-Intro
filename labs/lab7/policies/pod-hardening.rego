package main

import rego.v1

# Extract Pod spec from Deployment
pod_spec = input.spec.template.spec {
	input.kind == "Deployment"
}

# Collect both normal and init containers
containers[container] {
	container := pod_spec.containers[_]
}

containers[container] {
	container := pod_spec.initContainers[_]
}

# Deny if runAsNonRoot is not explicitly true
deny[msg] {
	input.kind == "Deployment"
	spec_security := object.get(pod_spec, "securityContext", {})
	object.get(spec_security, "runAsNonRoot", false) != true
	msg := "pod spec must set securityContext.runAsNonRoot: true"
}

# Deny if any container does not have readOnlyRootFilesystem: true
deny[msg] {
	input.kind == "Deployment"
	container := containers[_]
	container_security := object.get(container, "securityContext", {})
	object.get(container_security, "readOnlyRootFilesystem", false) != true
	msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

# Deny if any container allows privilege escalation (not set to false)
deny[msg] {
	input.kind == "Deployment"
	container := containers[_]
	container_security := object.get(container, "securityContext", {})
	object.get(container_security, "allowPrivilegeEscalation", true) != false
	msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

# Deny if capabilities.drop does not include ALL
deny[msg] {
	input.kind == "Deployment"
	container := containers[_]
	container_security := object.get(container, "securityContext", {})
	capabilities := object.get(container_security, "capabilities", {})
	dropped := object.get(capabilities, "drop", [])
	not "ALL" in dropped
	msg := sprintf("container %q must drop all Linux capabilities with capabilities.drop: [\"ALL\"]", [container.name])
}
