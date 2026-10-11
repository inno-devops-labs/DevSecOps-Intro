package main

all_containers(spec) = containers {
	containers := array.concat(
		object.get(spec, "containers", []),
		object.get(spec, "initContainers", []),
	)
}

is_non_root(spec) {
	spec.securityContext.runAsNonRoot == true
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	not is_non_root(spec)
	msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot: true"
}

is_readonly_rootfs(container) {
	container.securityContext.readOnlyRootFilesystem == true
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	container := all_containers(spec)[_]
	not is_readonly_rootfs(container)
	msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

no_priv_escalation(container) {
	container.securityContext.allowPrivilegeEscalation == false
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	container := all_containers(spec)[_]
	not no_priv_escalation(container)
	msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

drops_all_caps(container) {
	container.securityContext.capabilities.drop[_] == "ALL"
}

deny[msg] {
	input.kind == "Deployment"
	spec := input.spec.template.spec
	container := all_containers(spec)[_]
	not drops_all_caps(container)
	msg := sprintf("Container '%s' must drop ALL capabilities (securityContext.capabilities.drop: [\"ALL\"])", [container.name])
}
