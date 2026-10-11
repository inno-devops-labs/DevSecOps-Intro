package main

containers := input.spec.template.spec.containers

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

container_security_context(container) := object.get(container, "securityContext", {})

container_dropped_capabilities(container) := object.get(object.get(container_security_context(container), "capabilities", {}), "drop", [])

container_runs_as_non_root(container) if {
  container_security_context(container).runAsNonRoot == true
}

container_runs_as_non_root(container) if {
  pod_security_context.runAsNonRoot == true
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not container_runs_as_non_root(container)
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not container_security_context(container).allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not "ALL" in container_dropped_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("container %q must pin image by sha256 digest", [container.name])
}
