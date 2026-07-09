package main

containers := input.spec.template.spec.containers

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

security_context(container) := object.get(container, "securityContext", {})

capabilities(container) := object.get(security_context(container), "capabilities", {})

capability_drops(container) := object.get(capabilities(container), "drop", [])

has_value(arr, value) if {
  some i
  arr[i] == value
}

container_runs_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
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
  object.get(security_context(container), "allowPrivilegeEscalation", null) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := containers[_]
  not has_value(capability_drops(container), "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
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
