package main

containers := input.spec.template.spec.containers if {
  input.kind == "Deployment"
}

containers := input.spec.containers if {
  input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

pod_spec := input.spec if {
  input.kind == "Pod"
}

has_value(arr, value) if {
  some i
  arr[i] == value
}

capabilities_drop(container) := drop if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  drop := object.get(capabilities, "drop", [])
}

run_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

run_as_non_root(container) if {
  pod_spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
  container := containers[_]
  not run_as_non_root(container)
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  container := containers[_]
  not has_value(capabilities_drop(container), "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
