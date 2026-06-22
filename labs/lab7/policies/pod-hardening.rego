package main

has_all_drop(container) if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])
  "ALL" in dropped
}

deny contains msg if {
  input.kind == "Deployment"
  pod_spec := input.spec.template.spec
  pod_security_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_security_context, "runAsNonRoot", false) != true
  msg := "Deployment pod template must set spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %q must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not has_all_drop(container)
  msg := sprintf("container %q must drop Linux capability ALL", [container.name])
}
