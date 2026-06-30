package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not allow_privilege_escalation_false(container)
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not has_drop_all(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

allow_privilege_escalation_false(container) if {
  container.securityContext.allowPrivilegeEscalation == false
}

has_drop_all(container) if {
  some i
  container.securityContext.capabilities.drop[i] == "ALL"
}
