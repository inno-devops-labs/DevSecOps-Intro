package main

deny contains msg if {
  input.kind == "Deployment"
  run_as_non_root := object.get(input, ["spec", "template", "spec", "securityContext", "runAsNonRoot"], false)
  run_as_non_root != true
  msg := "Pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  readonly_fs := object.get(container, ["securityContext", "readOnlyRootFilesystem"], false)
  readonly_fs != true
  msg := sprintf("Container '%s' must set readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  allow_escalation := object.get(container, ["securityContext", "allowPrivilegeEscalation"], true)
  allow_escalation != false
  msg := sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  dropped := object.get(container, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in dropped
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}