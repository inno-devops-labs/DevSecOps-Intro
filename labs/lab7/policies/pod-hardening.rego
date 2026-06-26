package main

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "pod must set spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.securityContext.runAsNonRoot != true

  msg := "pod must set spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem

  msg := sprintf("container %q must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.readOnlyRootFilesystem != true

  msg := sprintf("container %q must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false

  msg := sprintf("container %q must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not "ALL" in container.securityContext.capabilities.drop

  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}
