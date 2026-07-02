package main

deny[msg] {
  input.kind == "Deployment"
  pod := input.spec.template.spec
  not pod.securityContext.runAsNonRoot
  msg := "Pod must set securityContext.runAsNonRoot: true"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation
  msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.capabilities
  msg := sprintf("Container '%s' must define securityContext.capabilities", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.capabilities
  not has_drop_all(container)
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

has_drop_all(container) {
  container.securityContext.capabilities.drop[_] == "ALL"
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
  msg := "Pod must set automountServiceAccountToken: false"
}

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.seccompProfile
  msg := "Pod must define seccompProfile in securityContext"
}
