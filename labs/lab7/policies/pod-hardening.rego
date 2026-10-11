package main

# Deny pods where pod-level runAsNonRoot is not true
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment '%s': pod securityContext must set runAsNonRoot: true", [input.metadata.name])
}

# Deny containers without readOnlyRootFilesystem: true
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("Deployment '%s': container '%s' must set readOnlyRootFilesystem: true", [input.metadata.name, container.name])
}

# Deny containers where allowPrivilegeEscalation is not false
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Deployment '%s': container '%s' must set allowPrivilegeEscalation: false", [input.metadata.name, container.name])
}

# Deny containers that do not drop ALL capabilities
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not "ALL" in container.securityContext.capabilities.drop
  msg := sprintf("Deployment '%s': container '%s' must drop ALL capabilities", [input.metadata.name, container.name])
}
