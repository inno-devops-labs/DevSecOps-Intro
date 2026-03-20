package main

# Deny privileged containers
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("DENY: Container '%v' must not run as privileged", [container.name])
}

# Deny running as root (uid 0)
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf("DENY: Container '%v' must not run as root (runAsUser: 0)", [container.name])
}

# Deny allowPrivilegeEscalation
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation == true
  msg := sprintf("DENY: Container '%v' must set allowPrivilegeEscalation: false", [container.name])
}

# Warn if readOnlyRootFilesystem is not true
warn contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("WARN: Container '%v' should set readOnlyRootFilesystem: true", [container.name])
}

# Warn if resource limits are missing
warn contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf("WARN: Container '%v' has no resource limits defined", [container.name])
}
