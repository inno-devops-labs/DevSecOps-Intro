package main

# 1. Pod or container must set runAsNonRoot: true
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment '%s': container '%s' must set runAsNonRoot: true", [input.metadata.name, c.name])
}

# 2. allowPrivilegeEscalation must be explicitly false on every container
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Deployment '%s': container '%s' must set allowPrivilegeEscalation: false", [input.metadata.name, c.name])
}

# 3. capabilities.drop must include ALL on every container
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not "ALL" in c.securityContext.capabilities.drop
  msg := sprintf("Deployment '%s': container '%s' must drop ALL capabilities", [input.metadata.name, c.name])
}

# 4. Memory limits must be set (OOM kill bound)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("Deployment '%s': container '%s' must set resources.limits.memory", [input.metadata.name, c.name])
}

# 5. Image must not use :latest tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("Deployment '%s': container '%s' uses disallowed :latest tag — pin to a digest or explicit version", [input.metadata.name, c.name])
}
