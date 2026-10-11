package main

import rego.v1

# Rule 1: runAsNonRoot must be true
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not input.spec.securityContext.runAsNonRoot
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container '%v' must set runAsNonRoot=true (pod-level or container-level)", [container.name])
}

# Rule 2: allowPrivilegeEscalation must be false
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("Container '%v' must set allowPrivilegeEscalation=false", [container.name])
}

# Rule 3: capabilities.drop must include ALL
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not "ALL" in container.securityContext.capabilities.drop
  msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

# Rule 4: memory limits must be set
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container '%v' must set resources.limits.memory", [container.name])
}
