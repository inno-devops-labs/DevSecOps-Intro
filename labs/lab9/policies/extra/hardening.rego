package main

# 1. runAsNonRoot must be true (container-level)
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true", [container.name])
}

# 1a. runAsNonRoot must be true (pod-level fallback)
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("container %q: neither pod nor container sets runAsNonRoot: true", [container.name])
}

# 2. allowPrivilegeEscalation must be false
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

# 3. capabilities.drop must include "ALL"
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities (capabilities.drop missing)", [container.name])
}

deny[msg] {
  container := input.spec.template.spec.containers[_]
  caps := container.securityContext.capabilities.drop
  count({v | v := caps[_]; v == "ALL"}) == 0
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}

# 4. resources.limits.memory must be set
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.resources
  msg := sprintf("container %q must have resources defined", [container.name])
}

deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
