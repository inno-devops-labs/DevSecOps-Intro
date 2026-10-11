package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

# 1. runAsNonRoot must be true (pod-level or container-level)
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment must set runAsNonRoot: true (pod-level or container-level for %q)", [c.name])
}

# 2. allowPrivilegeEscalation must be false (every container)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" (every container)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# 5. image must use sha256 digest, not :tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  contains(c.image, ":")
  not contains(c.image, "@")
  msg := sprintf("container %q must use image with sha256 digest, not tag (e.g., image@sha256:...), got: %q", [c.name, c.image])
}