package main

has_value(arr, v) {
  some i
  arr[i] == v
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny[msg] {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}