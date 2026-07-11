package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true (pod or container level)", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities (capabilities.drop not set)", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  c.securityContext.capabilities.drop
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must include \"ALL\" in capabilities.drop", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by sha256 digest, not a tag", [c.name])
}
