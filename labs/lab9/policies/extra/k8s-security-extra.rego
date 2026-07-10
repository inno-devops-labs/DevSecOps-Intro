package k8s.security.extra

has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  drops := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not has_value(drops, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
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
  msg := sprintf("container %q image %q must be pinned by sha256 digest", [c.name, c.image])
}
