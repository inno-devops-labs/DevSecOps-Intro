package main

has_value(arr, v) if {
  some i
  arr[i] == v
}

run_as_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

run_as_non_root if {
  c := input.spec.template.spec.containers[_]
  c.securityContext.runAsNonRoot == true
}

deny contains msg if {
  input.kind == "Deployment"
  not run_as_non_root
  msg := "pod or containers must set runAsNonRoot: true"
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
  not has_value(c.securityContext.capabilities.drop, "ALL")
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
  msg := sprintf("container %q image must be pinned by digest (@sha256:...)", [c.name])
}
