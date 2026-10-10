package k8s.extra

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run as privileged", [c.name])
}

warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.hostNetwork == true
  c := input.spec.template.spec.containers[_]
  msg := sprintf("container %q should not use hostNetwork", [c.name])
}
