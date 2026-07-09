package main

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("Container %s must set runAsNonRoot to true (pod or container level)", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Container %s must set allowPrivilegeEscalation to false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not "ALL" in c.securityContext.capabilities.drop
  msg := sprintf("Container %s must drop ALL capabilities", [c.name])
}
