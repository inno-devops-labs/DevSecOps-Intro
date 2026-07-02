package main

deny contains msg if {
  input.kind == "Deployment"
  pod_spec := input.spec.template.spec
  pod_security_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_security_context, "runAsNonRoot", false) != true
  msg := "pod must set spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %q must set readOnlyRootFilesystem to true", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  security_context := object.get(container, "securityContext", {})
  object.get(security_context, "allowPrivilegeEscalation", null) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  drop_list := object.get(capabilities, "drop", [])
  not "ALL" in drop_list
  msg := sprintf("container %q must drop the ALL capability set", [container.name])
}
