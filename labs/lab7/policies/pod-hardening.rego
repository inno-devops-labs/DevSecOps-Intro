package main

import rego.v1

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

deny contains msg if {
  input.kind == "Deployment"
  security_context := object.get(pod_spec, "securityContext", {})
  object.get(security_context, "runAsNonRoot", false) != true
  msg := "Pod must set securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  some container in pod_spec.containers
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("Container %q must use readOnlyRootFilesystem", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in pod_spec.containers
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("Container %q must disable privilege escalation", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some container in pod_spec.containers
  context := object.get(container, "securityContext", {})
  capabilities := object.get(context, "capabilities", {})
  drops := object.get(capabilities, "drop", [])
  not "ALL" in drops
  msg := sprintf("Container %q must drop ALL capabilities", [container.name])
}
