package main

has_value(arr, value) if {
  some i
  arr[i] == value
}

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

deny contains msg if {
  input.kind == "Deployment"
  not pod_spec.securityContext.runAsNonRoot == true
  msg := "pod must set spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  input.kind == "Deployment"
  c := pod_spec.containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %q must set readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := pod_spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := pod_spec.containers[_]
  security_context := object.get(c, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  drop := object.get(capabilities, "drop", [])
  not has_value(drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
