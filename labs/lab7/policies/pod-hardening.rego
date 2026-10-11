package main

pod_spec := object.get(object.get(input.spec, "template", {}), "spec", {})

deny contains msg if {
  input.kind == "Deployment"
  object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
  msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  container := pod_spec.containers[i]
  object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
  name := container.name
  msg := sprintf("Container %q must set readOnlyRootFilesystem to true", [name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  container := pod_spec.containers[i]
  object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false
  name := container.name
  msg := sprintf("Container %q must set allowPrivilegeEscalation to false", [name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  container := pod_spec.containers[i]
  drops := object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
  not "ALL" in drops
  name := container.name
  msg := sprintf("Container %q must drop capability ALL", [name])
}
