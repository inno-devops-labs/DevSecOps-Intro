package main

import rego.v1

is_deployment if {
  input.kind == "Deployment"
}

pod_spec := input.spec.template.spec if {
  is_deployment
}

all_containers := array.concat(
  object.get(pod_spec, "initContainers", []),
  object.get(pod_spec, "containers", [])
) if {
  is_deployment
}

deny contains msg if {
  is_deployment
  object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
  msg := "pod securityContext.runAsNonRoot must be true"
}

deny contains msg if {
  is_deployment
  container := all_containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %q must set readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
  is_deployment
  container := all_containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  is_deployment
  container := all_containers[_]
  context := object.get(container, "securityContext", {})
  capabilities := object.get(context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])
  not "ALL" in dropped
  msg := sprintf("container %q must drop the ALL capability set", [container.name])
}
