package main

import rego.v1

is_deployment if {
  input.kind == "Deployment"
}

pod_spec := input.spec.template.spec if {
  is_deployment
}

containers := object.get(pod_spec, "containers", []) if {
  is_deployment
}

pod_runs_as_non_root if {
  pod_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_context, "runAsNonRoot", false) == true
}

container_runs_as_non_root(container) if {
  context := object.get(container, "securityContext", {})
  object.get(context, "runAsNonRoot", false) == true
}

deny contains msg if {
  is_deployment
  container := containers[_]
  not pod_runs_as_non_root
  not container_runs_as_non_root(container)
  msg := sprintf(
    "container %q must set runAsNonRoot=true at pod or container level",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf(
    "container %q must set allowPrivilegeEscalation=false",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  context := object.get(container, "securityContext", {})
  capabilities := object.get(context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])
  not "ALL" in dropped
  msg := sprintf(
    "container %q must drop the ALL capability set",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  resources := object.get(container, "resources", {})
  limits := object.get(resources, "limits", {})
  object.get(limits, "memory", "") == ""
  msg := sprintf(
    "container %q must define resources.limits.memory",
    [container.name],
  )
}

deny contains msg if {
  is_deployment
  container := containers[_]
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf(
    "container %q must set readOnlyRootFilesystem=true",
    [container.name],
  )
}
