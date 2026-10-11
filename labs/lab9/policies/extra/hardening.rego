package main

container_run_as_non_root(container, pod_spec) if {
  container_security_context := object.get(container, "securityContext", {})
  object.get(container_security_context, "runAsNonRoot", false) == true
}

container_run_as_non_root(container, pod_spec) if {
  pod_security_context := object.get(pod_spec, "securityContext", {})
  object.get(pod_security_context, "runAsNonRoot", false) == true
}

deny contains msg if {
  input.kind == "Deployment"

  pod_spec := input.spec.template.spec
  container := pod_spec.containers[_]

  not container_run_as_non_root(container, pod_spec)

  msg := sprintf(
    "container %q must set runAsNonRoot: true at pod or container level",
    [container.name],
  )
}

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})

  object.get(security_context, "allowPrivilegeEscalation", true) != false

  msg := sprintf(
    "container %q must set allowPrivilegeEscalation: false",
    [container.name],
  )
}

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped_capabilities := object.get(capabilities, "drop", [])

  not "ALL" in dropped_capabilities

  msg := sprintf(
    "container %q must drop ALL capabilities",
    [container.name],
  )
}

deny contains msg if {
  input.kind == "Deployment"

  container := input.spec.template.spec.containers[_]
  resources := object.get(container, "resources", {})
  limits := object.get(resources, "limits", {})

  not object.get(limits, "memory", false)

  msg := sprintf(
    "container %q must set resources.limits.memory",
    [container.name],
  )
}
