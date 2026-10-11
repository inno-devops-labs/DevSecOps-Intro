package main

containers contains container if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
}

run_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

run_as_non_root(container) if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

drops_all_capabilities(container) if {
  drop := container.securityContext.capabilities.drop[_]
  drop == "ALL"
}

deny contains msg if {
  container := containers[_]
  not run_as_non_root(container)
  msg := sprintf("container %q must run as non-root at pod or container level", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
  container := containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
  container := containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

deny contains msg if {
  container := containers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("container %q must pin image by sha256 digest", [container.name])
}
