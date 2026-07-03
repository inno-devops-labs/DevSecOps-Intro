package main

has_run_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

has_run_as_non_root(container) if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

drops_all_capabilities(container) if {
  "ALL" in container.securityContext.capabilities.drop
}

uses_digest(image) if {
  contains(image, "@sha256:")
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not has_run_as_non_root(container)
  msg := sprintf("container %q must set runAsNonRoot=true at pod or container level", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not uses_digest(container.image)
  msg := sprintf("container %q must pin image by sha256 digest", [container.name])
}
