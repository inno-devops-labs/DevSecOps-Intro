package main

is_deployment if {
  input.kind == "Deployment"
}

pod_run_as_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

container_run_as_non_root(c) if {
  c.securityContext.runAsNonRoot == true
}

drop_all_caps(c) if {
  "ALL" in c.securityContext.capabilities.drop
}

uses_digest(image) if {
  contains(image, "@sha256:")
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not pod_run_as_non_root
  not container_run_as_non_root(c)
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not drop_all_caps(c)
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  is_deployment
  c := input.spec.template.spec.containers[_]
  not uses_digest(c.image)
  msg := sprintf("container %q must use an image pinned by sha256 digest", [c.name])
}
