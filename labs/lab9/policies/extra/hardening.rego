package main

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  run_as_non_root := object.get(c, ["securityContext", "runAsNonRoot"], false)
  run_as_non_root != true
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  allow_escalation := object.get(c, ["securityContext", "allowPrivilegeEscalation"], true)
  allow_escalation != false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  dropped := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in dropped
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  mem_limit := object.get(c, ["resources", "limits", "memory"], "")
  mem_limit == ""
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not startswith(c.image, "bkimminich/juice-shop@sha256:")
  contains(c.image, "@sha256:") == false
  msg := sprintf("container %q should pin image by digest (sha256:...), not a tag", [c.name])
}