package main

import future.keywords.contains
import future.keywords.if

# Helper: true if value v appears in array arr
value_in(arr, v) if {
  some i
  arr[i] == v
}

# Rule 1: containers must run as non-root
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

# Rule 2: privilege escalation must be disabled
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# Rule 3: all Linux capabilities must be dropped
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not value_in(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# Rule 4: memory limits must be set
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# Rule 5: images should be pinned by digest, not floating tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...)", [c.name])
}
