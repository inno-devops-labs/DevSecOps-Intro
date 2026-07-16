package main

import rego.v1

# 1. runAsNonRoot must be true (pod-level or container-level securityContext)
deny contains msg if {
  input.kind == "Deployment"
  spec := input.spec.template.spec
  containers := spec.containers[_]
  not spec.securityContext.runAsNonRoot == true
  not containers.securityContext.runAsNonRoot == true
  msg := "spec.template.spec.securityContext.runAsNonRoot (or per-container) must be true"
}

# 2. allowPrivilegeEscalation must be false (every container)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" (every container)
# NOTE: `not "ALL" in c.securityContext.capabilities.drop` silently never fires
# when securityContext is entirely absent (undefined does not propagate through
# `in` the way it does through a plain `not`), so default missing paths to [].
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  drop := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in drop
  msg := sprintf("container %q must drop ALL capabilities (capabilities.drop: [\"ALL\"])", [c.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. image must be pinned by sha256 digest, not a mutable tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin image by @sha256: digest, not a mutable tag (%q)", [c.name, c.image])
}
