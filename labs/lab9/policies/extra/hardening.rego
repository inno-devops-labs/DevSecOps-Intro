package main

# 1. runAsNonRoot must be true (pod-level or container-level)
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.securityContext.runAsNonRoot == true
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must set runAsNonRoot: true (pod- or container-level)", [c.name])
}

# 2. allowPrivilegeEscalation must be false on every container
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" on every container
# (uses object.get with a [] default so a MISSING securityContext/capabilities
#  path is treated as "no drops", not as "undefined" that silently skips the rule)
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    drops := object.get(c, ["securityContext", "capabilities", "drop"], [])
    not "ALL" in drops
    msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. (bonus) resources.limits.memory must be set
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. (bonus) image must be pinned by sha256 digest, not a mutable tag
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not contains(c.image, "@sha256:")
    msg := sprintf("container %q must be pinned by sha256 digest, not a tag", [c.name])
}