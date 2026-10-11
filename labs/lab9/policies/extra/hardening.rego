package main

import rego.v1

deny contains msg if {
    c := input.spec.template.spec.containers[_]
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    not c.securityContext.runAsNonRoot == true
    msg := sprintf("Container %v must set runAsNonRoot to true", [c.name])
}

deny contains msg if {
    c := input.spec.template.spec.containers[_]
    not c.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %v must set allowPrivilegeEscalation to false", [c.name])
}

deny contains msg if {
    c := input.spec.template.spec.containers[_]
    not has_drop_all(c)
    msg := sprintf("Container %v must drop ALL capabilities", [c.name])
}

deny contains msg if {
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("Container %v must have a memory limit set", [c.name])
}

deny contains msg if {
    c := input.spec.template.spec.containers[_]
    not contains(c.image, "@sha256:")
    msg := sprintf("Container %v must use a sha256 image digest", [c.name])
}

has_drop_all(c) if {
    "ALL" in c.securityContext.capabilities.drop
}
