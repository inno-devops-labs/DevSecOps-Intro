package main

import rego.v1

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    not c.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    c.securityContext.allowPrivilegeEscalation != false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not contains(c.image, "@sha256:")
    msg := sprintf("container %q must use an image digest (@sha256:)", [c.name])
}
