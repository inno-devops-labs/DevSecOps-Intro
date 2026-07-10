package main

import rego.v1

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %q must set runAsNonRoot=true", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container %q must drop ALL capabilities", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container %q must define memory limits", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    contains(container.image, ":latest")
    msg := sprintf("Container %q must not use the latest tag", [container.name])
}