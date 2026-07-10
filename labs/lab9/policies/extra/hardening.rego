package main

import future.keywords.in

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg = sprintf("Container %v: runAsNonRoot must be set to true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = sprintf("Container %v: allowPrivilegeEscalation must be false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg = sprintf("Container %v: capabilities.drop must include ALL", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg = sprintf("Container %v: resources.limits.memory must be set", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not contains(container.image, "@sha256:")
    msg = sprintf("Container %v: image must use sha256 digest, not tag", [container.name])
}
