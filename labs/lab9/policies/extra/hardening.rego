package main

import rego.v1

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    security_context := object.get(container, "securityContext", {})
    capabilities := object.get(security_context, "capabilities", {})
    dropped_capabilities := object.get(capabilities, "drop", [])
    not "ALL" in dropped_capabilities
    msg := sprintf("container %q must drop ALL Linux capabilities", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("container %q must set resources.limits.memory", [container.name])
}

