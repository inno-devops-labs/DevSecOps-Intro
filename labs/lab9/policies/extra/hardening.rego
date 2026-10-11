package main

deny contains msg if {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg := "DENY: Pod must have runAsNonRoot = true"
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("DENY: Container '%s' must have allowPrivilegeEscalation = false", [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("DENY: Container '%s' must drop ALL capabilities", [container.name])
}

deny contains msg if {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("DENY: Container '%s' must have memory limits", [container.name])
}
