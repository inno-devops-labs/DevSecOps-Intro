package main

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg = sprintf("Container %v must have runAsNonRoot=true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = sprintf("Container %v must have allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg = sprintf("Container %v must drop ALL capabilities", [container.name])
}