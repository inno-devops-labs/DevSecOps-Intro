package main

drops_all(container) if {
    container.securityContext.capabilities.drop[_] == "ALL"
}

deny contains msg if {
    input.kind == "Deployment"

    not input.spec.template.spec.securityContext.runAsNonRoot

    msg := "Pod must set spec.securityContext.runAsNonRoot=true"
}

deny contains msg if {
    input.kind == "Deployment"

    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem

    msg := sprintf("Container %q must set securityContext.readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"

    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation != false

    msg := sprintf("Container %q must set securityContext.allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"

    container := input.spec.template.spec.containers[_]
    not drops_all(container)

    msg := sprintf("Container %q must drop ALL capabilities", [container.name])
}
