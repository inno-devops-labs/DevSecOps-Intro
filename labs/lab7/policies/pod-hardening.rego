package main

import future.keywords

is_deployment {
    input.kind == "Deployment"
}

deny[msg] {
    is_deployment
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := "Pod must set spec.securityContext.runAsNonRoot to true"
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' must set readOnlyRootFilesystem to true", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' must set allowPrivilegeEscalation to false", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    caps := container.securityContext.capabilities
    not caps.drop
    msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    caps := container.securityContext.capabilities
    not "ALL" in caps.drop
    msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny[msg] {
    is_deployment
    some container in input.spec.template.spec.containers
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container '%s' must set runAsNonRoot to true", [container.name])
}