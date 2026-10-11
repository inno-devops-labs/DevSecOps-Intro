package main

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg := sprintf("Pod '%s' missing required securityContext.runAsNonRoot=true", [input.metadata.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' in pod '%s' missing required readOnlyRootFilesystem=true", [container.name, input.metadata.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' in pod '%s' must have allowPrivilegeEscalation=false", [container.name, input.metadata.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    caps := container.securityContext.capabilities.drop
    not caps[_] == "ALL"
    msg := sprintf("Container '%s' in pod '%s' must drop ALL capabilities", [container.name, input.metadata.name])
}
