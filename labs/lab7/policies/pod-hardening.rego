package main

import rego.v1

all_containers contains c if {
    c := input.spec.template.spec.containers[_]
}
all_containers contains c if {
    c := input.spec.template.spec.initContainers[_]
}

deny contains msg if {
    input.kind == "Deployment"
    pod_spec := input.spec.template.spec
    not pod_spec.securityContext.runAsNonRoot == true
    msg := sprintf("Deployment '%s' missing pod-level runAsNonRoot=true", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := all_containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' is missing readOnlyRootFilesystem=true", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := all_containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' must have allowPrivilegeEscalation set to false", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    container := all_containers[_]
    not drops_all_capabilities(container)
    msg := sprintf("Container '%s' must drop 'ALL' capabilities", [container.name])
}

drops_all_capabilities(container) if {
    container.securityContext.capabilities.drop[_] == "ALL"
}
