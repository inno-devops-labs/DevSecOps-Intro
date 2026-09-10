package main

deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    not spec.securityContext.runAsNonRoot == true
    containers := spec.containers
    count([c | c := containers[_]; c.securityContext.runAsNonRoot == true]) != count(containers)
    msg := sprintf("runAsNonRoot must be true for pod or all containers in %s", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    c.securityContext.allowPrivilegeEscalation != false
    msg := sprintf("Container %s in %s must set allowPrivilegeEscalation: false", [c.name, input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    c.securityContext.capabilities.drop
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf("Container %s in %s must drop ALL capabilities", [c.name, input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("Container %s in %s must have memory limits set", [c.name, input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not contains(c.image, "@sha256:")
    msg := sprintf("Container %s in %s must use image with sha256 digest (not tag)", [c.name, input.metadata.name])
}