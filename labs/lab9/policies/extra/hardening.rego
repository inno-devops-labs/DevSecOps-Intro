package main

run_as_non_root(container) if {
    container.securityContext.runAsNonRoot == true
}

run_as_non_root(container) if {
    input.spec.template.spec.securityContext.runAsNonRoot == true
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not run_as_non_root(c)
    msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not "ALL" in c.securityContext.capabilities.drop
    msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("container %q missing resources.limits.memory", [c.name])
}
