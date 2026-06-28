package main
import rego.v1

# 1. spec.securityContext.runAsNonRoot != true
deny contains msg if {
    input.kind == "Deployment"
    pod_spec := input.spec.template.spec
    not pod_spec.securityContext.runAsNonRoot == true
    msg := "Pod securityContext must have runAsNonRoot set to true"
}

# 2. (any container) spec.containers[_].securityContext.readOnlyRootFilesystem != true
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%v' must have readOnlyRootFilesystem set to true", [container.name])
}

# 3. (any container) spec.containers[_].securityContext.allowPrivilegeEscalation != false
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%v' must have allowPrivilegeEscalation set to false", [container.name])
}

# 4. (any container) spec.containers[_].securityContext.capabilities.drop missing "ALL"
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not has_drop_all(container)
    msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

has_drop_all(container) if {
    "ALL" in container.securityContext.capabilities.drop
}
