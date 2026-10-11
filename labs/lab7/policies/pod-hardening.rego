package main

import future.keywords.if

# Helper function to check if a container drops all capabilities
has_drop_all(container) if {
    some cap in container.securityContext.capabilities.drop
    cap == "ALL"
}
deny contains msg if{
    input.kind == "Deployment"
    spec := input.spec.template.spec
    not spec.securityContext

    msg := "Pod-level securityContext is missing (runAsNonRoot required)"
}
# Deny if runAsNonRoot is not true at pod level
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    spec.securityContext
    not spec.securityContext.runAsNonRoot == true
    msg := sprintf("Pod-level securityContext.runAsNonRoot is not true; got %v", [spec.securityContext.runAsNonRoot])
}

# Deny if ANY container has readOnlyRootFilesystem != true
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    some container in spec.containers
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' is missing readOnlyRootFilesystem: true", [container.name])
}

# Deny if ANY container has allowPrivilegeEscalation != false
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    some container in spec.containers
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' has allowPrivilegeEscalation != false", [container.name])
}

# Deny if ANY container is missing "ALL" in capabilities.drop
deny contains msg if {
    input.kind == "Deployment"
    spec := input.spec.template.spec
    some container in spec.containers
    not has_drop_all(container)
    msg := sprintf("Container '%s' is missing 'ALL' in capabilities.drop", [container.name])
}