package k8s.security

# 1. runAsNonRoot must be true
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container %s must have runAsNonRoot set to true", [container.name])
}

# 2. allowPrivilegeEscalation must be false
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %s must have allowPrivilegeEscalation set to false", [container.name])
}

# 3. capabilities.drop must include "ALL"
deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not has_all_capabilities_dropped(container)
    msg := sprintf("Container %s must drop ALL capabilities", [container.name])
}

has_all_capabilities_dropped(container) if {
    "ALL" in container.securityContext.capabilities.drop
}
