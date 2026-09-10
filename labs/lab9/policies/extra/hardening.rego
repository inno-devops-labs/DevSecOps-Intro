package main

# Rule 1: runAsNonRoot must be true
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("Container %v must have runAsNonRoot=true", [container.name])
}

# Rule 2: allowPrivilegeEscalation must be false
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container %v must have allowPrivilegeEscalation=false", [container.name])
}

# Rule 3: capabilities.drop must include "ALL"
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container %v must drop ALL capabilities", [container.name])
}

# Rule 4: resources.limits.memory must be set
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not container.resources.limits.memory
    msg := sprintf("Container %v must have memory limits set", [container.name])
}

# Rule 5: image must use sha256 digest
deny contains msg if {
    input.kind == "Pod"
    some container in input.spec.containers
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %v must use image with sha256 digest (not tag)", [container.name])
}
