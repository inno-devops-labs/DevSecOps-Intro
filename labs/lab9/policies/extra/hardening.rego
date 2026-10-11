package main

containers(obj) = all {
    obj.spec.containers
    init := object.get(obj.spec, "initContainers", [])
    all := array.concat(obj.spec.containers, init)
}

containers(obj) = all {
    not obj.spec.containers
    obj.spec.template.spec.containers
    init := object.get(obj.spec.template.spec, "initContainers", [])
    all := array.concat(obj.spec.template.spec.containers, init)
}

deny[msg] {
    some container in containers(input)
    container_run_as_non_root := object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null)
    container_run_as_non_root == false
    msg := sprintf("Container %q has runAsNonRoot set to false", [container.name])
}

deny[msg] {
    some container in containers(input)
    pod_run_as_non_root := object.get(object.get(input.spec, "securityContext", {}), "runAsNonRoot", null)
    container_run_as_non_root := object.get(object.get(container, "securityContext", {}), "runAsNonRoot", null)
    container_run_as_non_root != true
    pod_run_as_non_root != true
    msg := sprintf("Container %q must have runAsNonRoot true (either container-level or pod-level)", [container.name])
}

deny[msg] {
    some container in containers(input)
    allow_priv_esc := object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", null)
    allow_priv_esc != false
    msg := sprintf("Container %q must have allowPrivilegeEscalation set to false", [container.name])
}

deny[msg] {
    some container in containers(input)
    drop := object.get(object.get(container, "securityContext", {}), "capabilities", {}).drop
    not "ALL" in drop
    msg := sprintf("Container %q must drop all capabilities (capabilities.drop must include ALL)", [container.name])
}

deny[msg] {
    some container in containers(input)
    limits := object.get(container, "resources", {}).limits
    not limits.memory
    msg := sprintf("Container %q must have resources.limits.memory set", [container.name])
}

deny[msg] {
    some container in containers(input)
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %q must use image with sha256 digest (e.g., @sha256:...), not a tag", [container.name])
}
