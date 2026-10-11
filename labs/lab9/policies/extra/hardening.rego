package main

pod_enforces_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

container_enforces_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

removes_all_capabilities(container) if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped_capabilities := object.get(capabilities, "drop", [])

  "ALL" in dropped_capabilities
}

# 1. Ensure non-root execution is configured at either the pod or container level.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not pod_enforces_non_root
  not container_enforces_non_root(container)

  msg := sprintf(
    "container %q must enable runAsNonRoot at the pod or container level",
    [container.name],
  )
}

# 2. Disallow processes from acquiring extra privileges.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.securityContext.allowPrivilegeEscalation == false

  msg := sprintf(
    "container %q must disable privilege escalation",
    [container.name],
  )
}

# 3. Ensure every Linux capability is removed.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not removes_all_capabilities(container)

  msg := sprintf(
    "container %q must remove all Linux capabilities",
    [container.name],
  )
}

# 4. Ensure a memory limit is defined for each container.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.resources.limits.memory

  msg := sprintf(
    "container %q must define a memory resource limit",
    [container.name],
  )
}

# 5. Ensure container images are locked to an immutable SHA-256 digest.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not contains(container.image, "@sha256:")

  msg := sprintf(
    "container %q must reference an image pinned to an @sha256 digest",
    [container.name],
  )
}
