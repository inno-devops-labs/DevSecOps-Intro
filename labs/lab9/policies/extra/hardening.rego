package main

pod_runs_as_non_root if {
  input.spec.template.spec.securityContext.runAsNonRoot == true
}

container_runs_as_non_root(container) if {
  container.securityContext.runAsNonRoot == true
}

drops_all_capabilities(container) if {
  security_context := object.get(container, "securityContext", {})
  capabilities := object.get(security_context, "capabilities", {})
  dropped := object.get(capabilities, "drop", [])

  "ALL" in dropped
}

# 1. Require runAsNonRoot at pod or container level.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not pod_runs_as_non_root
  not container_runs_as_non_root(container)

  msg := sprintf(
    "container %q must set runAsNonRoot: true at pod or container level",
    [container.name],
  )
}

# 2. Prevent processes from gaining additional privileges.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.securityContext.allowPrivilegeEscalation == false

  msg := sprintf(
    "container %q must set allowPrivilegeEscalation: false",
    [container.name],
  )
}

# 3. Require all Linux capabilities to be dropped.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not drops_all_capabilities(container)

  msg := sprintf(
    "container %q must drop ALL capabilities",
    [container.name],
  )
}

# 4. Require a memory limit for every container.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.resources.limits.memory

  msg := sprintf(
    "container %q must set resources.limits.memory",
    [container.name],
  )
}

# 5. Require immutable images pinned by SHA-256 digest.
deny contains msg if {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not contains(container.image, "@sha256:")

  msg := sprintf(
    "container %q image must be pinned with an @sha256 digest",
    [container.name],
  )
}
