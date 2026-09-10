package extra.hardening

# Require image digest pin (@sha256:)
deny contains msg if {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not contains(container.image, "@sha256:")
  msg := sprintf("container %q must pin image by digest (@sha256:)", [container.name])
}

# Warn when automountServiceAccountToken is not explicitly false
warn contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
  some i
  container := input.spec.template.spec.containers[i]
  msg := sprintf("pod for container %q should set automountServiceAccountToken: false", [container.name])
}
