package k8s.extra

# Images must be immutable so a mutable tag cannot change after review.
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest", [c.name])
}

# Explicitly enabling the service-account token automount is unnecessary for Juice Shop.
warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.automountServiceAccountToken == true
  c := input.spec.template.spec.containers[_]
  msg := sprintf("container %q should disable automountServiceAccountToken", [c.name])
}
