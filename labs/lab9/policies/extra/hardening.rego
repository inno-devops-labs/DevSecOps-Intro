package k8s.extra

# Image must be pinned by digest, not only a mutable tag.
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not regex.match(`^.+@sha256:[a-fA-F0-9]{64}$`, object.get(c, "image", ""))
  msg := sprintf("container %q must pin its image with a SHA-256 digest", [c.name])
}

# Explicitly slow liveness probes (period > 30s) are a smell; default/omitted period is fine.
warn contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  period := object.get(c.livenessProbe, "periodSeconds", 10)
  period > 30
  msg := sprintf("container %q livenessProbe.periodSeconds is %v; use at most 30", [c.name, period])
}
