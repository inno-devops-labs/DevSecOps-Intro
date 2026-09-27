package k8s.extra

# A version tag alone does not make an image reference immutable.
deny contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    not regex.match(`^.+@sha256:[a-fA-F0-9]{64}$`, object.get(c, "image", ""))
    msg := sprintf("container %q must pin its image with a SHA-256 digest", [c.name])
}

# Missing probes are already covered by k8s.security. Kubernetes defaults an
# omitted periodSeconds to 10; this check flags explicitly slow liveness checks.
warn contains msg if {
    input.kind == "Deployment"
    c := input.spec.template.spec.containers[_]
    period := object.get(c.livenessProbe, "periodSeconds", 10)
    period > 30
    msg := sprintf("container %q livenessProbe.periodSeconds is %v; use at most 30", [c.name, period])
}
