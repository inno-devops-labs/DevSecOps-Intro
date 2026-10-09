package k8s.security

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not contains(container.image, "@sha256:")
    msg := sprintf("Container %q image must be pinned by digest (@sha256:), not a mutable tag", [c.name])
}
warn contains msg if {
    input.kind == "Deployment"
    not input.spec.template.spec.automountServiceAccountToken == false
    msg := "Deployment should set automountServiceAccountToken: false to prevent unneeded API access"
}