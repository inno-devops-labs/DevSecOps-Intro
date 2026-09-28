package k8s.security

# deny: image must be pinned by digest (@sha256:...), not just a tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...), not a mutable tag", [c.name])
}

# warn: automountServiceAccountToken should be explicitly disabled
warn contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
  msg := "Deployment should set automountServiceAccountToken: false to prevent unneeded API access"
}
