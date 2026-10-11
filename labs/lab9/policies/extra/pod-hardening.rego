package extra.pod

# Require namespace to be set (not default)
deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "default"
  msg := "Deployment must not be in the default namespace"
}

# Require automountServiceAccountToken to be false
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.automountServiceAccountToken == false
  msg := "Deployment must set automountServiceAccountToken: false"
}

# Require seccompProfile RuntimeDefault
deny contains msg if {
  input.kind == "Deployment"
  sc := input.spec.template.spec.securityContext
  not sc.seccompProfile.type == "RuntimeDefault"
  msg := "Pod must set seccompProfile.type: RuntimeDefault"
}

# Require a non-root runAsUser
deny contains msg if {
  input.kind == "Deployment"
  sc := input.spec.template.spec.securityContext
  sc.runAsUser == 0
  msg := "Pod must not run as root (runAsUser: 0)"
}
