package main

import rego.v1

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

deny contains msg if {
  pod_spec
  not pod_spec.securityContext.runAsNonRoot == true
  msg := "Deployment must set spec.template.spec.securityContext.runAsNonRoot: true"
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("Container '%s' must set securityContext.readOnlyRootFilesystem: true", [container.name])
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Container '%s' must set securityContext.allowPrivilegeEscalation: false", [container.name])
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  caps := container.securityContext.capabilities.drop
  not "ALL" in caps
  msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny contains msg if {
  pod_spec
  container := pod_spec.containers[_]
  not container.securityContext.capabilities.drop
  msg := sprintf("Container '%s' must set capabilities.drop: [ALL]", [container.name])
}
