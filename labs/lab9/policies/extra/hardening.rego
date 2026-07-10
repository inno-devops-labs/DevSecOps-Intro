package main

# Supports both standalone Pods and Deployments.
pod_spec := input.spec if {
  input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
  input.kind == "Deployment"
}

has_value(arr, value) if {
  some i
  arr[i] == value
}

# 1. runAsNonRoot may be set either at Pod level or container level.
deny contains msg if {
  c := pod_spec.containers[_]
  not pod_spec.securityContext.runAsNonRoot == true
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true at pod or container level", [c.name])
}

# 2. Every container must block privilege escalation.
deny contains msg if {
  c := pod_spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. Every container must drop all Linux capabilities.
deny contains msg if {
  c := pod_spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. Every container must have a memory limit.
deny contains msg if {
  c := pod_spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}
