package k8s.security

workload_containers contains c if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
}

workload_containers contains c if {
  input.kind == "Deployment"
  c := object.get(input.spec.template.spec, "initContainers", [])[_]
}

app_containers contains c if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
}

pod_security_context := object.get(input.spec.template.spec, "securityContext", {})

# No :latest tags
deny contains msg if {
  c := workload_containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("container %q uses disallowed :latest tag", [c.name])
}

# Require essential securityContext settings
deny contains msg if {
  c := workload_containers[_]
  container_sc := object.get(c, "securityContext", {})
  not object.get(container_sc, "runAsNonRoot", object.get(pod_security_context, "runAsNonRoot", false))
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %q must set readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  drop_caps := object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "drop", [])
  not "ALL" in drop_caps
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  add_caps := object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])
  count(add_caps) > 0
  msg := sprintf("container %q must not add capabilities", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run privileged", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  container_sc := object.get(c, "securityContext", {})
  container_seccomp := object.get(object.get(container_sc, "seccompProfile", {}), "type", "")
  pod_seccomp := object.get(object.get(pod_security_context, "seccompProfile", {}), "type", "")
  not container_seccomp == "RuntimeDefault"
  not container_seccomp == "Localhost"
  not pod_seccomp == "RuntimeDefault"
  not pod_seccomp == "Localhost"
  msg := sprintf("container %q must set seccompProfile.type to RuntimeDefault or Localhost", [c.name])
}

# Require CPU/Memory requests and limits
deny contains msg if {
  c := workload_containers[_]
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}

deny contains msg if {
  c := workload_containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# Recommend probes
warn contains msg if {
  c := app_containers[_]
  not c.readinessProbe
  msg := sprintf("container %q should define readinessProbe", [c.name])
}

warn contains msg if {
  c := app_containers[_]
  not c.livenessProbe
  msg := sprintf("container %q should define livenessProbe", [c.name])
}
