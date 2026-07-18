package k8s.security

import rego.v1

# 1. runAsNonRoot must be true
deny contains msg if {
  pod := input.spec.template.spec
  container := pod.containers[_]
  not has_run_as_non_root(pod, container)
  msg := sprintf("Container '%v' must set runAsNonRoot to true", [container.name])
}

has_run_as_non_root(pod, _) if pod.securityContext.runAsNonRoot == true
has_run_as_non_root(_, container) if container.securityContext.runAsNonRoot == true

# 2. allowPrivilegeEscalation must be false
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  not has_privilege_escalation_false(container)
  msg := sprintf("Container '%v' must set allowPrivilegeEscalation to false", [container.name])
}

has_privilege_escalation_false(container) if container.securityContext.allowPrivilegeEscalation == false

# 3. capabilities.drop must include "ALL"
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  not drops_all_capabilities(container)
  msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

drops_all_capabilities(container) if "ALL" in container.securityContext.capabilities.drop
