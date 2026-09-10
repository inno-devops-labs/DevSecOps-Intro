# labs/lab9/policies/extra/hardening.rego
#
# Conftest policies for Lab 9 — Task 2.
# Works for BOTH `kind: Pod` (lab's good-pod/bad-pod manifests) and
# `kind: Deployment` (e.g. juice-hardened.yaml / juice-unhardened.yaml).
#
# Default Conftest namespace is `main`, so `conftest test --policy <dir>`
# picks these up without any --namespace flag.

package main

import rego.v1

# ---------------------------------------------------------------------------
# Collect the container list from either a Pod or a Deployment
# ---------------------------------------------------------------------------
workload_containers contains c if {
  input.kind == "Pod"
  some c in input.spec.containers
}

workload_containers contains c if {
  input.kind == "Deployment"
  some c in input.spec.template.spec.containers
}

# Pod-level securityContext (differs between Pod and Deployment)
pod_security_context := input.spec.securityContext if {
  input.kind == "Pod"
}

pod_security_context := input.spec.template.spec.securityContext if {
  input.kind == "Deployment"
}

# ---------------------------------------------------------------------------
# Rule 1 — runAsNonRoot must be true (pod-level OR container-level)
# ---------------------------------------------------------------------------
deny contains msg if {
  some c in workload_containers
  not pod_security_context.runAsNonRoot == true
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true (pod- or container-level securityContext)", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 2 — allowPrivilegeEscalation must be false (every container)
# ---------------------------------------------------------------------------
deny contains msg if {
  some c in workload_containers
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 3 — capabilities.drop must include "ALL" (every container)
# ---------------------------------------------------------------------------
deny contains msg if {
  some c in workload_containers
  drop := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in drop
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 4 — resources.limits.memory must be set (every container)
# ---------------------------------------------------------------------------
deny contains msg if {
  some c in workload_containers
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 5 — reject the mutable :latest tag
# ---------------------------------------------------------------------------
deny contains msg if {
  some c in workload_containers
  endswith(c.image, ":latest")
  msg := sprintf("container %q must not use the mutable :latest tag", [c.name])
}

# ---------------------------------------------------------------------------
# Rule 5b (warn, not deny) — prefer pinning image by @sha256: digest.
# `warn` does NOT fail the build, so a good manifest still passes with 0
# failures; it just nudges toward full immutability (defense in depth).
# ---------------------------------------------------------------------------
warn contains msg if {
  some c in workload_containers
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q should pin its image by @sha256: digest for immutability", [c.name])
}
