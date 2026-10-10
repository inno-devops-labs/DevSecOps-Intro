package k8s.security

# Extra checks that join the shipped k8s.security package, so they run with
# either --all-namespaces or --namespace k8s.security.
#
# Differences from the shipped rules, on purpose:
#   - every pod-bearing kind is covered, not only Deployment
#   - initContainers are walked as well as containers
#   - missing keys go through object.get with a default. The shipped
#     `not has_value(c.securityContext.capabilities.drop, "ALL")` never fires
#     when the key is absent: OPA evaluates the undefined argument before the
#     `not`, and the whole rule body fails.

template_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in template_kinds

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

workload_containers contains c if {
  some c in object.get(pod_spec, "containers", [])
}

workload_containers contains c if {
  some c in object.get(pod_spec, "initContainers", [])
}

pinned_by_digest(image) if regex.match(`@sha256:[a-f0-9]{64}$`, image)

# Images must be pinned by digest. A tag is a mutable pointer (Lab 8): the
# shipped check only rejects a literal ":latest" suffix, so "nginx" (implicit
# latest) and any re-pushed version tag pass it.
deny contains msg if {
  some c in workload_containers
  image := object.get(c, "image", "")
  not pinned_by_digest(image)
  msg := sprintf("container %q image %q is not pinned by digest (@sha256:...)", [c.name, image])
}

# drop: ["ALL"] satisfies the shipped capability check even when add: lists
# capabilities right next to it. Some adds are legitimate (NET_BIND_SERVICE
# for a non-root process on port 80), so this warns and names what was added.
warn contains msg if {
  some c in workload_containers
  added := object.get(c, ["securityContext", "capabilities", "add"], [])
  count(added) > 0
  msg := sprintf("container %q adds capabilities back after dropping: %v", [c.name, added])
}
