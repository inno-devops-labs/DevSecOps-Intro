package k8s.hardening

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

all_containers contains c if {
  workload_kinds[input.kind]
  c := input.spec.template.spec.containers[_]
}

all_containers contains c if {
  workload_kinds[input.kind]
  c := input.spec.template.spec.initContainers[_]
}

deny contains msg if {
  c := all_containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest (image@sha256:...), got %q", [c.name, c.image])
}

warn contains msg if {
  c := all_containers[_]
  added := object.get(c, ["securityContext", "capabilities", "add"], [])
  count(added) > 0
  msg := sprintf("container %q adds Linux capabilities %v; justify each or remove them", [c.name, added])
}
