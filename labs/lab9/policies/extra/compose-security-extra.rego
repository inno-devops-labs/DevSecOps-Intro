package compose.security.extra

containers := input.services

deny contains msg if {
  svc_name := object.keys(containers)[_]
  svc := containers[svc_name]
  not svc.mem_limit
  msg := sprintf("service %q must set mem_limit", [svc_name])
}

deny contains msg if {
  svc_name := object.keys(containers)[_]
  svc := containers[svc_name]
  not svc.pids_limit
  msg := sprintf("service %q must set pids_limit", [svc_name])
}

deny contains msg if {
  svc_name := object.keys(containers)[_]
  svc := containers[svc_name]
  not contains(svc.image, "@sha256:")
  msg := sprintf("service %q image %q must be pinned by sha256 digest", [svc_name, svc.image])
}
