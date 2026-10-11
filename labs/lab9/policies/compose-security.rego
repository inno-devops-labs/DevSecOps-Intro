package compose.security

containers := input.services

# Helper: true if array arr contains value v
has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  svc := containers[_]
  not svc.user
  msg := "services must set an explicit non-root user"
}

deny contains msg if {
  svc := containers[_]
  not svc.read_only
  msg := "services must set read_only: true"
}

deny contains msg if {
  svc := containers[_]
  not has_value(object.get(svc, "cap_drop", []), "ALL")
  msg := "services must drop ALL capabilities"
}

warn contains msg if {
  svc := containers[_]
  not has_value(svc.security_opt, "no-new-privileges:true")
  msg := "services should enable no-new-privileges"
}
