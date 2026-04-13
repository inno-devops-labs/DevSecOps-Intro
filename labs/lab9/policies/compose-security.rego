package compose.security

containers := input.services

# Helper: true if array arr contains value v.
has_value(arr, v) if {
  some item in arr
  item == v
}

# Helper: true if a service declares a non-root user.
explicit_non_root_user(user) if {
  is_number(user)
  user != 0
}

explicit_non_root_user(user) if {
  is_string(user)
  user != ""
  principal := lower(split(user, ":")[0])
  principal != "0"
  principal != "root"
}

deny contains msg if {
  some name
  svc := containers[name]
  not svc.user
  msg := sprintf("service %q must set an explicit non-root user", [name])
}

deny contains msg if {
  some name
  svc := containers[name]
  svc.user
  not explicit_non_root_user(svc.user)
  msg := sprintf("service %q must set an explicit non-root user", [name])
}

deny contains msg if {
  some name
  svc := containers[name]
  not svc.read_only
  msg := sprintf("service %q must set read_only: true", [name])
}

deny contains msg if {
  some name
  svc := containers[name]
  not has_value(object.get(svc, "cap_drop", []), "ALL")
  msg := sprintf("service %q must drop ALL capabilities", [name])
}

deny contains msg if {
  some name
  svc := containers[name]
  count(object.get(svc, "cap_add", [])) > 0
  msg := sprintf("service %q must not add capabilities", [name])
}

deny contains msg if {
  some name
  svc := containers[name]
  svc.privileged == true
  msg := sprintf("service %q must not run privileged", [name])
}

warn contains msg if {
  some name
  svc := containers[name]
  not has_value(object.get(svc, "security_opt", []), "no-new-privileges:true")
  msg := sprintf("service %q should enable no-new-privileges", [name])
}
