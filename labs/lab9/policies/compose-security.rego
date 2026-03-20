package main

# Deny privileged compose services
deny contains msg if {
  input.services[name].privileged == true
  msg := sprintf("DENY: Compose service '%v' must not run as privileged", [name])
}

# Warn if running as root user
warn contains msg if {
  input.services[name].user == "0"
  msg := sprintf("WARN: Compose service '%v' is running as root (user: 0)", [name])
}
