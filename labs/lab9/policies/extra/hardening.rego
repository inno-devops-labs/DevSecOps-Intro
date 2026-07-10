package k8s.security

# --- NEW RULE 1: readinessProbe is required (deny, not just warn) ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.readinessProbe
	msg := sprintf("container %q must define a readinessProbe", [c.name])
}

# --- NEW RULE 2: livenessProbe is required (deny, not just warn) ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.livenessProbe
	msg := sprintf("container %q must define a livenessProbe", [c.name])
}

# --- NEW RULE 3: container must not add back any capabilities ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	count(object.get(c, ["securityContext", "capabilities", "add"], [])) > 0
	msg := sprintf("container %q must not add any Linux capabilities", [c.name])
}

# --- NEW RULE 4: container securityContext must exist ---
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext
	msg := sprintf("container %q must define a securityContext", [c.name])
}
