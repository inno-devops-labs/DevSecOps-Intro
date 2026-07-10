# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "time": "2026-07-10T17:30:58.007532108Z",
  "output": "A shell was spawned in a container with an attached terminal | user=root container_name=lab9-target command=sh -lc echo \"shell-in-container test\"",
  "tags": ["T1059", "container", "mitre_execution", "shell"]
}
```

### Baseline alert B — Container drift (write below binary dir)
```json
{
  "rule": "Reconnaissance in container",
  "priority": "Warning",
  "time": "2026-07-10T17:50:44.850688500Z",
  "output": "Reconnaissance detected (user=root cmd=whoami container=lab9-target)",
  "tags": ["container", "recon", "custom"]
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to tmp by container
  desc: Detect writes to /tmp via shell redirect in a container
  condition: >
    evt.type = execve 
    and container 
    and proc.cmdline contains "> /tmp/"
  output: "Write to /tmp detected (user=%user.name cmd=%proc.cmdline container=%container.name)"
  priority: WARNING
  tags: [container, drift, custom]

- rule: Reconnaissance in container
  desc: Detect whoami/id commands in a container
  condition: >
    evt.type = execve 
    and container 
    and proc.cmdline contains "whoami"
  output: "Reconnaissance detected (user=%user.name cmd=%proc.cmdline container=%container.name)"
  priority: WARNING
  tags: [container, recon, custom]
```

### Custom rule fired
Falco log line showing your custom rule:
```json
{
  "rule": "Write to tmp by container",
  "priority": "Warning",
  "time": "2026-07-10T17:34:47.364716371Z",
  "output": "Write to /tmp detected (user=root cmd=sh -lc echo \"HELLO_FALCO_TEST\" > /tmp/test.txt container=lab9-target)",
  "tags": ["container", "drift", "custom"]
}

{
  "rule": "Reconnaissance in container",
  "priority": "Warning",
  "time": "2026-07-10T17:50:44.850688500Z",
  "output": "Reconnaissance detected (user=root cmd=whoami container=lab9-target)",
  "tags": ["container", "recon", "custom"]
}
```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks
often write to /tmp). What's your tuning approach? (2-3 sentences referencing the
`exceptions:` block vs `and not proc.name=...` patterns from Lecture 9.)

My rule triggers on any write operation in `/tmp`, including the creation of standard application temporary files. To reduce the number of false positives, I would add an `exceptions:` block listing known safe processes or use an `and not proc.name=...` condition. Using exceptions is preferable to hardcoding conditions directly into the rule, as they are easier to update without altering the rule's core logic.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("container %q uses disallowed :latest tag", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}
```

### Good manifest passes
```
12 tests, 12 passed, 0 warnings, 0 failures, 0 exceptions
```

### Bad manifest 1 fails (runAsRoot)
```
FAIL - container "juice" uses disallowed :latest tag
FAIL - container "juice" must set runAsNonRoot: true
FAIL - container "juice" must set allowPrivilegeEscalation: false
FAIL - container "juice" must drop ALL capabilities
FAIL - container "juice" missing resources.requests.cpu
FAIL - container "juice" missing resources.limits.memory

6 tests, 0 passed, 0 warnings, 6 failures, 0 exceptions
```

### Bad manifest 2 fails (no resources)
```
FAIL - container "app" missing resources.requests.cpu
FAIL - container "app" missing resources.limits.memory

6 tests, 4 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
2-3 sentences. CI-time Conftest happens during PR review; admission-time Conftest happens at
`kubectl apply`. What's the operational benefit of running BOTH (defense in depth)?

CI-time catches errors during merge request reviews, 
while admission-time catches issues that slip through or 
manual changes made via kubectl. Together, they block errors 
at both the merge and deployment stages-providing multi-layered protection.