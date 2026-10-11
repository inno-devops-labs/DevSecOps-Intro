# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container

JSON alert from Falco logs (paste the most relevant lines):

```json
{
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "time": "2026-07-10T10:42:28.417234184Z",
  "output": "A shell was spawned in a container with an attached terminal | process=sh command=sh -lc echo \"shell-in-container test\" container_name=lab9-target",
  "output_fields": {
    "container.name": "lab9-target",
    "proc.name": "sh",
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
    "user.name": "root"
  }
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "time": "2026-07-10T10:42:34.951578155Z",
  "output": "Sensitive file opened for reading by non-trusted program | file=/etc/shadow process=cat command=cat /etc/shadow container_name=lab9-target",
  "output_fields": {
    "container.name": "lab9-target",
    "fd.name": "/etc/shadow",
    "proc.name": "cat",
    "proc.cmdline": "cat /etc/shadow",
    "user.name": "root"
  }
}
```

### Custom rule (paste `labs/lab9/falco/rules/custom-rules.yaml`)

```yaml
- rule: Write to /tmp by container
  desc: Detect writes to /tmp inside any container
  condition: >
    open_write and
    container and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired

```json
{
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "time": "2026-07-10T10:44:17.633087311Z",
  "output": "Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt cmd=sh -lc echo \"test\" > /tmp/my-write.txt)",
  "output_fields": {
    "container.name": "lab9-target",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  }
}
```

### Tuning consideration (Lecture 9 slide 8)

This rule can generate false positives because many legitimate applications create temporary files under `/tmp`. In a production environment, I would use the `exceptions:` block to exclude known trusted processes or containers instead of disabling the rule entirely. For simple cases, `and not proc.name in (...)` can also be used to filter expected behavior while still detecting suspicious file writes.


## Task 2: Conftest Policy-as-Code

### My policy file (paste `labs/lab9/policies/extra/hardening.rego`)

```rego
package main

import rego.v1

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %q must set runAsNonRoot=true", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %q must set allowPrivilegeEscalation=false", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container %q must drop ALL capabilities", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container %q must define memory limits", [container.name])
}

deny contains msg if {
    container := input.spec.template.spec.containers[_]
    contains(container.image, ":latest")
    msg := sprintf("Container %q must not use the latest tag", [container.name])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)

```text
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must define memory limits
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must not use the latest tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must set allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container "juice" must set runAsNonRoot=true

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`)

```text
# Compliant compose file

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# Non-compliant compose file

FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

Running Conftest during CI helps catch security issues before code is merged, allowing developers to fix problems early during the pull request review. Admission-time policy enforcement validates manifests again when they are applied to the cluster, preventing insecure deployments even if they bypass the CI pipeline. Using both stages provides defense in depth by enforcing security before merge and before deployment.
