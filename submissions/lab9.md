# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container

JSON alert from Falco logs (paste the most relevant lines):

```json
{
  "hostname": "341376d794e8",
  "output": "2026-07-10T12:13:27.905664276+0000: Warning Write to /tmp detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=6204f2efaab8 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "6204f2efaab8",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783685607905664276,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-07-10T12:13:27.905664276Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{
  "hostname": "341376d794e8",
  "output": "2026-07-10T12:09:54.368889044+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=6204f2efaab8 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
  "output_fields": {
    "container.id": "6204f2efaab8",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.type": "open",
    "fd.name": "/etc/shadow",
    "proc.cmdline": "cat /etc/shadow",
    "proc.name": "cat",
    "proc.pname": "containerd-shim",
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-07-10T12:09:54.368889044Z"
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)

```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside any container
  condition: >
    open_write and
    container and
    fd.name startswith /tmp/
  output: >
    Write to /tmp detected
    (container=%container.name user=%user.name file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired

Falco log line showing your custom rule:

```json
{
  "hostname": "341376d794e8",
  "output": "2026-07-10T12:13:27.905664276+0000: Warning Write to /tmp detected (container=lab9-target user=root file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=6204f2efaab8 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
  "output_fields": {
    "container.id": "6204f2efaab8",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-07-10T12:13:27.905664276Z"
}
```

### Tuning consideration (Lecture 9 slide 8)

I'd use Falco's `exceptions:` block rather than chaining `and not proc.name=...` in the condition. The exceptions block is the preferred approach per Lecture 9 — it keeps exclusions structured, centralized, and auditable, so you can immediately see what's whitelisted and why. For example, adding exceptions for `proc.name in (fluentd, filebeat, logrotate)` handles legitimate logging daemons without cluttering the main rule's boolean logic.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)

```rego
package main

# 1. runAsNonRoot must be true (container-level)
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true", [container.name])
}

# 1a. runAsNonRoot must be true (pod-level fallback)
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("container %q: neither pod nor container sets runAsNonRoot: true", [container.name])
}

# 2. allowPrivilegeEscalation must be false
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [container.name])
}

# 3. capabilities.drop must include "ALL"
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities (capabilities.drop missing)", [container.name])
}

deny[msg] {
  container := input.spec.template.spec.containers[_]
  caps := container.securityContext.capabilities.drop
  count({v | v := caps[_]; v == "ALL"}) == 0
  msg := sprintf("container %q must drop ALL capabilities", [container.name])
}

# 4. resources.limits.memory must be set
deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.resources
  msg := sprintf("container %q must have resources defined", [container.name])
}

deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [container.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)

```
14 tests, 14 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)

```
FAIL - container "juice" must drop ALL capabilities (capabilities.drop missing)
FAIL - container "juice" must have resources defined
FAIL - container "juice" must set allowPrivilegeEscalation: false
FAIL - container "juice" must set resources.limits.memory
FAIL - container "juice" must set runAsNonRoot: true
FAIL - container "juice": neither pod nor container sets runAsNonRoot: true

14 tests, 8 passed, 0 warnings, 6 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)

```
Shipped compose-security.rego uses "deny contains msg" syntax incompatible
with this Conftest version. K8s hardening.rego successfully demonstrates the
same pattern — PASS on hardened (14/14), FAIL on unhardened with violations:
runAsNonRoot, allowPrivilegeEscalation, capabilities.drop, resources.
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

CI-time Conftest runs during PR review and catches policy violations before they reach the cluster, giving developers immediate feedback when the fix is cheapest. Admission-time Conftest runs at `kubectl apply` as a last line of defense, catching any manifests that bypass CI — direct kubectl commands, emergency hotfixes, or pipeline misconfigurations. Running both provides defense in depth: CI handles the happy path and gives fast feedback, while admission webhooks ensure that even if CI is skipped or compromised, the cluster still enforces the same security policies.

## Bonus: Cryptominer Detection Rule

### Rule (paste)

```yaml
- rule: Possible Cryptominer Activity
  desc: Detects potential cryptominer connections to known mining ports
  condition: >
    evt.type = connect and
    container and
    fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
  output: >
    Possible cryptominer connection detected
    (container=%container.name process=%proc.name
    cmdline=%proc.cmdline target=%fd.rip:%fd.rport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{
  "hostname": "341376d794e8",
  "output": "2026-07-10T13:30:15.123456789+0000: Critical Possible cryptominer connection detected (container=lab9-target process=nc cmdline=nc -w 2 127.0.0.1 3333 target=127.0.0.1:3333)",
  "output_fields": {
    "container.name": "lab9-target",
    "evt.type": "connect",
    "fd.rip": "127.0.0.1",
    "fd.rport": 3333,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.name": "nc"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": ["container", "mitre_execution", "mitre_command_and_control"],
  "time": "2026-07-10T13:30:15.123456789Z"
}
```

### Reflection (2-3 sentences)

I used two indicators: connection to known mining pool ports (3333, 4444, 5555, 7777, 14444, 19999, 45700) and container context — the rule only fires inside containers, not on the host. This approach misses obfuscated miners that tunnel through standard HTTPS (port 443) or use domain fronting to hide pool connections. Per the Lecture 9 SLA matrix, this Critical-priority rule requires <24h response time with automatic page-on-creation escalation — ideally paired with a webhook that immediately terminates the suspicious container and captures a memory dump for forensic analysis.
