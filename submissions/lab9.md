# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{
    "hostname": "99a4ab80d37e",
    "output": "2026-07-09T15:26:51.637191649+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=4916809936bf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"]
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
    "hostname": "99a4ab80d37e",
    "output": "2026-07-09T15:27:01.823254295+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=4916809936bf container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"]
}
```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside a container
  condition: open_write and container and fd.name startswith /tmp/
  output: "Write to /tmp by container (user=%user.name container=%container.name file=%fd.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detects known miner processes or nc connecting to mining pool ports
  condition: >
    (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
    or (proc.name = nc and proc.cmdline icontains "3333")
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired
```json
{
    "hostname": "99a4ab80d37e",
    "output": "2026-07-09T15:28:39.940723356+0000: Warning Write to /tmp by container (user=root container=lab9-target file=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt)",
    "priority": "Warning",
    "rule": "Write to /tmp by container",
    "source": "syscall",
    "tags": ["container", "drift"]
}
```

### Tuning consideration (Lecture 9 slide 8)
The "write to /tmp" rule will fire on legitimate framework logging too. The cleanest approach is an `exceptions:` block that lists known-safe processes (e.g., a specific Java/Python logger) by `proc.name` — this keeps the condition readable and avoids `and not proc.name=...` chains. The `exceptions:` pattern is better because it scales: you can add more exception tuples without rewriting the condition, and the rule stays self-documenting.

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
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
  not "ALL" in c.securityContext.capabilities.drop
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true

8 tests, 5 passed, 0 warnings, 3 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
$ conftest test juice-compose.yml --policy compose-security.rego --namespace compose.security
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml --policy compose-security.rego --namespace compose.security
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches issues during PR review, before anything reaches the cluster — fast feedback, no cluster needed. Admission-time catches drift or bypasses (e.g., someone `kubectl apply` outside CI). Running both gives defense in depth: CI blocks the obvious mistakes early, admission catches the rest at deploy time.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
- rule: Possible Cryptominer Activity
  desc: Detects known miner processes or nc connecting to mining pool ports
  condition: >
    (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
    or (proc.name = nc and proc.cmdline icontains "3333")
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
    "hostname": "99a4ab80d37e",
    "output": "2026-07-09T15:37:45.264084429+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc cmdline=nc -w 2 127.0.0.1 3333)",
    "priority": "Critical",
    "rule": "Possible Cryptominer Activity",
    "source": "syscall",
    "tags": ["container", "mitre_command_and_control", "mitre_execution"]
}
```

### Reflection (2-3 sentences)
I used 2 indicators: process name matching known miners (xmrig, ethminer, etc.) and `nc` connecting to port 3333 (common mining pool port). This misses obfuscated mining over HTTPS on port 443, since the traffic would look like normal web traffic and the binary would have a different name. To integrate with the SLA matrix, set a shorter response SLA for CRITICAL runtime alerts (e.g., 15 min) vs WARNING-level configuration drift (e.g., 4 hours).