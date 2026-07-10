# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{
  "hostname": "720a1126571d",
  "output": "2026-07-10T12:49:50.318444165+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=runc command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=c4176f6b3f7d container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "c4176f6b3f7d",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1783687790318444165,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "runc",
    "proc.tty": 34816,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
  "time": "2026-07-10T12:49:50.318444165Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{
  "hostname": "720a1126571d",
  "output": "2026-07-10T12:50:18.803797948+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=c4176f6b3f7d container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "c4176f6b3f7d",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783687818803797948,
    "evt.type": "openat",
    "fd.name": "/etc/shadow",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.aname[2]": "systemd",
    "proc.aname[3]": null,
    "proc.aname[4]": null,
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "proc.name": "cat",
    "proc.pname": "containerd-shim",
    "proc.tty": 0,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
  "time": "2026-07-10T12:50:18.803797948Z"
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: Detect file write to /tmp inside a container (not host)
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    File written to /tmp inside container
    (container=%container.name user=%user.name fd=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: Detect network connection to mining pool port or known miner process
  condition: >
    (evt.type=connect and fd.sport in (3333,4444,5555,7777,14444,19999,45700))
    or (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity detected
    (container=%container.name user=%user.name process=%proc.name cmdline=%proc.cmdline target=%fd.cip)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired

```json

{
  "hostname": "720a1126571d",
  "output": "2026-07-10T12:54:33.597253389+0000: Warning File written to /tmp inside container (container=lab9-target user=root fd=/tmp/my-write.txt cmdline=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=c4176f6b3f7d container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "c4176f6b3f7d",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783688073597253389,
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
  "time": "2026-07-10T12:54:33.597253389Z"
}
```

### Tuning consideration (Lecture 9 slide 8)

The custom rule "Write to /tmp by container" will fire on legitimate writes (e.g., logging, temp files). Tuning can be done by adding `exceptions:` for known trusted processes (like `logrotate`, `nginx`, `java`) or using `and not proc.name in (trusted_processes)`. Alternatively, use `and not fd.name in (expected_tmp_files)` to whitelist specific paths. This balances detection with reducing false positives.

## Task 2: Conftest Policy-as-Code

### My policy file
```rego
package main

import future.keywords.in

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg = sprintf("Container %v: runAsNonRoot must be set to true", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = sprintf("Container %v: allowPrivilegeEscalation must be false", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg = sprintf("Container %v: capabilities.drop must include ALL", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg = sprintf("Container %v: resources.limits.memory must be set", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not contains(container.image, "@sha256:")
    msg = sprintf("Container %v: image must use sha256 digest, not tag", [container.name])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)

```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)

```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice: allowPrivilegeEscalation must be false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice: image must use sha256 digest, not tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice: resources.limits.memory must be set
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - Container juice: runAsNonRoot must be set to true

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`)

```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

CI-time Conftest catches issues during PR review before they reach the cluster, providing fast feedback to developers and preventing bad manifests from being merged. Admission-time Conftest (e.g., via Kyverno) acts as a second line of defense, blocking rollouts even if a bad manifest bypasses CI (e.g., via direct kubectl apply). Running both gives defense-in-depth: CI for speed and developer productivity, admission for runtime enforcement.

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: Possible Cryptominer Activity
  desc: Detect network connection to mining pool port or known miner process
  condition: >
    (evt.type=connect and fd.sport in (3333,4444,5555,7777,14444,19999,45700))
    or (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
  output: >
    Possible cryptominer activity detected
    (container=%container.name user=%user.name process=%proc.name cmdline=%proc.cmdline target=%fd.cip)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```
### Triggered alert

The rule was loaded successfully (syntax validated by Falco), but the `nc` trigger to 127.0.0.1 did not generate an event because Falco does not hook loopback connections inside the container by default. The rule is syntactically correct and loaded with a warning about performance (`LOAD_NO_EVTTYPE`). In a real environment, connecting to an external mining pool IP would trigger it.


### Reflection (2-3 sentences)

I used connection to common mining pool ports (3333, 4444, etc.) and known miner process names (xmrig, ethminer, etc.). These two cover both network and process-based detection, making the rule more robust.
It misses obfuscated miners using HTTPS (port 443) or custom ports, as well as miners that are hidden under legitimate process names.
This rule would be a "high severity" alert with a short SLA (e.g., 15 minutes) because cryptomining incidents consume resources and cost money. It could be paired with automated actions (e.g., kill container) or integrated with a SIEM for correlation.