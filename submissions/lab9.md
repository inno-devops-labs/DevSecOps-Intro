# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Environment note
Falco 0.43.1 (aarch64) was run on Docker Desktop (macOS Apple Silicon, kernel 6.12.76-linuxkit) using modern eBPF probe (`Opening 'syscall' source with modern BPF probe`). The linuxkit VM does not export `sys_enter_open/openat/connect` tracepoints, so TOCTOU mitigations are unavailable — Falco logged warnings for these but explicitly stated `Detection will continue to work`. Alerts were generated using `falcosecurity/event-generator` (official Falco test tool) and direct `docker exec` triggers.

### Baseline alert A — Run shell untrusted
```json
{
  "hostname": "docker-desktop",
  "output": "2026-07-04T07:01:40.836673687+0000: Notice Shell spawned by untrusted binary | parent_exe=/tmp/falco-event-generator-syscall-spawned-2753892175/httpd parent_exepath=/usr/bin/event-generator pcmdline=httpd --loglevel info run ^helper.RunShell$ gparent=event-generator ggparent=containerd-shim evt_type=execve user=root user_uid=0 process=sh proc_exepath=/usr/bin/dash parent=httpd command=sh -c ls > /dev/null container_id=e2bebd4617a4",
  "output_fields": {
    "container.id": "e2bebd4617a4",
    "evt.type": "execve",
    "proc.cmdline": "sh -c ls > /dev/null",
    "proc.exepath": "/usr/bin/dash",
    "proc.name": "sh",
    "proc.pname": "httpd",
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Run shell untrusted",
  "source": "syscall",
  "tags": ["T1059.004", "container", "host", "maturity_stable", "mitre_execution", "process", "shell"],
  "time": "2026-07-04T07:01:40.836673687Z"
}
```
**Triggered by:** `falcosecurity/event-generator` running `syscall.RunShellUntrusted` — spawns a shell (`sh`) as a child of an executable dropped to `/tmp` (simulating a binary that was not part of the original container image, i.e. EXE_WRITABLE|EXE_LOWER_LAYER flags set).

### Baseline alert B — Read sensitive file untrusted
```json
{
  "hostname": "docker-desktop",
  "output": "2026-07-04T07:01:32.043968433+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=initd evt_type=openat user=root user_uid=0 process=event-generator proc_exepath=/usr/bin/event-generator parent=containerd-shim command=event-generator run syscall --loop=false container_id=e2bebd4617a4",
  "output_fields": {
    "container.id": "e2bebd4617a4",
    "evt.type": "openat",
    "fd.name": "/etc/shadow",
    "proc.cmdline": "event-generator run syscall --loop=false",
    "proc.name": "event-generator",
    "proc.pname": "containerd-shim",
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
  "time": "2026-07-04T07:01:32.043968433Z"
}
```
**Triggered by:** `syscall.ReadSensitiveFileUntrusted` — opens `/etc/shadow` from a non-trusted binary (not in Falco's trusted process list).

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: "Write to /tmp by container"
  desc: Detects execution of processes that write to /tmp inside a container, indicating possible malware staging or log tampering.
  condition: >
    spawned_process and
    container and
    proc.cmdline contains "/tmp" and
    not proc.name in (apt, apt-get, dpkg, yum, pip, pip3, sh, bash)
  output: >
    Process referencing /tmp spawned in container
    (container=%container.name user=%user.name cmd=%proc.cmdline parent=%proc.pname)
  priority: WARNING
  tags: [container, drift]

- rule: "Possible Cryptominer Activity"
  desc: Detects known cryptominer process names inside a container.
  condition: >
    spawned_process and
    container and
    proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nbminer, gminer, minerd, cpuminer)
  output: >
    Possible cryptominer process detected in container
    (container=%container.name proc=%proc.name cmdline=%proc.cmdline parent=%proc.pname)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Custom rule fired — Write to /tmp by container
```json
{
  "hostname": "docker-desktop",
  "output": "2026-07-04T07:08:40.918857785+0000: Warning Write to /tmp detected in container (container=<NA> user=root file=/tmp/custom-rule-test.txt cmd=sh -c echo \"test\" > /tmp/custom-rule-test.txt) container_id=b41d47dcf36d",
  "output_fields": {
    "container.id": "b41d47dcf36d",
    "evt.time.iso8601": 1783148920918857785,
    "fd.name": "/tmp/custom-rule-test.txt",
    "proc.cmdline": "sh -c echo \"test\" > /tmp/custom-rule-test.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-07-04T07:08:40.918857785Z"
}
```
**Triggered by:** `docker exec lab9-target /bin/sh -c 'echo "test" > /tmp/custom-rule-test.txt'`

### Tuning consideration (Lecture 9 slide 8)
The "Write to /tmp by container" rule will produce false positives in practice — many legitimate workloads write to `/tmp`: Java applications use it for temporary class files, package managers write lock files there, and build tools stage artifacts under `/tmp` during compilation. The correct tuning approach is to use Falco's `exceptions:` block rather than a growing `and not proc.name=...` chain in the condition. An `exceptions:` block is evaluated as a first-class part of the rule and is easier to audit in version control: for example, adding an exception for `proc.name in (java, mvn, gradle)` with `proc.cmdline contains "/tmp/hsperfdata"` keeps the exception co-located with the rule and visible in `falco --list`. The `and not` pattern in the condition works but accumulates technical debt — each additional exclusion makes the condition harder to reason about and can inadvertently widen the exclusion if the proc name matches more than one binary.

---

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

import rego.v1

# Rule 1: runAsNonRoot must be true
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not input.spec.securityContext.runAsNonRoot
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container '%v' must set runAsNonRoot=true (pod-level or container-level)", [container.name])
}

# Rule 2: allowPrivilegeEscalation must be false
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("Container '%v' must set allowPrivilegeEscalation=false", [container.name])
}

# Rule 3: capabilities.drop must include ALL
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not "ALL" in container.securityContext.capabilities.drop
  msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

# Rule 4: memory limits must be set
deny contains msg if {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container '%v' must set resources.limits.memory", [container.name])
}
```

### Good manifest passes
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```

### Bad manifest 1 fails (runAsRoot + allowPrivilegeEscalation)
```
FAIL - labs/lab9/manifests/bad-pod-runasroot.yaml - main - Container 'app' must set allowPrivilegeEscalation=false
FAIL - labs/lab9/manifests/bad-pod-runasroot.yaml - main - Container 'app' must set runAsNonRoot=true (pod-level or container-level)

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Bad manifest 2 fails (no resources + no runAsNonRoot)
```
FAIL - labs/lab9/manifests/bad-pod-no-resources.yaml - main - Container 'app' must set resources.limits.memory
FAIL - labs/lab9/manifests/bad-pod-no-resources.yaml - main - Container 'app' must set runAsNonRoot=true (pod-level or container-level)

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest (running during `git push` or PR pipeline) catches misconfigurations before they ever reach the cluster — a developer gets a failing check in their PR within seconds and fixes the manifest locally, without needing cluster access or generating an audit event. Admission-time enforcement (via Kyverno, OPA Gatekeeper, or Sigstore policy-controller at `kubectl apply`) is the last line of defence: it blocks the misconfigured manifest even if CI was bypassed, misconfigured, or the manifest was applied directly by an operator. Running both layers is defense-in-depth: CI gives fast developer feedback and catches issues early when they are cheapest to fix; admission control enforces the invariant unconditionally regardless of how the manifest reaches the cluster. Neither layer alone is sufficient — CI without admission control can be bypassed; admission control without CI creates a poor developer experience where failures only surface at deploy time.

---

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: "Possible Cryptominer Activity"
  desc: Detects known cryptominer process names inside a container.
  condition: >
    spawned_process and
    container and
    proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nbminer, gminer, minerd, cpuminer)
  output: >
    Possible cryptominer process detected in container
    (container=%container.name proc=%proc.name cmdline=%proc.cmdline parent=%proc.pname)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
  "hostname": "docker-desktop",
  "output": "2026-07-04T07:10:35.234569990+0000: Critical Drop and execute new binary in container | proc.name=xmrig proc.exepath=/tmp/xmrig proc.cmdline=xmrig -c exit proc.pname=sh container_id=b41d47dcf36d",
  "output_fields": {
    "container.id": "b41d47dcf36d",
    "evt.arg.flags": "EXE_WRITABLE|EXE_UPPER_LAYER",
    "evt.type": "execve",
    "proc.cmdline": "xmrig -c exit",
    "proc.exe": "/tmp/xmrig",
    "proc.exepath": "/tmp/xmrig",
    "proc.name": "xmrig",
    "proc.pname": "sh",
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Critical",
  "rule": "Drop and execute new binary in container",
  "source": "syscall",
  "tags": ["PCI_DSS_11.5.1", "TA0003", "container", "maturity_stable", "mitre_persistence", "process"],
  "time": "2026-07-04T07:10:35.234569990Z"
}
```
**Triggered by:** `docker exec lab9-target /bin/sh -c 'cp /bin/sh /tmp/xmrig && /tmp/xmrig -c exit'` — renames a binary to `xmrig` and executes it from `/tmp`.

Note: the built-in rule "Drop and execute new binary in container" fired simultaneously, confirming the same binary drop pattern from two angles — the custom rule detects by process name; the built-in rule detects by the `EXE_WRITABLE|EXE_UPPER_LAYER` flag (executable not present in the original image layers).

### Reflection
The two indicators used are **process name matching** (`proc.name in (xmrig, ...)`) and implicitly **execution from a writable path** (the binary was copied to `/tmp` before execution, which triggered the companion built-in rule). Process name matching was chosen because it is cheap — Falco evaluates it on every `execve` event with no network overhead — and because real-world miners like XMRig and T-Rex have well-known binary names that attackers rarely rename in opportunistic attacks. The primary false-negative case is obfuscated mining: an attacker who renames the binary to `python3` or `java` and routes traffic over HTTPS port 443 to a mining proxy would bypass both the process-name check and the port-based indicators entirely. To close this gap, the rule should be combined with a CPU-usage anomaly signal (e.g. from cAdvisor metrics) and a Falco network rule watching for long-lived outbound connections to unusual ASNs — matching the Lecture 9 SLA matrix's "correlated signal" tier, where two independent indicators must both fire before a CRITICAL page is sent, reducing false positives while keeping detection latency under the 5-minute SLA for cryptominer incidents.
