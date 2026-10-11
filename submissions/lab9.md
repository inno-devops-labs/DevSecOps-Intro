# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container

JSON alert from Falco logs (paste the most relevant lines):

```json
{
  "hostname": "22335ae5173e",
  "output": "2026-07-10T09:30:12.910103048+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=412df0545944 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "412df0545944",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1783675812910103048,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo \"shell-in-container test\"",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "containerd-shim",
    "proc.tty": 34816,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
  "time": "2026-07-10T09:30:12.910103048Z"
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)

```json
{
  "hostname": "22335ae5173e",
  "output": "2026-07-10T09:30:19.332631096+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=412df0545944 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "412df0545944",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783675819332631096,
    "evt.type": "open",
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
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-07-10T09:30:19.332631096Z"
}
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)

```yaml
- rule: Write to /tmp by container
  desc: Detects writes to /tmp inside any container
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp in container (user=%user.name container=%container.name
    file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired

Falco log line showing your custom rule:

```json
{
  "hostname": "22335ae5173e",
  "output": "2026-07-10T09:31:13.585707592+0000: Warning Write to /tmp in container (user=root container=lab9-target file=/tmp/my-write.txt proc=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=412df0545944 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "412df0545944",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783675873585707592,
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
  "time": "2026-07-10T09:31:13.585707592Z"
}
```

### Tuning consideration (Lecture 9 slide 8)

To reduce false positives from legitimate logging frameworks or package managers writing to `/tmp`, I would use the `exceptions:` block introduced in Falco 0.28+. This allows for structured, easily auditable whitelisting of specific process names (e.g., `proc.name in (java, python, apt-get)`) or container images, which is much cleaner and more maintainable than chaining multiple `and not proc.name=...` conditions directly in the rule body.

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)

```rego
package main

# Helper: true if array arr contains value v
has_value(arr, v) if {
  some i
  arr[i] == v
}

# 1. runAsNonRoot must be true
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

# 2. allowPrivilegeEscalation must be false
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL"
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not has_value(c.securityContext.capabilities.drop, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)

```text
6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)

```text
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true

6 tests, 4 passed, 0 warnings, 2 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)

```text
# PASS on juice-compose.yml
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# FAIL on /tmp/bad-compose.yml
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

CI-time Conftest provides immediate feedback to developers during PR review, preventing bad configurations from ever merging and reducing rework. Admission-time Conftest (via Gatekeeper/Kyverno) acts as a runtime guardrail, catching any manifests that bypass CI (e.g., manual `kubectl apply` or Helm upgrades) and ensuring defense-in-depth by enforcing compliance at the cluster level.

## Bonus: Cryptominer Detection Rule

### Rule (paste)

```yaml
- rule: Possible Cryptominer Activity
  desc: Detects container connecting to mining-pool ports or running known miner processes
  condition: >
    container.id != host and
    (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore) or
     (evt.type=connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)))
  output: >
    Possible Cryptominer Activity (user=%user.name container=%container.name
    proc=%proc.name cmdline=%proc.cmdline target=%fd.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{
  "hostname": "22335ae5173e",
  "output": "2026-07-10T13:20:24.864074205+0000: Critical Possible Cryptominer Activity (user=root container=lab9-target proc=xmrig cmdline=xmrig sleep 5 target=<NA>) container_id=412df0545944 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "412df0545944",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783689624864074205,
    "fd.name": null,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "xmrig sleep 5",
    "proc.name": "xmrig",
    "user.name": "root"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": ["container", "mitre_command_and_control", "mitre_execution"],
  "time": "2026-07-10T13:20:24.864074205Z"
}
```

### Reflection

- **Indicators used:** I combined process name matching (`proc.name in (xmrig...)`) with network destination port detection (`fd.sport in (3333...)` as defined by the lab hint). Using both provides defense in depth: the process name catches known binaries even if they tunnel over standard ports, while the port list catches generic/obfuscated miners connecting to known pools.
- **False-negative case & Kernel limitation:** This misses obfuscated mining over standard HTTPS (port 443) or DNS tunneling. Additionally, during testing on my Arch kernel (7.1.2), I discovered that the `syscalls/sys_enter_connect` tracepoint is missing, causing Falco's modern eBPF probe to fail to capture `connect` syscalls entirely. To ensure the rule could be triggered for this submission, I simulated the process name indicator by creating a fake `xmrig` binary. In a production environment with a supported kernel (or using the legacy eBPF driver), the network port indicator would also fire.
- **SLA matrix integration:** Tagged `CRITICAL` with MITRE Execution + C2, this maps directly to the "Critical (CVSS 9–10)" tier from Lecture 9 slide 12: 24-hour remediation SLA, owned by On-call + Security Lead, with an automatic page on creation. The MITRE tags also let the SOC pivot from this alert to related TTPs (e.g., initial access via exposed K8s dashboard, as in the 2018 Tesla incident referenced in the lab).
