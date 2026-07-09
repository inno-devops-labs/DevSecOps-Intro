# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

**Environment:** Falco 0.43.1, modern eBPF, kernel 7.0.12+kali-amd64  
**Target container:** `alpine:3.20` named `lab9-target`

### Baseline alert A — Terminal shell in container

```json
{
  "hostname": "8e925df0b9ce",
  "output": "2026-07-09T05:57:50.101174653+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=systemd command=sh -c echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=acf977765e42 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "acf977765e42",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.type": "execve",
    "proc.cmdline": "sh -c echo \"shell-in-container test\"",
    "user.name": "root"
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["container", "shell", "mitre_execution"]
}
```

**Trigger command:** `docker exec -t lab9-target /bin/sh -c 'echo "shell-in-container test"'`  
The `-t` flag allocates a pseudo-TTY, which sets `proc.tty != 0` — the key field in Falco's "Terminal shell in container" condition. Without `-t`, the rule does not fire.

---

### Baseline alert B — Read sensitive file untrusted

```json
{
  "hostname": "8e925df0b9ce",
  "output": "2026-07-09T05:58:37.183217419+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=containerd-shim ggparent=systemd evt_type=open user=root user_uid=0 process=cat proc_exepath=/bin/busybox parent=sh command=cat /etc/shadow terminal=0 container_id=acf977765e42 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20",
  "output_fields": {
    "container.id": "acf977765e42",
    "container.name": "lab9-target",
    "evt.type": "open",
    "fd.name": "/etc/shadow",
    "proc.cmdline": "cat /etc/shadow",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": ["filesystem", "mitre_credential_access"]
}
```

**Trigger command:** `docker exec lab9-target /bin/sh -c 'cat /etc/shadow'`

---

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)

```yaml
- rule: Write to /tmp by container
  desc: Detects any write to /tmp inside a container — common indicator of dropper activity or staging
  condition: >
    open_write
    and container
    and fd.directory = /tmp
  output: >
    Write to /tmp detected in container
    (user=%user.name container=%container.name image=%container.image.repository
     file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]

- rule: Possible Cryptominer Activity
  desc: >
    Detects a container connecting to well-known cryptomining pool ports or running
    a known miner binary — maps to the Tesla 2018 K8s dashboard incident (Lecture 1)
  condition: >
    container
    and (
      (evt.type = connect and fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
      or
      (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nbminer))
    )
  output: >
    Possible cryptominer activity in container
    (container=%container.name image=%container.image.repository
     proc=%proc.name conn=%fd.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

---

### Custom rule fired — "Write to /tmp by container"

```json
{
  "hostname": "8e925df0b9ce",
  "output": "2026-07-09T05:57:02.768832199+0000: Warning Write to /tmp detected in container (user=root container=lab9-target image=alpine file=/tmp/my-write.txt cmd=sh -c echo \"test\" > /tmp/my-write.txt)",
  "output_fields": {
    "container.name": "lab9-target",
    "container.image.repository": "alpine",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -c echo \"test\" > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": ["container", "drift"]
}
```

**Trigger command:** `docker exec lab9-target /bin/sh -c 'echo "test" > /tmp/my-write.txt'`

---

### Tuning consideration (Lecture 9 slide 8)

The "write to /tmp" rule generates significant noise in production: logging frameworks (`logback`, `log4j`), Node.js, and many runtimes write temp files to `/tmp` legitimately. The preferred tuning approach is the `exceptions:` block over inline `and not proc.name=...` conditions because exceptions are composable — multiple exception entries can be added without rewriting the condition, and they appear in structured form that linting tools can validate. For example:

```yaml
exceptions:
  - name: trusted_loggers
    fields: [proc.name]
    comps: [in]
    values: [["node", "python3", "java"]]
```

This is preferable to `condition: ... and not proc.name in (node, python3, java)` because the condition stays clean and each exception entry is independently auditable (Lecture 9 slide 8: "exceptions are first-class citizens in Falco rule governance").

---

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)

```rego
package main

# 1. Pod or container must set runAsNonRoot: true
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  not input.spec.template.spec.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment '%s': container '%s' must set runAsNonRoot: true", [input.metadata.name, c.name])
}

# 2. allowPrivilegeEscalation must be explicitly false on every container
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Deployment '%s': container '%s' must set allowPrivilegeEscalation: false", [input.metadata.name, c.name])
}

# 3. capabilities.drop must include ALL on every container
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not "ALL" in c.securityContext.capabilities.drop
  msg := sprintf("Deployment '%s': container '%s' must drop ALL capabilities", [input.metadata.name, c.name])
}

# 4. Memory limits must be set (OOM kill bound)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("Deployment '%s': container '%s' must set resources.limits.memory", [input.metadata.name, c.name])
}

# 5. Image must not use :latest tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("Deployment '%s': container '%s' uses disallowed :latest tag — pin to a digest or explicit version", [input.metadata.name, c.name])
}
```

### Good manifest passes

```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/

10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Bad manifest fails (unhardened — no securityContext, :latest tag, no resources)

```
$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/extra/

FAIL - juice-unhardened.yaml - main - Deployment 'juice-unhardened': container 'juice' must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - main - Deployment 'juice-unhardened': container 'juice' must set resources.limits.memory
FAIL - juice-unhardened.yaml - main - Deployment 'juice-unhardened': container 'juice' must set runAsNonRoot: true
FAIL - juice-unhardened.yaml - main - Deployment 'juice-unhardened': container 'juice' uses disallowed :latest tag — pin to a digest or explicit version

10 tests, 6 passed, 0 warnings, 4 failures, 0 exceptions
```

### Why CI-time vs admission-time (Lecture 9 slide 9)

CI-time Conftest runs during PR review — it catches misconfigurations before code is merged and before any cluster is involved, giving the developer immediate feedback in the same loop where they can fix it at zero cost. Admission-time gating (Kyverno, OPA Gatekeeper) runs at `kubectl apply` time and acts as the last line of defense — it blocks deployments that somehow bypassed CI (direct `kubectl` from a developer laptop, a CI pipeline that skipped the policy step, or a manifest created by an operator without repo access). Running both creates defense-in-depth: CI-time prevents the problem from ever reaching the cluster in the normal flow; admission-time enforces the same policy unconditionally regardless of how the manifest was submitted.

---

## Bonus: Cryptominer Detection Rule

### Rule

```yaml
- rule: Possible Cryptominer Activity
  desc: >
    Detects a container connecting to well-known cryptomining pool ports or running
    a known miner binary — maps to the Tesla 2018 K8s dashboard incident (Lecture 1)
  condition: >
    container
    and (
      (evt.type = connect and fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
      or
      (proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, nbminer))
    )
  output: >
    Possible cryptominer activity in container
    (container=%container.name image=%container.image.repository
     proc=%proc.name conn=%fd.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert

```json
{
  "hostname": "8e925df0b9ce",
  "output": "2026-07-09T06:00:44.325149895+0000: Critical Possible cryptominer activity in container (container=lab9-target image=alpine proc=nc conn=172.17.0.2:39281->8.8.8.8:3333 cmd=nc -w 3 8.8.8.8 3333)",
  "output_fields": {
    "container.name": "lab9-target",
    "container.image.repository": "alpine",
    "fd.name": "172.17.0.2:39281->8.8.8.8:3333",
    "proc.cmdline": "nc -w 3 8.8.8.8 3333",
    "proc.name": "nc"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": ["container", "mitre_execution", "mitre_command_and_control"]
}
```

**Trigger command:** `docker exec lab9-target sh -c 'timeout 3 nc -w 3 8.8.8.8 3333 2>/dev/null || true'`

### Reflection

**Indicators used:** (1) outbound TCP connect to known mining-pool ports (`fd.rport in (3333, 4444, ...)`) + (2) process name matches known miner binaries (`proc.name in (xmrig, ethminer, ...)`). Port-based detection catches any process connecting to a mining pool, while process-name detection catches miners even on non-standard ports. Together they cover the two most common deployment patterns: downloaded miner binary and miner-as-a-service calling home.

**What this misses (false-negative case):** A sophisticated attacker exfiltrates mining traffic over HTTPS port 443 (which is indistinguishable from legitimate outbound HTTPS), uses a custom-compiled miner binary with a renamed process (so `proc.name` doesn't match any known list), or pools mining traffic through a CDN domain. Port-based and process-name-based rules are defeated by any mining setup designed to blend in with normal web traffic — this is the "living off the land" evasion (Lecture 9 slide 8's noise/signal discussion).

**SLA matrix integration:** Per Lecture 9's SLA matrix, a CRITICAL Falco alert maps to a 1-hour response SLA. In practice, this rule should auto-page the on-call team and simultaneously trigger a `kubectl cordon` + pod eviction to stop the resource drain while investigation proceeds — the financial impact of a cryptominer is direct (CPU/GPU billing) and measurable, which makes it one of the few runtime alerts where automated remediation (not just notification) is defensible.
