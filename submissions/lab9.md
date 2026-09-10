# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

Falco was run with the **modern eBPF** probe (log line: `Opening 'syscall' source with modern BPF probe`) against an `alpine:3.20` target container.

### Baseline alert A — Terminal shell in container
```json
{"rule":"Terminal shell in container","priority":"Notice","output":"2026-07-09T15:38:39.475949524+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc id terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=038f91e742b6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"rule":"Read sensitive file untrusted","priority":"Warning","output":"2026-07-09T15:38:20.955069765+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=initd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=038f91e742b6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>"}
```

### Custom rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- rule: Write to /tmp by container
  desc: >
    Detects any process writing a file under /tmp from inside a container.
    Writes on the host are ignored. Container-drift indicator.
  condition: >
    open_write
    and container
    and fd.name startswith "/tmp/"
  output: >
    File written under /tmp inside a container
    (user=%user.name container=%container.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{
  "hostname": "ddabf6158bd9",
  "output": "2026-07-09T15:33:30.774865258+0000: Warning File written under /tmp inside a container (user=root container=lab9-target file=/tmp/my-write.txt cmd=sh -lc echo test > /tmp/my-write.txt) container_id=038f91e742b6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "038f91e742b6",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783611210774865258,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-07-09T15:33:30.774865258Z"
}
```

### Tuning consideration (Lecture 9 slide 8)
The "Write to /tmp by container" rule is inherently noisy: legitimate processes
(logging frameworks, caches, `pip`/`npm`, compilers) write to `/tmp` all the time.
The cleanest way to cut false positives is to add an `exceptions:` block to the rule
that matches on specific fields (e.g. the `proc.name` + `fd.name` pair) without
touching the main `condition:` — it is declarative, easy to review in a PR, and does
not break the original detection logic. The blunter alternative is to append inline
exclusions to the `condition:` such as `and not proc.name in (node, python3, java, pip)`,
but that quickly turns into an unreadable wall and mixes the signal with its filters.
In practice I would keep the rule at WARNING for alerting and move known-trusted
processes into `exceptions:`, preserving both coverage and readability.

---

## Task 2: Conftest Policy-as-Code

### My policy file (labs/lab9/policies/extra/hardening.rego)
```rego
package main

import rego.v1

# Collect containers from either a Pod or a Deployment
workload_containers contains c if {
  input.kind == "Pod"
  some c in input.spec.containers
}

workload_containers contains c if {
  input.kind == "Deployment"
  some c in input.spec.template.spec.containers
}

# Pod-level securityContext (differs between Pod and Deployment)
pod_security_context := input.spec.securityContext if {
  input.kind == "Pod"
}

pod_security_context := input.spec.template.spec.securityContext if {
  input.kind == "Deployment"
}

# Rule 1 — runAsNonRoot must be true (pod-level OR container-level)
deny contains msg if {
  some c in workload_containers
  not pod_security_context.runAsNonRoot == true
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %q must set runAsNonRoot: true (pod- or container-level securityContext)", [c.name])
}

# Rule 2 — allowPrivilegeEscalation must be false (every container)
deny contains msg if {
  some c in workload_containers
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# Rule 3 — capabilities.drop must include "ALL" (every container)
deny contains msg if {
  some c in workload_containers
  drop := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in drop
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# Rule 4 — resources.limits.memory must be set (every container)
deny contains msg if {
  some c in workload_containers
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# Rule 5 — reject the mutable :latest tag
deny contains msg if {
  some c in workload_containers
  endswith(c.image, ":latest")
  msg := sprintf("container %q must not use the mutable :latest tag", [c.name])
}

# Rule 5b (warn, not deny) — prefer pinning image by @sha256: digest
warn contains msg if {
  some c in workload_containers
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q should pin its image by @sha256: digest for immutability", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/

12 tests, 12 passed, 0 warnings, 0 failures, 0 exceptions

# Image is pinned by @sha256 digest, so even the digest warn stays silent — a fully clean pass.
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/extra/

WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" should pin its image by @sha256: digest for immutability
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must not use the mutable :latest tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true (pod- or container-level securityContext)

12 tests, 6 passed, 1 warning, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
$ conftest test labs/lab9/manifests/compose/juice-compose.yml \
    --policy labs/lab9/policies/compose-security.rego --namespace compose.security

4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test /tmp/bad-compose.yml \
    --policy labs/lab9/policies/compose-security.rego --namespace compose.security

FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions

# Same deny[msg] pattern as the K8s policy, but over the input.services shape —
# the hardened compose passes cleanly, while the bare nginx:latest fails.
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest runs inside the PR pipeline: a violation is caught before merge, the
author gets feedback within seconds and fixes the manifest in context, and the decision
trail stays in code review. Admission-time Conftest (Conftest/Kyverno on a webhook) is
the last line of defense at `kubectl apply`: it catches whatever bypassed CI (a manual
`apply`, drift, a different pipeline, a compromised runner). Running **both** gives
defense in depth: CI provides the fast developer loop and "shift left," while admission
guarantees the policy is physically unenforceable to skip inside the cluster, even if CI
was bypassed.

---

## Bonus: Cryptominer Detection Rule

### Rule (labs/lab9/falco/rules/custom-rules.yaml)
```yaml
- list: crypto_miner_binaries
  items: [xmrig, ethminer, cgminer, t-rex, claymore, minerd, xmr-stak]

- macro: outbound_to_miner_port
  condition: >
    evt.type = connect and evt.dir = <
    and fd.sockfamily = ip
    and (fd.sport = 3333 or fd.sport = 4444 or fd.sport = 5555
         or fd.sport = 7777 or fd.sport = 14444 or fd.sport = 19999
         or fd.sport = 45700)

- macro: known_miner_process
  condition: >
    spawned_process
    and proc.name in (crypto_miner_binaries)

- rule: Possible Cryptominer Activity
  desc: >
    Fires when a container either connects out to a well-known mining-pool port
    OR spawns a known cryptominer binary.
  condition: >
    container
    and (outbound_to_miner_port or known_miner_process)
  output: >
    Possible cryptominer activity
    (container=%container.name image=%container.image.repository
     process=%proc.name cmd=%proc.cmdline
     dest=%fd.name server_port=%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
  "hostname": "ddabf6158bd9",
  "output": "2026-07-09T19:37:27.439983756+0000: Critical Possible cryptominer activity (container=lab9-target image=alpine process=nc cmd=nc -w 2 127.0.0.1 3333 dest=127.0.0.1:38977->127.0.0.1:3333 server_port=3333) container_id=038f91e742b6 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "038f91e742b6",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1783625847439983756,
    "fd.name": "127.0.0.1:38977->127.0.0.1:3333",
    "fd.sport": 3333,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.name": "nc"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "source": "syscall",
  "tags": ["container", "mitre_command_and_control", "mitre_execution"],
  "time": "2026-07-09T19:37:27.439983756Z"
}
```

### Reflection
- **Which 2 indicators and why.** I combined a *network* indicator (outbound connection
  to common mining-pool ports: 3333/4444/5555/7777/14444/…) with a *process* indicator
  (launch of known miner binaries: xmrig, ethminer, cgminer, etc.). They complement each
  other: the port catches a miner even if its binary is renamed, and the process name
  catches a miner that uses a non-standard port.
- **What it misses (false negative).** Obfuscated mining over 443/HTTPS to a
  benign-looking host (a pool proxy over TLS) produces neither a "miner" port nor a known
  process name, so the rule stays blind. That case needs different signals: CPU anomaly
  detection, domain-reputation/DNS feeds, or JA3/TLS fingerprinting.
- **Tie-in with the Lecture 9 SLA matrix.** The CRITICAL priority maps to the strictest
  row of the SLA matrix (immediate investigation/escalation), whereas the WARNING `/tmp`
  rule maps to a softer SLA (batch triage). The matrix thus turns a stream of alerts into
  predictable, severity-driven response times.
