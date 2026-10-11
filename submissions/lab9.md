# Lab 9 — Submission

Runtime detection with Falco (modern eBPF) + policy-as-code with Conftest, on the provided
`labs/lab9/` plumbing.

Tooling: Falco 0.43.1 · Conftest (Rego v1) · Docker · jq 1.7.1.

> **Environment note (Falco only):** I ran Falco on **Colima** (a Lima VM with a real Ubuntu 6.8 kernel +
> BTF — `test -f /sys/kernel/btf/vmlinux` → BTF OK), exactly as the lab's macOS pitfall note recommends.
> Modern eBPF attaches and all file/process detection works. One caveat carries into the bonus: on this
> host neither Docker Desktop nor the Colima VM exposes the per-syscall `sys_enter_connect` tracepoint
> (`/sys/kernel/tracing/events/syscalls/` is empty), which is where Falco reads the connect **destination**
> sockaddr — so network events arrive with `fd.sport=<NA>`. That only affects the port-based miner
> indicator; I cover it in the bonus reflection and trigger that rule via its process-name indicator.
> Conftest (Task 2) is pure userspace and ran natively.

## Task 1: Runtime Detection with Falco

Falco started on the modern BPF probe (`docker logs falco | grep -i "modern BPF"` →
`Opening 'syscall' source with modern BPF probe`).

### Baseline alert A — Terminal shell in container
```json
{
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "output": "A shell was spawned in a container with an attached terminal | evt_type=execve user=root process=sh command=sh -lc echo terminal-shell-test terminal=34816 container_id=36134568b258 container_name=lab9-target container_image=alpine:3.20",
  "output_fields": { "container.name": "lab9-target", "proc.name": "sh", "proc.cmdline": "sh -lc echo terminal-shell-test", "user.name": "root" }
}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "output": "Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=openat user=root process=cat command=cat /etc/shadow container_id=36134568b258 container_name=lab9-target container_image=alpine:3.20",
  "output_fields": { "container.name": "lab9-target", "fd.name": "/etc/shadow", "proc.name": "cat", "proc.cmdline": "cat /etc/shadow", "user.name": "root" }
}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: >
    A process running inside a container wrote to a file under /tmp.
  condition: >
    open_write
    and container
    and fd.name startswith /tmp/
  output: >
    Write to /tmp inside container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "output": "Write to /tmp inside container (container=lab9-target user=root file=/tmp/xmrig cmd=sh -c printf ... > /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig)",
  "output_fields": { "container.name": "lab9-target", "fd.name": "/tmp/xmrig", "user.name": "root" }
}
```

### Tuning consideration (Lecture 9 slide 8)
The "write to /tmp" rule will fire on legitimate work too — package managers, logging frameworks, and
language runtimes all stage files under /tmp. I'd tune it with an `exceptions:` block keyed on the
known-good process, e.g. an exception `(proc.name)` with values `[apt, pip, node]`, rather than bolting a
long `and not proc.name in (...)` onto the condition. The `exceptions:` approach is append-only and
composable (Falco merges exception entries across rule files), so ops can extend the allow-list without
editing the detection logic and risking a typo that silently breaks the whole condition.

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

import rego.v1

podspec := input.spec.template.spec if input.kind == "Deployment"

container_nonroot(c) if podspec.securityContext.runAsNonRoot == true
container_nonroot(c) if c.securityContext.runAsNonRoot == true

# 1. Must run as non-root.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not container_nonroot(c)
	msg := sprintf("container %q must run as non-root (securityContext.runAsNonRoot: true)", [c.name])
}

# 2. Must not allow privilege escalation.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. Must drop ALL Linux capabilities.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# 4. Must set a memory limit.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. Must pin the image by digest, not a mutable tag.
deny contains msg if {
	input.kind == "Deployment"
	c := podspec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin image by digest (@sha256:), not a tag", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies/extra/
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
$ conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies/extra/
FAIL - ... - main - container "juice" must drop ALL capabilities
FAIL - ... - main - container "juice" must pin image by digest (@sha256:), not a tag
FAIL - ... - main - container "juice" must run as non-root (securityContext.runAsNonRoot: true)
FAIL - ... - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - ... - main - container "juice" must set resources.limits.memory

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
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
2 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
The same `deny contains msg` pattern works on `input.services` (compose) as on
`input.spec.template.spec.containers` (K8s) — only the input shape changes.

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest runs during PR review, so a developer gets the "you forgot runAsNonRoot" feedback before
merge, when it's cheapest to fix and nothing is deployed yet. Admission-time (the same Rego behind
Kyverno/OPA at `kubectl apply`) is the backstop that catches whatever bypassed CI — a hand-applied
manifest, a Helm chart rendered outside the pipeline, or a compromised CI runner. Running both is defense
in depth: CI gives fast feedback and keeps the repo clean; admission guarantees the cluster itself never
runs a non-compliant pod regardless of how it got there.

---

## Bonus: Cryptominer Detection Rule

### Rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- list: cryptominer_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: cryptominer_procs
  items: [xmrig, ethminer, cgminer, t-rex, claymore, minerd, xmr-stak]

- rule: Possible Cryptominer Activity
  desc: >
    A container either connected to a port commonly used by mining pools
    or ran a process named like a known miner.
  condition: >
    container
    and (
      (evt.type in (connect, sendto, sendmsg) and fd.sport in (cryptominer_ports))
      or proc.name in (cryptominer_procs)
    )
  output: >
    Possible cryptominer activity
    (container=%container.name process=%proc.name cmd=%proc.cmdline
     target=%fd.name sport=%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
The rule fired (CRITICAL) via the **process-name** indicator — a process named `xmrig` running in the
container:
```json
{
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "output": "Possible cryptominer activity (container=lab9-target process=xmrig cmd=xmrig /tmp/xmrig target=<NA> sport=<NA>)",
  "output_fields": { "container.name": "lab9-target", "proc.name": "xmrig", "proc.cmdline": "xmrig /tmp/xmrig" }
}
```

> On the `nc 127.0.0.1 3333` port trigger the rule does **not** fire here, and `target/sport` above are
> `<NA>`: on this host Falco's modern probe can't read the connect **destination** (the per-syscall
> `sys_enter_connect` tracepoint isn't exposed — `/sys/kernel/tracing/events/syscalls/` is empty on both
> Docker Desktop and the Colima VM), so `fd.sport` is never populated and the port branch can't match. The
> rule itself is correct (either indicator is sufficient); on a stock cloud/bare-metal node with the
> syscall tracepoints present, the `nc`-to-3333 test fires the port branch. I demonstrate the rule via the
> process indicator, which uses `execve` (fully captured here).

### Reflection
- **Which 2 indicators & why:** (1) outbound connection to a known mining-pool port
  (3333/4444/5555/…) and (2) a process named like a known miner (xmrig/ethminer/…). Ports and binary
  names are the two cheapest, highest-signal indicators — a miner has to talk to a pool and has to run a
  process, and combining them (OR) catches either the network side or the execution side.
- **What it misses (false negatives):** obfuscated mining hidden in a renamed binary (`proc.name` won't
  match) that talks to a pool over **443/TLS** or through a proxy (so `fd.sport` looks like normal HTTPS).
  A miner that renames itself to `nginx` and tunnels over 443 evades both indicators. Detecting that needs
  behavioural signals (sustained high CPU with low network throughput, or DNS to pool domains) rather than
  static port/name lists.
- **SLA matrix:** a CRITICAL runtime alert like this should sit at the top of the Lecture 9 SLA matrix —
  short time-to-acknowledge and an automated response (kill/quarantine the pod), because an active miner is
  live abuse costing money every minute, unlike a lower-severity drift alert that can wait for business
  hours.
