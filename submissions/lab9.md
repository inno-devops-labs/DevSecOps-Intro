# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{
  "hostname": "5770eb4b1b1e",
  "output": "2026-07-10T15:08:47.168137434+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -c echo \"shell-in-container test\" terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=0560708d4cbe container_name=lab9-target container_image_repository=127.0.0.1:5000/juice-shop container_image_tag=v20.0.0-tampered",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "output_fields": {
    "proc.name": "sh",
    "proc.cmdline": "sh -c echo \"shell-in-container test\"",
    "proc.tty": 34816,
    "user.name": "root",
    "container.name": "lab9-target"
  },
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
  "time": "2026-07-10T15:08:47.168137434Z"
}
```
> Note: `docker exec -it` failed here with `the input device is not a TTY` (no real terminal attached to the automation shell that ran these commands) so the rule didn't see `proc.tty != 0`. Using `docker exec -t` (pty allocated by Docker inside the container, without requiring an interactive host stdin) reproduced the same condition the rule checks for and fired correctly.

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{
  "hostname": "5770eb4b1b1e",
  "output": "2026-07-10T15:08:49.297453477+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow ... process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow container_name=lab9-target",
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "output_fields": {
    "evt.type": "openat",
    "fd.name": "/etc/shadow",
    "proc.name": "cat",
    "proc.cmdline": "cat /etc/shadow",
    "user.name": "root"
  },
  "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"],
  "time": "2026-07-10T15:08:49.297453477Z"
}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detects a process inside a container writing a file under /tmp
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

### Custom rule fired
```json
{
  "hostname": "5770eb4b1b1e",
  "output": "2026-07-10T15:08:51.388185603+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo \"test\" > /tmp/my-write.txt) container_id=0560708d4cbe container_name=lab9-target",
  "priority": "Warning",
  "rule": "Write to /tmp by container",
  "output_fields": {
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo \"test\" > /tmp/my-write.txt",
    "user.name": "root",
    "container.name": "lab9-target"
  },
  "tags": ["container", "drift"],
  "time": "2026-07-10T15:08:51.388185603Z"
}
```

### Tuning consideration (Lecture 9 slide 8)
This rule will fire on plenty of legitimate `/tmp` usage — package managers, language runtimes (Node/Python temp files), and logging frameworks that buffer to `/tmp` before rotating. The `exceptions:` block is the better tuning tool here over a hand-rolled `and not proc.name=...`, because exceptions are declared as data (a list of exempted values) rather than baked into the rule's boolean logic, so an SRE can add a new exempted process name or container image without touching or re-testing the condition expression itself — and Falco can hot-reload just the exceptions list. I'd add an `exceptions: [{name: known_tmp_writers, fields: [proc.name], values: [[npm], [node], [pip]]}]` block scoped to specific trusted images/processes rather than a blanket `and not proc.name in (...)`, since exceptions can be further scoped per-container-image (`container.image.repository`), which a flat `and not` clause can't express as cleanly.

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

import rego.v1

# 1. runAsNonRoot must be true (pod-level or container-level securityContext)
deny contains msg if {
  input.kind == "Deployment"
  spec := input.spec.template.spec
  containers := spec.containers[_]
  not spec.securityContext.runAsNonRoot == true
  not containers.securityContext.runAsNonRoot == true
  msg := "spec.template.spec.securityContext.runAsNonRoot (or per-container) must be true"
}

# 2. allowPrivilegeEscalation must be false (every container)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" (every container)
# NOTE: `not "ALL" in c.securityContext.capabilities.drop` silently never fires
# when securityContext is entirely absent (undefined does not propagate through
# `in` the way it does through a plain `not`), so default missing paths to [].
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  drop := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not "ALL" in drop
  msg := sprintf("container %q must drop ALL capabilities (capabilities.drop: [\"ALL\"])", [c.name])
}

# 4. resources.limits.memory must be set
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. image must be pinned by sha256 digest, not a mutable tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin image by @sha256: digest, not a mutable tag (%q)", [c.name, c.image])
}
```

> **Debugging note:** an early version of rule 3 used `not "ALL" in c.securityContext.capabilities.drop` directly (mirroring the shipped `k8s-security.rego` style). That silently never fired on `juice-unhardened.yaml`, where `securityContext` is absent entirely — `in` on a deeply-undefined nested path doesn't propagate through `not` as a plain field-existence check does. Wrapping the lookup in `object.get(c, [...], [])` with an explicit default fixed it; verified with an isolated Conftest reproduction before and after the fix.

### Compliant manifest passes (`juice-hardened.yaml`)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities (capabilities.drop: ["ALL"])
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin image by @sha256: digest, not a mutable tag ("bkimminich/juice-shop:latest")
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set securityContext.allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - spec.template.spec.securityContext.runAsNonRoot (or per-container) must be true

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```
(5 distinct deny messages — all 5 rules trip at once, as expected since the unhardened manifest sets no securityContext, no resources, and uses a `:latest` tag.)

### Compose policy generalizes (shipped `compose-security.rego`)
PASS on the shipped hardened compose file:
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```
FAIL on a deliberately unhardened compose file (`nginx:latest`, no `user`, no `read_only`, no `cap_drop`):
```
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
Same `deny[msg]` pattern, same `has_value` helper style, just walking `input.services` instead of `input.spec.template.spec.containers` — confirms the skill transfers across target shapes without changing the underlying Rego idiom.

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest catches a bad manifest during PR review, before it's merged — the feedback loop is a `git push` and a re-run, and the fix never touches a running cluster. Admission-time enforcement (Kyverno/OPA Gatekeeper at `kubectl apply`) is the backstop for everything that *doesn't* go through CI-time review: a manual `kubectl apply` from someone's laptop, a manifest generated by a script that bypassed the PR pipeline, or a Helm chart with templating that only resolves to something non-compliant at deploy time. Running both is defense in depth in the classic sense — CI-time is cheap and fast but trivially bypassed by anyone with cluster credentials; admission-time is authoritative and can't be bypassed, but by the time it rejects something, someone has already burned a deploy cycle. Together they mean policy violations get caught at the cheapest point (CI) in the common case, with a hard guarantee (admission) that nothing non-compliant reaches a running workload regardless of how it was submitted.

---

## Bonus: Cryptominer Detection Rule

### Rule
```yaml
- rule: Possible Cryptominer Activity
  desc: >
    Detects a container connecting to a well-known mining-pool port, or a process
    matching a well-known miner binary name. Either indicator alone is enough to
    fire (fd.sport OR proc.name), so a single connection attempt from a container
    to a stratum-protocol port is sufficient to trigger this rule.
  condition: >
    container.id != host
    and (
      (evt.type=connect and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
      or (evt.type=execve and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore))
    )
  output: >
    Possible Cryptominer Activity
    (container=%container.name process=%proc.name command=%proc.cmdline connection=%fd.name port=%fd.sport user=%user.name)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{
  "hostname": "5770eb4b1b1e",
  "output": "2026-07-10T15:10:22.578111895+0000: Critical Possible Cryptominer Activity (container=lab9-target process=nc command=nc -w 2 127.0.0.1 3333 connection=127.0.0.1:45469->127.0.0.1:3333 port=3333 user=root) container_id=0560708d4cbe container_name=lab9-target",
  "priority": "Critical",
  "rule": "Possible Cryptominer Activity",
  "output_fields": {
    "fd.name": "127.0.0.1:45469->127.0.0.1:3333",
    "fd.sport": 3333,
    "proc.name": "nc",
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "user.name": "root",
    "container.name": "lab9-target"
  },
  "tags": ["container", "mitre_command_and_control", "mitre_execution"],
  "time": "2026-07-10T15:10:22.578111895Z"
}
```
> **Debugging note:** the lab's suggested trigger (`nc -w 2 127.0.0.1 3333` with nothing listening) produces an immediate `ECONNREFUSED`, and on this Falco/kernel combination the `fd.*` fields are only populated by the kernel for a `connect()` that actually completes — a synchronously-refused connect leaves `fd.sport` null, so the rule never sees a port to match. Starting a throwaway `nc -l -p 3333` listener inside `lab9-target` first (so the connect() succeeds) let the rule observe `fd.sport=3333` correctly. Confirmed this by writing a temporary debug rule that printed the raw `fd.sport`/`fd.name`/`evt.res` fields for all `connect()` events from the container, which is also how I caught that `container.id != host` alone (matched against *any* container) captured Falco's own container repeatedly retrying nonexistent container-runtime Unix sockets (podman/CRI-O/containerd) at extremely high frequency — that flooded the log to over 1GB before I scoped the debug rule down to `container.name=lab9-target` and removed it once done. The final rule only checks TCP ports (`fd.sport`), so it isn't exposed to that particular noise source (Unix-domain-socket connects don't carry a TCP port).

### Reflection
- **Indicators used:** connection to a known mining-pool port (`fd.sport in (3333, 4444, ...)`) and known miner process names (`xmrig`, `ethminer`, etc.) — port-based detection catches the network behavior regardless of what the binary is called, while the process-name check catches the binary even before/without a network connection (e.g., during a benchmark run or if egress is blocked). Together they cover both the "I don't recognize this traffic" and "I don't recognize this process" cases from Lecture 9.
- **What this misses:** a miner using a non-default port, connecting over HTTPS (443) to a pool proxy or via a domain-fronted/CDN-hidden pool endpoint, or a renamed/statically-linked binary (`proc.name` trivially defeated by `cp xmrig totally-not-a-miner`) — obfuscated mining over HTTPS to a pool disguised behind a generic-looking hostname is the realistic false-negative case, since port 443 traffic is indistinguishable from normal outbound web traffic at the syscall level Falco observes.
- **SLA matrix integration (Lecture 9):** a `CRITICAL` cryptominer alert should sit at the top of the response-time tier (minutes, not hours) given the direct dollar cost of compute theft and the fact that Tesla's 2018 incident was discovered by an external researcher rather than internal alerting — but given the false-negative gap above, this rule alone shouldn't be the *only* signal in that SLA tier; it should be paired with anomalous-egress-volume or CPU-utilization-based detection (out of Falco's scope, per the table above) so the SLA is backed by more than one independent detection path.
