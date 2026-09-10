# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

Falco v0.43.1 running with the **modern eBPF probe** (`Opening 'syscall' source with modern BPF
probe.` in the startup log; the host kernel is 6.17 with `/sys/kernel/btf/vmlinux` present, so no
Colima/legacy-driver fallback was needed). The startup log also shows some
`libpman: ... TOCTOU mitigation ... may not properly work` warnings for `open`/`openat`/`connect`
— these only disable an *extra* anti-race hardening hook on this kernel; the log line itself says
"Detection will continue to work", and the alerts below confirm detection is fully functional.

### Baseline alert A — Terminal shell in container
```json
{"output":"2026-07-10T18:12:58.082489650+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root process=sh proc_exepath=/bin/busybox parent=systemd command=sh -lc echo \"shell-in-container test\" container_id=8f2c18ed9a5b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["T1059","container","maturity_stable","mitre_execution","shell"],"time":"2026-07-10T18:12:58.082489650Z"}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"output":"2026-07-10T18:12:58.223457549+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=open user=root process=cat proc_exepath=/bin/busybox parent=systemd command=cat /etc/shadow container_id=8f2c18ed9a5b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","user.name":"root"},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2026-07-10T18:12:58.223457549Z"}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: Detects a process inside a container writing to /tmp
  condition: >
    open_write and
    container.id != host and
    fd.name startswith /tmp/
  output: >
    Write to /tmp by container (container=%container.name user=%user.name
    file=%fd.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```
Reuses the shipped `open_write` macro (`evt.type in (open,openat,openat2) and
evt.is_open_write=true and fd.typechar='f' and fd.num>=0`), adds a container-only guard
(`container.id != host`) and a path filter (`fd.name startswith /tmp/`).

### Custom rule fired
```json
{"output":"2026-07-10T18:15:48.377110403+0000: Warning Write to /tmp by container (container=lab9-target user=root file=/tmp/my-write.txt proc=sh -lc echo \"test\" > /tmp/my-write.txt)","output_fields":{"container.name":"lab9-target","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"priority":"Warning","rule":"Write to /tmp by container","source":"syscall","tags":["container","drift"]}
```

### Tuning consideration
This rule will fire constantly on legitimate behaviour — plenty of apps write scratch files,
logs, and lock files under `/tmp` (logging frameworks, package managers, language runtimes). Left
as-is it's a noisy true-positive, which Lecture 9 slide 8 warns is just as useless as a false
positive because nobody reads it. My tuning approach is to add a structured `exceptions:` block
rather than growing a long `and not proc.name=...` chain: an `exceptions` entry keyed on
`proc.name` (and/or `container.image.repository`) is easier to audit and extend than an inline
boolean tail, and it keeps the `condition:` readable. For example, exempt known-good writers
(the app's own process name, `apt`, `dpkg`) while still alerting on an unexpected process — e.g.
a shell or `xmrig` — writing to `/tmp`, which is the behaviour actually worth catching.

## Task 2: Conftest Policy-as-Code

> Tooling note: the system `conftest` was v0.56.0, which defaults to Rego v0 and can't parse the
> shipped v1-syntax policies (`deny contains msg if`) without an explicit import. Upgraded to the
> lab-pinned **v0.68.2** (OPA 1.15.2), which defaults to Rego v1 — all runs below are on 0.68.2.

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

import rego.v1

# 1. runAsNonRoot must be true (pod-level OR container-level securityContext)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not container_runs_non_root(c)
	msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}

container_runs_non_root(c) if c.securityContext.runAsNonRoot == true
container_runs_non_root(c) if input.spec.template.spec.securityContext.runAsNonRoot == true

# 2. allowPrivilegeEscalation must be false on every container
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# 3. capabilities.drop must include "ALL" on every container
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not drops_all_caps(c)
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

drops_all_caps(c) if "ALL" in c.securityContext.capabilities.drop

# 4. resources.limits.memory must be set
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# 5. image must be pinned by sha256 digest, not a tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin image by @sha256: digest, not a tag", [c.name])
}
```

Rule #3 uses a helper (`drops_all_caps`) + `not helper(...)` instead of
`not "ALL" in c.securityContext.capabilities.drop`. When a container has no `securityContext` at
all, the inline form leaves the path undefined and the rule silently doesn't fire (same Rego
gotcha seen in Lab 7); the helper pattern treats "path missing" the same as "ALL not present", so
it fires correctly on the unhardened manifest.

### Compliant manifest passes (juice-hardened.yaml)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```
(10 = 5 rules × 2 documents — the Deployment plus the Service, which short-circuits at
`input.kind == "Deployment"`.)

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must pin image by @sha256: digest, not a tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - main - container "juice" must set runAsNonRoot: true

10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```
All 5 rules trip at once — the unhardened Deployment has no `securityContext`, no
`resources`, and a bare `:latest` tag.

### Compose policy generalizes (shipped compose-security.rego)
```
# juice-compose.yml (hardened) — PASS
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# /tmp/bad-compose.yml (nginx:latest, nothing hardened) — FAIL
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
Same `deny contains msg` pattern, different input shape: instead of
`input.spec.template.spec.containers[_]` it iterates `input.services[_]`. The skill transfers
directly — only the field paths change (`svc.user`, `svc.read_only`, `svc.cap_drop`).

### Why CI-time vs admission-time
CI-time Conftest runs during PR review, so a bad manifest gets blocked before it's ever merged —
fast feedback to the author, and it never reaches a cluster. Admission-time enforcement
(Gatekeeper/Kyverno running the same Rego as a webhook) runs at `kubectl apply`, catching anything
that bypassed CI: a hand-applied manifest, a Helm chart rendered differently than the repo, or
drift applied straight to prod. Running both is defense in depth — CI is the cheap early gate that
keeps developers fast, admission is the backstop that guarantees *nothing* lands in the cluster
unchecked regardless of how it got there.

## Bonus: Cryptominer Detection Rule

### Rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- list: miner_ports
  items: [3333, 4444, 5555, 7777, 14444, 19999, 45700]

- list: miner_proc_names
  items: [xmrig, ethminer, cgminer, t-rex, claymore, minerd]

- rule: Possible Cryptominer Activity
  desc: >
    Container making an outbound connection to a known mining-pool port, or
    running a known cryptominer process. Combines two indicators (destination
    port + process name) so it fires on either signal.
  condition: >
    evt.type = connect and
    container.id != host and
    (fd.sport in (miner_ports) or proc.name in (miner_proc_names))
  output: >
    Possible cryptominer activity (container=%container.name proc=%proc.cmdline
    connection=%fd.name sport=%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```

### Triggered alert
```json
{"output":"2026-07-10T18:32:04.041749620+0000: Critical Possible cryptominer activity (container=lab9-target proc=nc -w 2 127.0.0.1 3333 connection=127.0.0.1:41799->127.0.0.1:3333 sport=3333) container_id=8f2c18ed9a5b container_name=lab9-target container_image_repository=alpine container_image_tag=3.20","output_fields":{"container.name":"lab9-target","fd.name":"127.0.0.1:41799->127.0.0.1:3333","fd.sport":3333,"proc.cmdline":"nc -w 2 127.0.0.1 3333"},"priority":"Critical","rule":"Possible Cryptominer Activity","source":"syscall","tags":["container","mitre_command_and_control","mitre_execution"],"time":"2026-07-10T18:32:04.041749620Z"}
```
Debugging note: the first trigger (`nc` to a port with no listener) did **not** fire. On a refused
connection Falco doesn't populate `fd.sport`, so the port indicator had nothing to match. Starting
a listener on 3333 first so the `connect` actually succeeds made `fd.sport=3333` available and the
rule fired.

### Reflection
- **Which 2 indicators and why:** destination port in a known mining-pool set (3333/4444/5555/…)
  and process name matching known miners (`xmrig`, `ethminer`, …), combined with OR. Port catches
  a miner I've never seen by name as long as it talks to a standard pool port; process name catches
  a miner even if it uses a non-standard port. Together they cover the two cheapest, most reliable
  signals without needing metrics.
- **What it misses (false negatives):** a miner talking to a pool over 443 with a generic process
  name (e.g. renamed to `nginx`) evades both indicators — obfuscated mining over HTTPS to port 443
  looks like ordinary web traffic. Proxy-through-pool services and encrypted Stratum-over-TLS also
  slip past a port/name rule. Catching those needs behavioural signals (sustained high CPU + low
  network, or DNS analytics) that this rule intentionally doesn't cover.
- **Combining with the SLA matrix (Lecture 9):** this rule is `priority: CRITICAL`. Under the
  severity SLA matrix that maps to the 24h / page-on-creation lane — a Critical runtime detection
  should page the on-call immediately, not sit in a backlog. Runtime is the last line of defense,
  so an active-exploitation signal like a live mining connection is exactly the case the tightest
  SLA tier exists for.
