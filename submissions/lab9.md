# Lab 9 — Submission

> **Environment note:** Falco was run under **Colima** (not Docker Desktop). Docker Desktop's LinuxKit VM kernel ships without the BTF + syscall tracepoints Falco's modern-eBPF probe needs, so it loads but detects nothing. Colima's Lima VM has a real Ubuntu kernel — gate check `colima ssh -- test -f /sys/kernel/btf/vmlinux` printed `BTF OK`. One quirk of this kernel: the `sys_enter_connect` tracepoint isn't exposed, so network-`connect` conditions don't fire live; the cryptominer rule below is triggered via its process/cmdline indicator instead (both indicators are defined in the rule).

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
```json
{"priority":"Notice","rule":"Terminal shell in container","output":"A shell was spawned in a container with an attached terminal | evt_type=execve user=root process=sh command=sh -lc echo \"shell-in-container test\" container_id=4a79794f1bf6","output_fields":{"container.id":"4a79794f1bf6","evt.type":"execve","proc.cmdline":"sh -lc echo \"shell-in-container test\"","proc.name":"sh","user.name":"root"},"tags":["T1059","container","maturity_stable","mitre_execution","shell"]}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"priority":"Warning","rule":"Read sensitive file untrusted","output":"Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=openat user=root process=cat command=cat /etc/shadow container_id=4a79794f1bf6","output_fields":{"container.id":"4a79794f1bf6","evt.type":"openat","fd.name":"/etc/shadow","proc.cmdline":"cat /etc/shadow","proc.name":"cat","user.name":"root"},"tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"]}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: >
    Detects any process inside a container writing to a file under /tmp.
    Container filesystems should be immutable at runtime; writes to /tmp
    are a common dropper/staging indicator.
  condition: >
    open_write
    and container
    and fd.name startswith /tmp/
  output: >
    Write under /tmp detected in container
    (file=%fd.name user=%user.name command=%proc.cmdline
     container=%container.name id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [container, drift, filesystem]
```

### Custom rule fired
```json
{"priority":"Warning","rule":"Write to /tmp by container","output":"Write under /tmp detected in container (file=/tmp/my-write.txt user=root command=sh -lc echo \"test\" > /tmp/my-write.txt id=4a79794f1bf6)","output_fields":{"container.id":"4a79794f1bf6","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo \"test\" > /tmp/my-write.txt","user.name":"root"},"tags":["container","drift","filesystem"]}
```

### Tuning consideration (Lecture 9 slide 8)
The "write to /tmp" rule will fire on legitimate uses — logging frameworks, package managers, and language runtimes routinely stage files under `/tmp`. The right tuning tool is an `exceptions:` block rather than piling `and not proc.name=...` clauses into the condition. An `exceptions:` entry (e.g. `- name: known_tmp_writers`, `fields: [proc.name]`, `values: [[pip], [npm], [gunicorn]]`) is maintainable and self-documenting: the exception list is data, appended to as new legitimate writers are discovered, without ever touching the detection logic. Cramming `and not proc.name=pip and not proc.name=npm` into the condition works but degrades into an unreadable one-liner and mixes "what we detect" with "what we allow" — the `exceptions:` block keeps those two concerns cleanly separated (Lecture 9 slide 8).

---

## Task 2: Conftest Policy-as-Code

### My policy file (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main

has_value(arr, v) if {
	some i
	arr[i] == v
}

# Rule 1 — runAsNonRoot (pod OR container level)
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.runAsNonRoot
	not input.spec.template.spec.securityContext.runAsNonRoot
	msg := sprintf("container %q must run as non-root (set runAsNonRoot: true at pod or container level)", [c.name])
}

# Rule 2 — allowPrivilegeEscalation false
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

# Rule 3 — drop ALL capabilities
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not has_value(c.securityContext.capabilities.drop, "ALL")
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

# Rule 4 — memory limit set
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.resources.limits.memory
	msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

# Rule 5 — no :latest tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	endswith(c.image, ":latest")
	msg := sprintf("container %q must not use the mutable :latest tag; pin a version", [c.name])
}

# Rule 6 — image must carry an explicit tag
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, ":")
	msg := sprintf("container %q image must carry an explicit version tag", [c.name])
}
```

### Compliant manifest passes (juice-hardened.yaml)
```
12 tests, 12 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
FAIL - juice-unhardened.yaml - main - container "juice" must not use the mutable :latest tag; pin a version
FAIL - juice-unhardened.yaml - main - container "juice" must run as non-root (set runAsNonRoot: true at pod or container level)
FAIL - juice-unhardened.yaml - main - container "juice" must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - main - container "juice" must set resources.limits.memory

12 tests, 8 passed, 0 warnings, 4 failures, 0 exceptions
```

### Compose policy generalizes (shipped compose-security.rego)
```
# Hardened compose — PASS
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# Bad compose (nginx:latest, no user/read_only) — FAIL
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
The identical `deny contains msg` idiom works against two different input shapes — `input.spec.template.spec.containers[_]` for K8s Deployments and `input.services` for docker-compose — showing the policy skill is shape-agnostic.

### Why CI-time vs admission-time (Lecture 9 slide 9)
CI-time Conftest runs during PR review, giving the developer feedback in the same context they wrote the manifest — before merge, when the fix is cheapest. Admission-time Conftest (via a controller at `kubectl apply`) is the enforcement backstop that also catches anything applied out-of-band — a hotfix applied straight to the cluster, a Helm chart that never went through the repo, or a manifest from a branch that skipped CI. Running both is defense in depth: CI-time shifts the feedback left so problems rarely reach the cluster, while admission-time guarantees that even the manifests that bypass CI still can't land a non-compliant pod — neither layer alone covers both the "caught early" and "caught always" properties.

---

## Bonus: Cryptominer Detection Rule

### Rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Possible Cryptominer Activity
  desc: >
    Detects a container process whose executable path or name matches a
    known cryptominer, OR an outbound connection to a port commonly used
    by mining pools. Two independent indicators raise confidence over
    either signal alone.
  condition: >
    container
    and (
      (evt.type = connect and fd.rport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
      or
      (spawned_process and (
        proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, minerd, nbminer)
        or proc.exepath endswith /xmrig
        or proc.exepath endswith /minerd
        or proc.cmdline contains "stratum+tcp"
      ))
    )
  output: >
    Possible cryptominer activity in container
    (process=%proc.name exe=%proc.exepath command=%proc.cmdline
     connection=%fd.name rport=%fd.rport container=%container.name
     id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control, T1496]
```

### Triggered alert
```json
{"priority":"Critical","rule":"Possible Cryptominer Activity","output":"Possible cryptominer activity in container (process=busybox exe=/bin/busybox command=busybox sleep 5 --url stratum+tcp://pool.minexmr.com:4444 id=4a79794f1bf6)","output_fields":{"container.id":"4a79794f1bf6","proc.cmdline":"busybox sleep 5 --url stratum+tcp://pool.minexmr.com:4444","proc.exepath":"/bin/busybox","proc.name":"busybox"},"tags":["T1496","container","mitre_command_and_control","mitre_execution"]}
```

### Reflection
**Two indicators used:** (1) the mining-pool **destination port** set (3333/4444/5555/…) on an outbound `connect`, and (2) a **process/command signature** — a known miner binary name/path or a `stratum+tcp://` string in the command line (the stratum protocol is the near-universal miner↔pool handshake). Requiring either raises recall; the alert above fired on the `stratum+tcp` cmdline indicator.

**What it misses (false negatives):** A miner that connects over **443/TLS to a pool that fronts as HTTPS** evades both the port list and the plaintext `stratum+tcp` string — the traffic looks like ordinary web egress, and a statically-linked binary renamed to something innocuous (`/usr/bin/nginx-worker`) defeats the name/path checks too. Encrypted, port-443, renamed mining is the blind spot.

**Combining with the Lecture 9 SLA matrix:** This rule is high-severity (CRITICAL) but medium-confidence (the `/tmp` and port heuristics have real false-positive rates), so on the SLA matrix it belongs in the "investigate fast, don't auto-remediate" quadrant — page a human within the CRITICAL SLA window, but pair it with a corroborating signal (sustained high CPU, or the SBOM/attestation checks from Lab 8) before automatically killing the pod. The false-negative gap (TLS/443 mining) is exactly what you'd close with a complementary **network-behavioral** detector — flagging sustained high-bandwidth egress to a single endpoint — rather than trying to make this signature-based rule catch everything.
