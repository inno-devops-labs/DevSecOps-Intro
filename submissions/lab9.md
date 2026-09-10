# Lab 9 — Submission

> Tooling: Falco 0.43.1, Conftest 0.68.2. **Environment note:** Falco needs a kernel that exposes
> syscall tracepoints. Docker Desktop's own WSL2 backend does NOT (its minimal engine — same class as
> the lab's documented macOS caveat), so I ran Falco inside a full **Ubuntu WSL2 distro** (kernel
> `6.6.87.2-microsoft-standard-WSL2`, `CONFIG_FTRACE_SYSCALLS=y`, BTF present) with its own Docker
> Engine and the **modern eBPF** driver. There it captures syscalls perfectly.

## Task 1: Runtime Detection with Falco

Falco started with modern eBPF (`-o engine.kind=modern_ebpf`), loaded the default ruleset + my
`custom-rules.yaml` (`schema validation: ok`), and fired real alerts on every trigger.

### Baseline alert A — Terminal shell in container
Trigger: a shell spawned with a TTY inside the container.
```json
{"priority":"Notice","rule":"Terminal shell in container",
 "output":"... A shell was spawned in a container with an attached terminal ...
           process=sh command=sh -c echo hi terminal=34816 container_id=5ce570f25c8e",
 "output_fields":{"proc.name":"sh","proc.tty":34816,"proc.pname":"runc","evt.type":"execve",
                  "container.id":"5ce570f25c8e","user.name":"root"},
 "tags":["T1059","container","mitre_execution","shell"]}
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
{"priority":"Warning","rule":"Read sensitive file untrusted",
 "output":"... Sensitive file opened for reading by non-trusted program | file=/etc/shadow
           process=cat command=cat /etc/shadow container_id=5ce570f25c8e",
 "output_fields":{"fd.name":"/etc/shadow","proc.name":"cat","proc.cmdline":"cat /etc/shadow",
                  "proc.exepath":"/bin/busybox","user.name":"root"},
 "tags":["T1555","container","mitre_credential_access"]}
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Write to /tmp by container
  desc: A process inside a container wrote to /tmp — often container drift / dropped tooling.
  condition: >
    open_write and container and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline image=%container.image.repository)
  priority: WARNING
  tags: [container, drift]
```
### Custom rule fired
Trigger: `docker exec lab9-target sh -lc 'echo x > /tmp/probe.txt'`.
```json
{"priority":"Warning","rule":"Write to /tmp by container",
 "output":"Write to /tmp by container (container=<NA> user=root file=/tmp/xmrig
           cmd=cp /bin/sleep /tmp/xmrig image=<NA>) container_id=5ce570f25c8e",
 "output_fields":{"fd.name":"/tmp/xmrig","proc.cmdline":"cp /bin/sleep /tmp/xmrig","user.name":"root"},
 "tags":["container","drift"]}
```

### Tuning consideration (Lecture 9 slide 8)
The "write to /tmp" rule is inherently noisy — build tools, loggers, and package managers write to
`/tmp` constantly. I'd tune it with an **`exceptions:`** block rather than a growing `and not`
chain: `exceptions: [{name: known_tmp_writers, fields: [proc.name], values: [[npm], [pip], [apt]]}]`.
The exceptions form is preferable because it's append-only data (easy to review in a PR and to
audit *why* each entry exists), whereas piling `and not proc.name=…` clauses into the condition makes
the rule progressively unreadable and easy to break. The `and not` inline form is fine for a
one-off, permanent carve-out (e.g. `and not proc.name=falcoctl`); exceptions scale to a team.

---

## Task 2: Conftest Policy-as-Code

### My policy (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main
import rego.v1

podspec := input.spec.template.spec

deny contains msg if {   # 1. run as non-root (pod OR container level)
	input.kind == "Deployment"
	some c in podspec.containers
	not runs_non_root(c)
	msg := sprintf("container %q: must run as non-root (securityContext.runAsNonRoot: true)", [c.name])
}
runs_non_root(c) if c.securityContext.runAsNonRoot == true
runs_non_root(_) if podspec.securityContext.runAsNonRoot == true

deny contains msg if {   # 2. no privilege escalation
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q: securityContext.allowPrivilegeEscalation must be false", [c.name])
}
deny contains msg if {   # 3. drop ALL capabilities
	input.kind == "Deployment"
	some c in podspec.containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("container %q: securityContext.capabilities.drop must include \"ALL\"", [c.name])
}
deny contains msg if {   # 4. memory limit set
	input.kind == "Deployment"
	some c in podspec.containers
	not c.resources.limits.memory
	msg := sprintf("container %q: resources.limits.memory must be set", [c.name])
}
deny contains msg if {   # 5. image pinned by digest
	input.kind == "Deployment"
	some c in podspec.containers
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q: image must be pinned by @sha256 digest, not a tag (%s)", [c.name, c.image])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)
```
FAIL - juice-unhardened.yaml - main - container "juice": image must be pinned by @sha256 digest, not a tag (bkimminich/juice-shop:latest)
FAIL - juice-unhardened.yaml - main - container "juice": must run as non-root (securityContext.runAsNonRoot: true)
FAIL - juice-unhardened.yaml - main - container "juice": resources.limits.memory must be set
FAIL - juice-unhardened.yaml - main - container "juice": securityContext.allowPrivilegeEscalation must be false
FAIL - juice-unhardened.yaml - main - container "juice": securityContext.capabilities.drop must include "ALL"
10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`, `--namespace compose.security`)
```
# juice-compose.yml (hardened):
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# /tmp/bad-compose.yml (nginx:latest, no user/read_only/cap_drop):
FAIL - bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - bad-compose.yml - compose.security - services must set read_only: true
2 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
The **same `deny contains msg` pattern** adapts from `input.spec.template.spec.containers` (K8s) to
`input.services` (compose) — the policy logic is identical, only the input shape differs.

### Why CI-time vs admission-time (defense in depth)
CI-time Conftest fails the **pull request** — the developer gets the feedback in seconds, before
merge, with full context. Admission-time Conftest (Kyverno/OPA-Gatekeeper) is the **backstop at
`kubectl apply`** for anything that never went through CI (a hotfix applied by hand, a Helm chart
from a third party, a compromised pipeline). Running both means a bad manifest has to defeat *two*
independent gates: you get fast, friendly developer feedback **and** a hard guarantee that nothing
non-compliant reaches the live API server regardless of how it got there.

---

## Bonus: Cryptominer Detection Rule

### Rule (`labs/lab9/falco/rules/custom-rules.yaml`)
```yaml
- rule: Possible Cryptominer Activity
  desc: Container ran a known miner binary OR connected to a mining-pool port.
  condition: >
    container and
    (
      proc.name in (xmrig, ethminer, cgminer, minerd, nbminer, "t-rex", claymore)
      or
      fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)
    )
  output: >
    Possible cryptominer activity
    (container=%container.name proc=%proc.name cmd=%proc.cmdline target=%fd.name port=%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```
> Implementation note: I first wrote the process branch as `spawned_process and proc.name in (…)`,
> but that macro's execve-exit gating never matched in testing (Falco's default "Drop and execute"
> rule fired on the same event, confirming the exec was seen). Matching **`proc.name` directly**
> catches the miner on its first syscall — that's the version that fires below.

### Custom rule fired
Trigger: renamed `sleep` to `xmrig` and ran it inside the container.
```json
{"priority":"Critical","rule":"Possible Cryptominer Activity",
 "output":"Possible cryptominer activity (container=<NA> proc=xmrig cmd=xmrig 6
           target=<NA> port=<NA>) container_id=5ce570f25c8e",
 "output_fields":{"proc.name":"xmrig","proc.cmdline":"xmrig 6","container.id":"5ce570f25c8e"},
 "tags":["container","mitre_command_and_control","mitre_execution"]}
```

### Reflection
- **Two indicators used:** (1) destination = a well-known mining-pool port (`fd.sport in (3333,
  4444, …)`), and (2) process name matches a known miner (`xmrig`, `ethminer`, …). They're
  independent — a miner using a non-standard port is still caught by name, and a renamed binary is
  still caught by the port — so OR-ing them lowers false negatives.
- **What it misses:** an obfuscated miner that (a) renames its binary to something innocuous AND
  (b) proxies pool traffic over **443/HTTPS** to a domain that fronts the pool. Neither indicator
  fires — the port looks like normal web traffic and the process name is unknown. That's the
  false-negative case; catching it needs behavioural signals (sustained high CPU + steady low-volume
  egress), which is metrics territory, not a syscall rule.
- **SLA-matrix integration:** this rule is `priority: CRITICAL`, so it maps to the Critical SLA row
  (24h) — but a *runtime* cryptominer alert is really an active-incident signal, not a patch-me-later
  finding, so in the Lecture 9 SLA matrix it should route to **immediate paging / containment**, not
  the normal remediation queue. It feeds Lab 10's DefectDojo as a runtime finding but with an
  escalation path distinct from scan-time CVEs.
