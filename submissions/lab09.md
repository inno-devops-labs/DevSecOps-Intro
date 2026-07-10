# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
<No JSON alert available. Falco is non-functional on this platform (macOS Sonoma 14.6.1 / Apple Silicon / Docker 29.5.2 inside Colima 0.10.3, using `falcosecurity/falco:0.43.1-debian`). Even after switching from Docker Desktop to Colima as the lab's Setup section recommends, the Colima VM kernel is missing the tracepoints Falco needs for the modern eBPF probe. Falco starts (`Loaded event sources: syscall`, `Enabled event sources: syscall`, `Starting health webserver ... on 0.0.0.0:8765`, `Opening 'syscall' source with modern BPF probe`) but fails to attach any syscall tracepoint. Selected lines from `labs/lab9/results/falco-startup.log`:
```
[libs]: libbpf: failed to determine tracepoint 'syscalls/sys_enter_creat' perf event ID: No such file or directory
[libs]: libbpf: failed to determine tracepoint 'syscalls/sys_enter_open' perf event ID: No such file or directory
[libs]: libbpf: failed to determine tracepoint 'syscalls/sys_enter_mkdir' perf event ID: No such file or directory
[libs]: libbpf: failed to determine tracepoint 'syscalls/sys_enter_unlink' perf event ID: No such file or directory
[libs]: libbpf: failed to determine tracepoint 'syscalls/sys_enter_chmod' perf event ID: No such file or directory
```Empirically confirmed: triggered `docker exec lab9-target sh -c "echo shell-in-container-triggered"` (canonical "Terminal shell in container" event), and `docker logs falco 2>&1 | grep -i "shell\|terminal\|spawned"` returned nothing. The `Terminal shell in container` rule is present in `/etc/falco/falco_rules.yaml` (grepped) but never fires because the `execve` syscall is invisible to the probe>
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
<No JSON alert available. Same root cause as alert A — Falco's `open`/`openat` syscall probes did not attach on the Colima VM kernel, so any `cat /etc/shadow` inside a container never reaches the ruleset. In a working environment the built-in `Read sensitive file untrusted` rule matches on `evt.type in (open, openat) and fd.name in sensitive_files and not proc.name in user_trusted_containers` — the exact conditions our tracepoint errors block>
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
<No custom Falco YAML rule shipped in this submission. Because Falco cannot see any syscall on this platform (evidence above), authoring a Falco YAML rule with no way to run it against real events would be untested code. Instead, I moved the miner-detection use case to a Conftest rule that can actually be exercised — see the Bonus section below. The tuning discussion (next subsection) still applies conceptually>
```

### Custom rule fired
Falco log line showing your custom rule:
```json
<Not applicable>
```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks
often write to /tmp). What's your tuning approach? (2-3 sentences referencing the
`exceptions:` block vs `and not proc.name=...` patterns from Lecture 9.)

## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
<File path used: `labs/lab9/policies/extra/k8s-security-extra.rego` (subdir `extra/` per lab Setup, `.rego` filename per convention with the shipped `k8s-security.rego`), package `k8s.security.extra`:
```rego
package k8s.security.extra

has_value(arr, v) if {
  some i
  arr[i] == v
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  drops := object.get(c, ["securityContext", "capabilities", "drop"], [])
  not has_value(drops, "ALL")
  msg := sprintf("container %q must drop ALL capabilities", [c.name])
}
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q must set resources.limits.memory", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image %q must be pinned by sha256 digest", [c.name, c.image])
}>
```

### Compliant manifest passes (juice-hardened.yaml)
```
<6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions>
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
<FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security.extra - container "juice" image "bkimminich/juice-shop:latest" must be pinned by sha256 digest
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security.extra - container "juice" must drop ALL capabilities
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security.extra - container "juice" must set resources.limits.memory

6 tests, 3 passed, 0 warnings, 3 failures, 0 exceptions>
```

### Compose policy generalizes (shipped compose-security.rego)
```
<PASS on `juice-compose.yml`:
```
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions
```
FAIL on `/tmp/bad-compose.yml` (minimal `services: { bad: { image: nginx:latest } }`):
```
WARN - /tmp/bad-compose.yml - compose.security - services should enable no-new-privileges
FAIL - /tmp/bad-compose.yml - compose.security - services must drop ALL capabilities
FAIL - /tmp/bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - /tmp/bad-compose.yml - compose.security - services must set read_only: true

4 tests, 0 passed, 1 warning, 3 failures, 0 exceptions
```
Same `deny contains msg if { svc := input.services[_]; ... }` pattern that catches the Kubernetes `containers[_]` shape catches the Compose `services[_]` shape.>
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
2-3 sentences. CI-time Conftest happens during PR review; admission-time Conftest happens at
`kubectl apply`. What's the operational benefit of running BOTH (defense in depth)?
Slide 9 ("Policy-as-Code: Hardening Before Deploy") frames both stages as the same policy engine at two enforcement points: "Conftest is CLI/CI; the same Rego runs server-side as a Gatekeeper or Kyverno webhook (Kyverno uses its own DSL, but the role is identical)." CI-time Conftest fails the PR before the manifest ever reaches the cluster — fast feedback, cheap to fix, and it catches the "we forgot resources.limits.memory again" class before merge. Admission-time Conftest catches the class CI cannot: manifests that bypass PR review (hotfixes, generated Helm output, `kubectl apply` from a laptop), or manifests that were compliant at PR time but got hand-edited before apply. The defence-in-depth benefit the slide points at is that a single Rego file stays enforceable at both the human-review boundary and the API-server boundary — the flow `K8s YAML → conftest test → policy/*.rego → fail/pass` runs identically in CI and in the admission webhook, so the rule text is written once and neither gate alone is enough.

## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
<Because Falco is non-functional on this platform (see Task 1 evidence), I implemented the miner detector as a Conftest / Rego shift-left rule instead. It lives in `labs/lab9/policies/extra/crypto-miner.rego` under the same `k8s.security.extra` namespace:
```rego
package k8s.security.extra

miner_indicators := [
  "xmrig",
  "cpuminer",
  "cgminer",
  "minerd",
  "monero",
  "stratum+tcp",
  "--donate-level",
  "pool.minexmr.com",
]
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  cmd := array.concat(c.command, c.args)
  arg := cmd[_]
  ind := miner_indicators[_]
  contains(lower(arg), lower(ind))
  msg := sprintf("container %q command/args contain crypto-miner indicator %q", [c.name, ind])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  ind := miner_indicators[_]
  contains(lower(c.image), lower(ind))
  msg := sprintf("container %q image %q contains crypto-miner indicator %q", [c.name, c.image, ind])
}>
```

### Triggered alert
```json
<Not `nc`-triggered (no runtime detector), but shown to fire against a purpose-built test manifest `labs/lab9/manifests/k8s/juice-miner-attack.yaml` (Juice Shop image but with `command: [xmrig]`, `args: [--donate-level, 1, -o, stratum+tcp://pool.minexmr.com:4444]`):
```
FAIL - k8s.security.extra - container "juice" command/args contain crypto-miner indicator "--donate-level"
FAIL - k8s.security.extra - container "juice" command/args contain crypto-miner indicator "pool.minexmr.com"
FAIL - k8s.security.extra - container "juice" command/args contain crypto-miner indicator "stratum+tcp"
FAIL - k8s.security.extra - container "juice" command/args contain crypto-miner indicator "xmrig"

5 tests, 1 passed, 0 warnings, 4 failures, 0 exceptions
```
Re-run on `juice-hardened.yaml`: `10 tests, 10 passed, 0 warnings, 0 failures` — no false positives on a clean deployment.>
```

### Reflection (2-3 sentences)
- Which 2 indicators did you use and why?
xmrig (the process/binary name of the dominant Monero miner) and stratum+tcp (the mining-pool protocol scheme every miner needs to reach a pool) — one indicator is process-identity, the other is behavioural intent, so an attacker has to defeat both to
- What does this miss? (i.e., the false-negative case — e.g., obfuscated mining over HTTPS)
Obfuscated mining over HTTPS to a pool that terminates the `stratum` protocol server-side, or a miner renamed away from `xmrig` and shipped as a raw binary in the image layers (my rule reads `command`/`args`/`image` strings, not `image` filesystem contents). Also any miner that never appears in the manifest at all — dropped in at runtime by an already-compromised container
- How would you combine this with the Lecture 9 SLA matrix?
lide 4 ("Shift-Left ≠ Shift-Only-Left") opens with Liz Rice: "You can shift left as far as you want — attackers still get to attack the running system", and closes with the point that "each stage catches a different failure class. Runtime is the last line of defense — and the only one that sees what an attacker actually does". My Conftest miner rule occupies the Deploy row ("Policy-as-code, supply-chain verify") and catches the manifest-time failure class: any PR that hard-codes `xmrig` or `stratum+tcp` in `command`/`args`/`image` fails at CI or admission. A Falco version of the same rule (`proc.name in ("xmrig","minerd") or proc.args contains "stratum+tcp"`) occupies the Runtime row ("Behavior detection, anomaly") and covers the failure class slide 4 flags as unreachable from earlier stages — the miner binary downloaded after admission from an image that looked clean at deploy time, which is literally "what an attacker actually does" once inside a running container