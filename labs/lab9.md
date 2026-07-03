# Lab 9 — Runtime Detection (Falco) + Policy-as-Code (Conftest)

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Runtime%20%2B%20PaC-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Falco%20%2B%20Conftest-informational)

> **Goal:** Run Falco with modern eBPF, trigger baseline + custom alerts, then write Conftest/Rego policies that gate Kubernetes manifests at CI time. (Bonus) Write a Falco rule that detects a specific attacker pattern.
> **Deliverable:** A PR from `feature/lab9` with `submissions/lab9.md` + custom Falco rule(s) + Conftest policies. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- **Falco v0.43.x** runtime detection via modern eBPF (Lecture 9 slides 5-8)
- **Custom Falco rules** with `condition:` + `exceptions:` (Lecture 9 slide 8)
- **Conftest / Rego** for K8s admission policy (Lecture 9 slides 9-10)
- (Bonus) **Cryptominer-style detection** — a Falco rule that catches network egress to known mining-pool patterns

> Lecture 9 slide 6 — Falco is "the runtime equivalent of grep — fast, predictable, composable." This lab is where you actually wield it.

---

## Project State

**You should have from Labs 1-8:**
- Juice Shop image (Lab 1), hardened K8s deployment from Lab 7 (or you'll re-deploy)
- Lab 7's Conftest preview (this lab goes deep on it)

**This lab adds:**
- Falco running in a container with custom rules
- Captured Falco alerts proving runtime detection works
- Conftest policies gating ≥3 hardening requirements at CI time

---

## Setup

You need:
- **Docker** (Falco runs containerized)
- **`jq`**
- **`conftest`** v0.68.x — `brew install conftest` (Lab 7 bonus used this if you did it)
- **A Linux kernel with eBPF + BTF** (for Falco's modern driver). Native Linux and WSL2 (kernel ≥ 5.8) work out of the box. **macOS — including Apple Silicon — does NOT work through Docker Desktop**: its LinuxKit VM kernel ships without BTF, so Falco runs but detects nothing. Use **Colima** instead — see Common Pitfalls → "macOS / Apple Silicon"

```bash
git switch main && git pull
git switch -c feature/lab9

# Verify
docker --version && conftest --version

mkdir -p labs/lab9/{falco/{rules,logs},policies/extra,analysis}
```

> **Plumbing provided** (already in `labs/lab9/`):
> - [`labs/lab9/manifests/`](lab9/manifests/) — `k8s/juice-{hardened,unhardened}.yaml` + `compose/juice-compose.yml`
> - [`labs/lab9/policies/`](lab9/policies/) — starter Conftest policies for both shapes (`k8s-security.rego`, `compose-security.rego`)
>
> Read these files before writing your own — they show the Rego style + sample manifest shape.

---

## Task 1 — Runtime Detection with Falco (6 pts)

**Objective:** Run Falco against a target container, trigger 2 baseline alerts + 1 custom alert.

### 9.1: Start the target container

```bash
docker run -d --name lab9-target alpine:3.20 sleep 1d
```

### 9.2: Run Falco with modern eBPF

```bash
docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:0.43.1 \
  falco -U \
        -o json_output=true \
        -o time_format_iso_8601=true

# Follow Falco logs in a separate terminal OR background it
docker logs -f falco > labs/lab9/falco/logs/falco.log 2>&1 &
LOGS_PID=$!
echo "Falco logs tail PID: $LOGS_PID — kill it when done"

# Give Falco a moment to initialize
sleep 5
```

### 9.3: Trigger 2 baseline alerts

```bash
# Trigger A: Terminal shell in container — built-in rule
docker exec -it lab9-target /bin/sh -lc 'echo "shell-in-container test"'

# Trigger B: Read a sensitive file — built-in "Read sensitive file untrusted" rule
docker exec lab9-target /bin/sh -lc 'cat /etc/shadow'

# Wait a few seconds, then check Falco alerts
sleep 3
grep -E "(Terminal shell|Read sensitive file)" labs/lab9/falco/logs/falco.log | head -10
```

### 9.4: Write 1 custom Falco rule

Create `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
# YOUR TASK: Write a custom Falco rule
# Requirements (Lecture 9 slide 7):
#   - rule: "Write to /tmp by container"
#   - condition: detects writes to /tmp inside any container (NOT host)
#   - output: should include container.name + user.name + fd.name + proc.cmdline
#   - priority: WARNING
#   - tags: [container, drift]
#
# Hint: Falco ships the `open_write` macro — read it inside the container:
#       docker exec falco cat /etc/falco/falco_rules.yaml | grep -A2 'macro: open_write'
#       Your rule combines open_write + a container check (container.id != host) +
#       fd.name startswith /tmp/.
```

Falco auto-reloads rules in `/etc/falco/rules.d/`. To force reload after editing:

```bash
docker kill --signal=SIGHUP falco && sleep 3
```

### 9.5: Trigger your custom rule

```bash
docker exec --user 0 lab9-target /bin/sh -lc 'echo "test" > /tmp/my-write.txt'
sleep 3
grep "Write to /tmp by container" labs/lab9/falco/logs/falco.log | head -5
```

### 9.6: Document in `submissions/lab9.md`

````markdown
# Lab 9 — Submission

## Task 1: Runtime Detection with Falco

### Baseline alert A — Terminal shell in container
JSON alert from Falco logs (paste the most relevant lines):
```json
<paste>
```

### Baseline alert B — Read sensitive file untrusted (`cat /etc/shadow`)
```json
<paste>
```

### Custom rule (paste labs/lab9/falco/rules/custom-rules.yaml)
```yaml
<paste full rule>
```

### Custom rule fired
Falco log line showing your custom rule:
```json
<paste>
```

### Tuning consideration (Lecture 9 slide 8)
Your custom "write to /tmp" rule will fire on legitimate uses too (logging frameworks
often write to /tmp). What's your tuning approach? (2-3 sentences referencing the
`exceptions:` block vs `and not proc.name=...` patterns from Lecture 9.)
````

---

## Task 2 — Conftest Policy-as-Code (4 pts)

> ⏭️ Optional. Skipping won't affect future labs.

**Objective:** Write Rego policies for Conftest that catch ≥3 K8s manifest hardening issues at CI time, then run the shipped compose policy to see the same `deny[msg]` skill generalize to a second target shape.

### 9.7: Read the provided manifests + starter policies

```bash
ls labs/lab9/manifests/k8s/
# Should show: juice-hardened.yaml (compliant), juice-unhardened.yaml (non-compliant)

ls labs/lab9/policies/
# Two starter policies, one per target shape:
#   k8s-security.rego      (package k8s.security)     — K8s Deployments (input.spec.template.spec)
#   compose-security.rego  (package compose.security) — docker-compose  (input.services)

cat labs/lab9/policies/*.rego
# Read both — note how the SAME deny[msg] pattern adapts to two different input shapes.
# Task 2 has you EXTEND the K8s one (9.8) and RUN the compose one (9.9).
```

### 9.8: Write your Conftest policies

Add to `labs/lab9/policies/extra/`:

```rego
# labs/lab9/policies/extra/hardening.rego
# YOUR TASK: Rego policies for 3+ K8s hardening rules
# Required denies (one Rego rule per requirement):
#   1. runAsNonRoot must be true (pod-level or container-level securityContext)
#   2. allowPrivilegeEscalation must be false (every container)
#   3. capabilities.drop must include "ALL" (every container)
#   4. (optional 4th) resources.limits.memory must be set
#   5. (optional 5th) image must use sha256: digest, not :tag
#
# Hints:
#   - Lecture 9 slide 10 shows the deny[msg] pattern
#   - `not <something>` is your friend
#   - For arrays: `not "ALL" in container.securityContext.capabilities.drop`
#     (requires Rego v1 — recent OPA/Conftest versions)
```

### 9.9: Run Conftest — your K8s policy + the shipped compose policy

**A. Your K8s policy** (`policies/extra/`) against the shipped manifests:

```bash
# Compliant manifest — should PASS (0 failures)
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml \
  --policy labs/lab9/policies/extra/

# Non-compliant manifest — should FAIL with multiple deny messages
# (juice-unhardened has no securityContext, no resources, and a :latest tag,
#  so it trips several of your rules at once)
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml \
  --policy labs/lab9/policies/extra/
```

**B. The shipped compose policy** — same `deny[msg]` skill, a different target shape.
It declares `package compose.security`, so Conftest needs `--namespace compose.security`
to find its rules (Conftest defaults to the `main` namespace):

```bash
# Shipped hardened compose — should PASS
conftest test labs/lab9/manifests/compose/juice-compose.yml \
  --policy labs/lab9/policies/compose-security.rego \
  --namespace compose.security

# A deliberately unhardened compose — should FAIL (no user / read_only / cap_drop)
cat > /tmp/bad-compose.yml <<'EOF'
services:
  app:
    image: nginx:latest
    ports: ["8080:80"]
EOF
conftest test /tmp/bad-compose.yml \
  --policy labs/lab9/policies/compose-security.rego \
  --namespace compose.security
```

### 9.10: Document in `submissions/lab9.md`

````markdown
## Task 2: Conftest Policy-as-Code

### My policy file (paste labs/lab9/policies/extra/hardening.rego)
```rego
<paste>
```

### Compliant manifest passes (juice-hardened.yaml)
```
<paste conftest output — 0 failures>
```

### Non-compliant manifest fails (juice-unhardened.yaml)
```
<paste conftest output — must show ≥2 distinct deny messages,
 e.g. runAsNonRoot + allowPrivilegeEscalation + dropped capabilities>
```

### Compose policy generalizes (shipped compose-security.rego)
```
<paste both runs — PASS on juice-compose.yml, FAIL on /tmp/bad-compose.yml —
 showing the same deny[msg] pattern works on input.services>
```

### Why CI-time vs admission-time (Lecture 9 slide 9)
2-3 sentences. CI-time Conftest happens during PR review; admission-time Conftest happens at
`kubectl apply`. What's the operational benefit of running BOTH (defense in depth)?
````

---

## Bonus Task — Detect Cryptominer Network Pattern (2 pts)

> 🌟 **Practical & directly maps to real attacks.** The Tesla 2018 incident (Lecture 1 + 6) had cryptominers on an exposed K8s dashboard. This rule would have flagged the egress within minutes.

**Objective:** Write a Falco rule that detects a container connecting to common mining-pool ports/domains.

### B.1: Pick the detection pattern

Common cryptominer indicators (any 2 are sufficient for the rule):

| Indicator | Pattern |
|---|---|
| Connection to mining pool port | `fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700)` |
| DNS query for known pool hostname | `evt.type=connect and fd.sockfamily=ip and fd.cip.name contains "minexmr"` |
| Process name matches known miner | `proc.name in (xmrig, ethminer, cgminer, t-rex, claymore)` |
| High CPU + low network ratio | (Out of scope — needs metrics) |

### B.2: Write the rule

Add to `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
# YOUR TASK: Detect cryptominer network/process pattern
# Requirements:
#   - rule: "Possible Cryptominer Activity"
#   - condition: combines AT LEAST 2 of the indicators above
#   - priority: CRITICAL
#   - tags: [container, mitre_execution, mitre_command_and_control]
#   - output: must include container, process, target (IP/port/name)
```

### B.3: Trigger your rule

Simulating a connection to a typical mining-pool port:

```bash
# Don't actually connect to a real pool — use a netcat to a non-existent local address
docker exec lab9-target /bin/sh -c 'nc -w 2 127.0.0.1 3333' 2>/dev/null || true
sleep 3
grep "Cryptominer" labs/lab9/falco/logs/falco.log
```

### B.4: Document in `submissions/lab9.md`

````markdown
## Bonus: Cryptominer Detection Rule

### Rule (paste)
```yaml
<paste>
```

### Triggered alert
```json
<paste — must show the rule firing on the nc test>
```

### Reflection (2-3 sentences)
- Which 2 indicators did you use and why?
- What does this miss? (i.e., the false-negative case — e.g., obfuscated mining over HTTPS)
- How would you combine this with the Lecture 9 SLA matrix?
````

---

## Cleanup

```bash
# Stop the tail
kill $LOGS_PID 2>/dev/null || true

# Stop containers
docker stop falco lab9-target
docker rm falco lab9-target
```

---

## How to Submit

```bash
git add labs/lab9/falco/rules/custom-rules.yaml
git add labs/lab9/policies/extra/                # Task 2 only
git add submissions/lab9.md
git commit -m "feat(lab9): falco custom rules + conftest hardening policies"
git push -u origin feature/lab9
```

> **Do NOT commit** `labs/lab9/falco/logs/` — log files are large and student-specific. Submission paste-ins are the evidence.

PR checklist body:

```text
- [x] Task 1 — 2 baseline + 1 custom Falco alert with tuning discussion
- [ ] Task 2 — ≥3 Conftest rules (K8s pass/fail) + shipped compose policy run
- [ ] Bonus — Cryptominer detection rule with triggered alert
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Falco running with modern eBPF (verify with `docker logs falco | grep -i engine`)
- ✅ Both baseline alerts (Terminal shell + Read sensitive file) appear in Falco logs
- ✅ Custom rule `custom-rules.yaml` exists with required fields
- ✅ Custom rule fires (visible in Falco log after the test trigger)
- ✅ Tuning consideration mentions `exceptions:` block OR `and not` pattern with reasoning

### Task 2 (4 pts)
- ✅ ≥3 Rego rules in `labs/lab9/policies/extra/`
- ✅ Compliant manifest (`juice-hardened.yaml`) PASSES (0 failures from conftest)
- ✅ Non-compliant manifest (`juice-unhardened.yaml`) FAILS with ≥2 distinct deny messages
- ✅ Shipped `compose-security.rego` run shown — PASS on `juice-compose.yml`, FAIL on a bad compose
- ✅ CI-vs-admission answer demonstrates understanding of defense-in-depth

### Bonus Task (2 pts)
- ✅ Cryptominer rule combines ≥2 indicators (port OR process OR DNS)
- ✅ Rule fires on the `nc` test trigger (visible in Falco log)
- ✅ Reflection covers false-negative case + SLA matrix integration

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Falco runtime | **6** | 2 baseline + 1 custom alert + tuning discussion |
| **Task 2** — Conftest policies | **4** | 3+ Rego rules + K8s good/bad + shipped compose policy run + CI/admission reasoning |
| **Bonus Task** — Cryptominer rule | **2** | 2+ indicators + triggered alert + reflection on FN + SLA |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Falco rules reference](https://falco.org/docs/rules/) — Default rules + macro reference
- [Falco fields reference](https://falco.org/docs/reference/rules/supported-fields/) — All `%evt.*`, `%proc.*`, `%container.*` fields
- [Conftest documentation](https://www.conftest.dev/) — CLI + Rego patterns
- [OPA Rego playground](https://play.openpolicyagent.org/) — 30-min interactive tutorial
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — What your Conftest policies enforce

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **Falco fails to start with "engine.kind not detected"** — your kernel might be < 5.8 (no modern eBPF). Fall back to the legacy eBPF driver: add `-e FALCO_BPF_PROBE=""` to the docker run command.
- 🚨 **macOS / Apple Silicon — Falco starts but detects nothing** — Docker Desktop runs a stripped LinuxKit VM whose kernel ships without BTF (and the raw tracepoints Falco's modern-eBPF probe attaches to), so Falco loads cleanly and stays blind. This is **not** a CPU/arch problem — the image is multi-arch (arm64 included) — it's the VM kernel. Fix: give Falco a real Ubuntu kernel via **Colima** (free, Homebrew, a Lima-based Docker backend whose VM has BTF):
  ```bash
  brew install colima docker
  colima start --cpu 4 --memory 6 --disk 30
  # Gate check — must print "BTF OK" before you bother running Falco:
  colima ssh -- test -f /sys/kernel/btf/vmlinux && echo "BTF OK"
  ```
  Colima becomes your Docker backend, so steps 9.1–9.5 run **unchanged** (clone the repo under your home dir — Colima mounts `$HOME` into the VM). The universal 5-second check for *any* environment: `test -f /sys/kernel/btf/vmlinux` — present ⇒ modern eBPF attaches; absent (Docker Desktop) ⇒ Falco is blind. Task 2 (Conftest) is pure userspace — `brew install conftest` and run it natively on macOS, no VM needed. *(A plain Ubuntu VM via multipass/Lima/UTM works too; Colima is just the least-disruptive since it keeps the Docker CLI workflow.)*
- 🚨 **Falco dies with `could not initialize inotify handler`** — WSL2 / crowded-Docker hosts hit the default `fs.inotify.max_user_instances=128` (same wall as Lab 7). Two fixes: (a) as root, `sysctl -w fs.inotify.max_user_instances=1024`; or (b) if you can't sudo, append `-o watch_config_files=false` to the `falco ...` command — Falco then starts without the file watcher, and you reload rules manually with the `SIGHUP` step below (which doesn't need inotify).
- 🚨 **No alerts fire after triggering** — Falco needs a few seconds to load rules. Wait 5+ seconds between starting Falco and triggering. Also confirm rules loaded with `docker logs falco | grep -i "loaded rule"`.
- 🚨 **Custom rule has YAML parse error and silently doesn't load** — `docker logs falco | grep -i error` shows the parse error. Common cause: indentation. Validate with `yq eval . custom-rules.yaml`.
- 🚨 **`docker kill --signal=SIGHUP falco`** — used to reload rules; if you instead `docker restart falco`, the log file gets truncated.
- 🚨 **Conftest deny message is "Rego_typecheck_error: undefined function..."** — usually old Rego syntax. Conftest 0.68.x supports Rego v1; use `not "ALL" in container.securityContext.capabilities.drop` syntax.
- 🚨 **Cryptominer rule fires on legitimate dev work** — yes. That's the noise/signal tradeoff in Lecture 9 slide 8. The lab's submission requires you to acknowledge this in the reflection.
- 💡 **Read `/etc/falco/falco_rules.yaml`** inside the container before writing your own. `docker exec falco cat /etc/falco/falco_rules.yaml | head -100` shows the default ruleset's macros — your rules will be cleaner if you use the same ones (`open_write`, `container_started`, `proc_is_new`).

</details>

<details>
<summary>🪜 Looking ahead</summary>

- **Lab 10** (DefectDojo) — your Falco alerts can be ingested as a "runtime" finding source alongside Trivy/Grype/Semgrep
- The Conftest policies you wrote are the foundation of admission-time gating (Lecture 9 slide 16). Real production deployments add Kyverno or Sigstore policy-controller; your Rego skills transfer directly.

</details>
