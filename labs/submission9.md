# Lab 9 Submission — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

**Student:** Sarmat  
**Date:** April 5, 2026

---

## Task 1 — Runtime Security Detection with Falco

### Setup

Started helper container and Falco with modern eBPF:

```bash
docker run -d --name lab9-helper alpine:3.19 sleep 1d

docker run -d --name falco --privileged \
  -v /proc:/host/proc:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true
```

Falco loaded successfully with modern BPF probe and validated the custom rule:
```
/etc/falco/falco_rules.yaml | schema validation: ok
/etc/falco/rules.d/custom-rules.yaml | schema validation: ok
Opening 'syscall' source with modern BPF probe.
```

### Baseline Alert 1 — Terminal Shell in Container

**Trigger:**
```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**Falco Alert:**
```json
{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "output": "A shell was spawned in a container with an attached terminal",
  "output_fields": {
    "container.name": "lab9-helper",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "user.name": "root",
    "evt.type": "execve"
  },
  "tags": ["T1059", "container", "mitre_execution", "shell"],
  "time": "2026-04-05T15:22:46Z"
}
```

**Why it matters:** Spawning an interactive shell inside a running container is a classic attacker technique (MITRE T1059). In production, containers should never need interactive shells — if one appears, it likely means an attacker has gained code execution and is exploring the environment.

### Baseline Alert 2 — Custom Rule: Write Binary Under UsrLocalBin

**Trigger:**
```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

**Falco Alert:**
```json
{
  "rule": "Write Binary Under UsrLocalBin",
  "priority": "Warning",
  "output": "Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/drift.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY)",
  "tags": ["compliance", "container", "drift"],
  "time": "2026-04-05T15:22:58Z"
}
```

### Custom Rule Validation

**Trigger:**
```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

**Falco Alert:**
```json
{
  "rule": "Write Binary Under UsrLocalBin",
  "priority": "Warning",
  "output": "Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/custom-rule.txt)",
  "time": "2026-04-05T15:23:01Z"
}
```

### Custom Rule Analysis

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and
             evt.is_open_write=true and
             fd.name startswith /usr/local/bin/ and
             container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name
    user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

**When it SHOULD fire:**
- Any write to `/usr/local/bin/` inside a container
- Attacker dropping a backdoor binary
- Container drift — image content changing at runtime

**When it should NOT fire:**
- Writes on the host (excluded by `container.id != host`)
- Reads from `/usr/local/bin/` (only write events match)
- Writes to other directories like `/usr/bin/` or `/tmp/`

**Tuning notes:** In a real environment you might add exceptions for specific trusted containers (e.g., init containers that legitimately install tools) using `and container.name != "trusted-init"`.

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### Unhardened Manifest Results

```
WARN - juice-unhardened.yaml - container "juice" should define livenessProbe
WARN - juice-unhardened.yaml - container "juice" should define readinessProbe
FAIL - juice-unhardened.yaml - container "juice" missing resources.limits.cpu
FAIL - juice-unhardened.yaml - container "juice" missing resources.limits.memory
FAIL - juice-unhardened.yaml - container "juice" missing resources.requests.cpu
FAIL - juice-unhardened.yaml - container "juice" missing resources.requests.memory
FAIL - juice-unhardened.yaml - container "juice" must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - container "juice" must set readOnlyRootFilesystem: true
FAIL - juice-unhardened.yaml - container "juice" must set runAsNonRoot: true
FAIL - juice-unhardened.yaml - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures
```

**Analysis of each violation:**

| Violation | Security Impact |
|-----------|----------------|
| `:latest` tag | Non-deterministic deployments — different image may be pulled each time, breaking reproducibility and potentially pulling a compromised image |
| `runAsNonRoot: false` | Container runs as root (UID 0) — if exploited, attacker has root inside container and easier path to host escape |
| `allowPrivilegeEscalation: true` | Process can gain more privileges via setuid binaries (e.g., `sudo`) — enables privilege escalation attacks |
| `readOnlyRootFilesystem: false` | Attacker can write malware, modify configs, or persist backdoors to the container filesystem |
| Missing resource limits | Container can consume all host CPU/memory — enables DoS attacks and noisy neighbor problems |
| Missing probes | Kubernetes cannot detect unhealthy containers and route traffic away — availability impact |

### Hardened Manifest Results

```
15 tests, 15 passed, 0 warnings, 0 failures
```

All policies pass. The hardened manifest addresses every violation:

| Fix Applied | How it satisfies the policy |
|-------------|----------------------------|
| `image: bkimminich/juice-shop:v19.0.0` | Pinned tag — deterministic, auditable |
| `runAsNonRoot: true` | Container cannot run as root |
| `allowPrivilegeEscalation: false` | Blocks setuid privilege escalation |
| `readOnlyRootFilesystem: true` | Filesystem immutable at runtime |
| `capabilities.drop: ["ALL"]` | Removes all Linux capabilities |
| `resources.requests/limits` | CPU and memory bounded |
| `readinessProbe` + `livenessProbe` | Health checks defined |

### Docker Compose Manifest Results

```
15 tests, 15 passed, 0 warnings, 0 failures
```

The compose manifest is already hardened with:
- `user: "10001:10001"` — explicit non-root user
- `read_only: true` — immutable filesystem
- `cap_drop: ["ALL"]` — all capabilities dropped
- `security_opt: [no-new-privileges:true]` — privilege escalation blocked
- `tmpfs: ["/tmp"]` — writable temp directory without filesystem write access

### Key Takeaway

Policy-as-code with Conftest enforces security baselines automatically and consistently. The unhardened manifest had 8 hard failures that would be blocked in a CI/CD pipeline, while the hardened manifest passes all checks. This shift-left approach catches misconfigurations before they reach production — the same issues that Falco would detect at runtime are prevented at the deployment stage.
