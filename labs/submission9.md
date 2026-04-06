# Lab 9 Submission — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

---

## Task 1 — Runtime Security Detection with Falco

### Setup

Started a helper container (`alpine:3.19`) and ran Falco with modern eBPF in a privileged container. Custom rules were loaded from `labs/lab9/falco/rules/custom-rules.yaml`.

Falco version: **0.43.0** — engine: **modern BPF** (auto-selected)

---

### Baseline Alerts Observed

#### Alert 1 — Terminal shell in container

Triggered by running `docker exec -t lab9-helper /bin/sh -c 'echo hello-tty-shell'`

```json
{
  "output": "2026-04-06T10:52:43.054589880+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -c echo hello-tty-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=530feb29d5fe container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "tags": ["T1059", "container", "mitre_execution", "shell"]
}
```

**What it means:** Someone opened an interactive shell inside a running container. This is suspicious in production — containers should run a single process, not accept shell access. An attacker with exec access could run arbitrary commands.

---

#### Alert 2 — Write Binary Under UsrLocalBin (custom rule, drift)

Triggered by `docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'`

```json
{
  "output": "2026-04-06T10:51:58.597247986+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/drift.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER)",
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "tags": ["compliance", "container", "drift"]
}
```

**What it means:** A file was written to `/usr/local/bin/` inside the container. This is a container drift indicator — the filesystem changed after startup. An attacker could drop a malicious binary there.

---

#### Alert 3 — Custom rule validated (second trigger)

Triggered by `docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'`

```
Rule: Write Binary Under UsrLocalBin | Priority: Warning | Time: 2026-04-06T10:52:54.170720191Z
File: /usr/local/bin/custom-rule.txt
```

This confirms the custom rule fires consistently.

---

### Custom Rule — Write Binary Under UsrLocalBin

**File:** `labs/lab9/falco/rules/custom-rules.yaml`

**When it fires:** Any `open`/`openat`/`openat2`/`creat` syscall that opens a file under `/usr/local/bin/` for writing, inside a container (not the host). Priority: WARNING.

**When it should NOT fire:**
- Reads to `/usr/local/bin/` (read-only access)
- Writes on the host (outside containers)
- Writes to other directories like `/tmp` or `/var`

**Why this matters:** Binaries placed in `/usr/local/bin` are on the PATH and could be executed by any process. Writing there after startup is a sign of container drift or a backdoor attempt.

**Tuning note:** If a legitimate container setup script writes to this path at startup, you can add an exception with `container.name != "my-setup-container"` in the condition to reduce false positives.

---

### Event Generator Results

Ran `falcosecurity/event-generator:latest run syscall`. Falco detected all major simulated attacks:

| Rule | Priority |
|---|---|
| Drop and execute new binary in container | Critical |
| Fileless execution via memfd_create | Critical |
| Detect release_agent File Container Escapes | Critical |
| Execution from /dev/shm | Warning |
| Netcat Remote Code Execution in Container | Warning |
| Read sensitive file untrusted | Warning |
| Search Private Keys or Passwords | Warning |
| Create Symlink Over Sensitive Files | Warning |
| Find AWS Credentials | Warning |
| Clear Log Activities | Warning |
| Remove Bulk Data from Disk | Warning |
| Run shell untrusted | Notice |
| Terminal shell in container | Notice |
| PTRACE anti-debug attempt | Notice |

This confirms Falco is working correctly and can detect a wide range of real attack techniques.

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### 2.1 — Manifest Comparison

**juice-unhardened.yaml** — bare minimum deployment: no security context, no resource limits, uses `:latest` tag. No probes. This is how many teams deploy in a hurry — it works but is totally unsafe.

**juice-hardened.yaml** — applies all best practices:
- Pinned image tag (`v19.0.0`) instead of `:latest`
- `runAsNonRoot: true` — process cannot run as root
- `allowPrivilegeEscalation: false` — cannot gain extra privileges
- `readOnlyRootFilesystem: true` — filesystem is immutable
- `capabilities.drop: ["ALL"]` — all Linux capabilities removed
- CPU and memory requests/limits defined
- readinessProbe and livenessProbe configured

---

### 2.2 — Conftest Policy Review

**k8s-security.rego** — enforces Kubernetes hardening. `deny` rules are hard failures:
- No `:latest` image tags
- Must have `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`
- Must drop ALL capabilities
- Must have CPU/memory requests and limits

`warn` rules are soft guidance:
- Should have readinessProbe and livenessProbe

**compose-security.rego** — enforces Docker Compose hardening:
- Must set explicit non-root `user`
- Must set `read_only: true`
- Must drop ALL capabilities
- Should enable `no-new-privileges`

---

### 2.3 — Conftest Test Results

#### Unhardened K8s Manifest (8 failures, 2 warnings)

```
WARN - container "juice" should define livenessProbe
WARN - container "juice" should define readinessProbe
FAIL - container "juice" missing resources.limits.cpu
FAIL - container "juice" missing resources.limits.memory
FAIL - container "juice" missing resources.requests.cpu
FAIL - container "juice" missing resources.requests.memory
FAIL - container "juice" must set allowPrivilegeEscalation: false
FAIL - container "juice" must set readOnlyRootFilesystem: true
FAIL - container "juice" must set runAsNonRoot: true
FAIL - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

**Why each failure matters:**
- `:latest` tag — image can change between deployments, breaking reproducibility and security audits
- No `runAsNonRoot` — container runs as root, giving full OS-level access if escaped
- No `allowPrivilegeEscalation: false` — child processes can gain root via setuid binaries
- No `readOnlyRootFilesystem` — malware can write files to the container filesystem
- No resource limits — a single pod can starve the entire node (DoS)
- No requests — scheduler cannot place the pod correctly

---

#### Hardened K8s Manifest (all passing)

```
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

All 8 previously failing policies now pass. The hardened manifest satisfies every requirement, including the optional probes (0 warnings).

---

#### Docker Compose Manifest (all passing)

```
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

The `juice-compose.yml` is already compliant:
- `user: "10001:10001"` — runs as non-root
- `read_only: true` — immutable filesystem
- `cap_drop: ["ALL"]` — no Linux capabilities
- `security_opt: no-new-privileges:true` — privilege escalation blocked

---

## Summary

| Task | Status |
|---|---|
| Task 1 — Falco setup + baseline alerts | Done |
| Task 1 — Custom rule (Write Binary Under UsrLocalBin) | Done |
| Task 1 — Event generator run | Done |
| Task 2 — Unhardened manifest fails Conftest | Done (8 failures) |
| Task 2 — Hardened manifest passes Conftest | Done (0 failures) |
| Task 2 — Docker Compose passes Conftest | Done (0 failures) |
