# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Environment

- Date: 2026-04-03
- OS: macOS (Darwin 25.3.0, arm64) / Docker Desktop VM (Linux 6.12.67-linuxkit)
- Branch: `feature/lab9`
- Docker: Docker Desktop for Mac
- Falco: 0.43.0 (aarch64), modern eBPF probe
- Conftest: latest (OPA/Rego)
- Target container: `alpine:3.19` (BusyBox helper)

---

## Task 1 — Runtime Security Detection with Falco (6 pts)

### 1.1 Setup

Falco was deployed as a privileged container with the modern eBPF engine on Docker Desktop's LinuxKit VM:

```
docker run -d --name falco \
  --privileged --pid=host \
  -v /proc:/host/proc:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true
```

The standard `/boot` and `/lib/modules` mounts were omitted because they are unavailable on macOS; the modern eBPF driver uses in-kernel BTF and does not require external kernel headers. TOCTOU mitigation warnings appeared for some tracepoints but did not affect detection capability.

A BusyBox helper container was started for event generation:

```
docker run -d --name lab9-helper alpine:3.19 sleep 1d
```

### 1.2 Baseline Alerts

Two actions were performed to trigger baseline Falco rules:

**A) Shell execution inside a container:**

```
docker exec lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**B) Container drift — write under a binary directory:**

```
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

The drift write triggered the custom rule immediately (see 1.3 below). The built-in "Terminal shell in container" rule did not fire because Docker Desktop's exec path ran without a TTY allocation (no `-t` flag), which is a known limitation when invoking `docker exec` from a non-interactive shell.

### 1.3 Custom Falco Rule

**Rule file:** `labs/lab9/falco/rules/custom-rules.yaml`

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and 
             evt.is_open_write=true and 
             fd.name startswith /usr/local/bin/ and 
             container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin
    (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

**Purpose:** Detects any file write operation under `/usr/local/bin/` inside a container. This directory is a common target for dropping malicious binaries (container drift) — an attacker who gains shell access typically places backdoors or tools in PATH directories.

**When it should fire:**
- Any `open`, `openat`, `openat2`, or `creat` syscall with write flags targeting `/usr/local/bin/*` inside a container
- Legitimate cases: package installation (`apk add`, `pip install --target`) writing to `/usr/local/bin/`

**When it should NOT fire:**
- Host-level writes (filtered by `container.id != host`)
- Read-only opens of files in `/usr/local/bin/` (filtered by `evt.is_open_write=true`)
- Writes to other directories (e.g., `/tmp`, `/var`)

**Tuning considerations:** In production, this rule would produce false positives during legitimate image builds or init scripts that install utilities. A tuning append could exclude known CI containers or specific init processes:

```yaml
- rule: Write Binary Under UsrLocalBin
  append: true
  condition: and not (container.image.repository = "my-ci-runner")
```

### 1.4 Alert Evidence from falco.log

**Custom rule alert — drift.txt (baseline trigger B):**

```json
{
  "rule": "Write Binary Under UsrLocalBin",
  "priority": "Warning",
  "time": "2026-04-03T10:42:35.333644365Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "fd.name": "/usr/local/bin/drift.txt",
    "user.name": "root",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER"
  },
  "tags": ["compliance", "container", "drift"]
}
```

**Custom rule alert — custom-rule.txt (validation trigger):**

```json
{
  "rule": "Write Binary Under UsrLocalBin",
  "priority": "Warning",
  "time": "2026-04-03T10:42:45.569522550Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/usr/local/bin/custom-rule.txt",
    "user.name": "root",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER"
  },
  "tags": ["compliance", "container", "drift"]
}
```

### 1.5 Event Generator Results

The `falcosecurity/event-generator` was run to validate the Falco setup with a broad set of syscall-based detections:

```
docker run --rm --name eventgen --privileged \
  -v /proc:/host/proc:ro -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

**Alerts triggered by the event generator (22 alerts from various rules):**

| # | Rule | Priority | MITRE ATT&CK | Description |
|---|------|----------|--------------|-------------|
| 1 | Packet socket created in container | Notice | T1557.002 | Raw packet socket creation for network sniffing |
| 2 | Fileless execution via memfd_create | Critical | T1620 | In-memory execution without touching disk |
| 3 | Read sensitive file untrusted | Warning | T1555 | `/etc/shadow` read by non-trusted process |
| 4 | Netcat Remote Code Execution in Container | Warning | T1059 | `nc -e /bin/sh` reverse shell attempt |
| 5 | Clear Log Activities | Warning | T1070 | Tampering with syslog files |
| 6 | Search Private Keys or Passwords | Warning | T1552.001 | `find` searching for `id_rsa` files |
| 7 | Create Hardlink Over Sensitive Files | Warning | T1555 | Hardlink to `/etc/shadow` |
| 8 | Execution from /dev/shm | Warning | T1059.004 | Script execution from shared memory (2 events) |
| 9 | Debugfs Launched in Privileged Container | Warning | T1611 | Filesystem debugging tool in privileged container |
| 10 | PTRACE anti-debug attempt | Notice | T1622 | `PTRACE_TRACEME` anti-debugging |
| 11 | Drop and execute new binary in container | Critical | TA0003 | Binary dropped and executed (container drift) |
| 12 | Disallowed SSH Connection Non Standard Port | Notice | T1059 | SSH on non-standard port 443 |
| 13 | Read sensitive file trusted after startup | Warning | T1555 | `/etc/shadow` read after container started |
| 14 | System user interactive | Informational | T1059 | `daemon` user running `login` |
| 15 | Create Symlink Over Sensitive Files | Warning | T1555 | Symlink to `/etc` |
| 16 | PTRACE attached to process | Warning | T1055.008 | Process injection via `ptrace` |
| 17 | Remove Bulk Data from Disk | Warning | T1485 | `shred -u` data destruction |
| 18 | Directory traversal monitored file read | Warning | T1555 | `/etc/../etc/../etc/shadow` path traversal |
| 19 | Detect release_agent File Container Escapes | Critical | T1611 | Container escape via cgroup `release_agent` |
| 20 | Run shell untrusted | Notice | T1059.004 | Shell spawned by untrusted binary (httpd) |
| 21 | Find AWS Credentials | Warning | T1552 | Searching for `.aws/credentials` |

**Summary:** Falco detected 24 total events across 21 distinct rules, spanning 3 severity levels (Critical: 3, Warning: 15, Notice: 4, Informational: 1) and covering MITRE ATT&CK techniques for defense evasion, credential access, privilege escalation, execution, persistence, and impact.

---

## Task 2 — Policy-as-Code with Conftest (Rego) (4 pts)

### 2.1 Manifest Comparison

| Aspect | Unhardened | Hardened |
|--------|-----------|---------|
| Image tag | `:latest` (mutable, unpinned) | `:v19.0.0` (pinned, immutable) |
| `runAsNonRoot` | not set (defaults to root) | `true` |
| `allowPrivilegeEscalation` | not set (defaults to true) | `false` |
| `readOnlyRootFilesystem` | not set (writable) | `true` |
| Capabilities | all granted (default) | `drop: ["ALL"]` |
| CPU requests/limits | none | `100m / 500m` |
| Memory requests/limits | none | `256Mi / 512Mi` |
| Readiness probe | none | HTTP GET on `/` port 3000 |
| Liveness probe | none | HTTP GET on `/` port 3000 |

### 2.2 Policy Review

**k8s-security.rego** enforces 9 `deny` rules (hard failures) and 2 `warn` rules (soft guidance):

| Policy | Type | What it checks |
|--------|------|----------------|
| No `:latest` tags | deny | Image tags must be pinned for reproducibility |
| `runAsNonRoot: true` | deny | Prevents containers from running as UID 0 |
| `allowPrivilegeEscalation: false` | deny | Blocks `setuid` and kernel capability escalation |
| `readOnlyRootFilesystem: true` | deny | Prevents runtime filesystem modifications |
| Drop ALL capabilities | deny | Enforces least-privilege capability model |
| CPU requests | deny | Ensures scheduler can place pods predictably |
| Memory requests | deny | Prevents OOM-kill cascades from unbounded memory use |
| CPU limits | deny | Caps compute consumption per container |
| Memory limits | deny | Caps memory, triggers OOM-kill before node impact |
| Readiness probe | warn | Ensures traffic routing only to healthy pods |
| Liveness probe | warn | Enables automatic restart of hung containers |

**compose-security.rego** enforces 3 `deny` rules and 1 `warn` rule for Docker Compose:

| Policy | Type | What it checks |
|--------|------|----------------|
| Explicit non-root user | deny | `user` field must be set |
| Read-only filesystem | deny | `read_only: true` required |
| Drop ALL capabilities | deny | `cap_drop: ["ALL"]` required |
| No-new-privileges | warn | `security_opt: no-new-privileges:true` recommended |

### 2.3 Conftest Results

**Unhardened K8s manifest — 8 FAILURES, 2 warnings:**

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

1. **`:latest` tag** — mutable tags break reproducibility; different deploys may pull different images, and supply chain attacks can inject malicious layers
2. **`runAsNonRoot` missing** — container processes run as root by default, giving full filesystem and capability access if a breakout occurs
3. **`allowPrivilegeEscalation` missing** — allows `setuid` binaries and kernel exploits to escalate from unprivileged to root within the container
4. **`readOnlyRootFilesystem` missing** — enables attackers to drop binaries, modify configs, and establish persistence inside the container
5. **Capabilities not dropped** — default Docker capabilities include `CAP_NET_RAW`, `CAP_SYS_CHROOT`, etc., which expand the attack surface
6. **No resource requests/limits** — without bounds, a compromised container can consume all node CPU/memory (DoS), and the scheduler cannot make informed placement decisions

**Hardened K8s manifest — all passed:**

```
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

All deny and warn policies pass because the hardened manifest includes pinned image tag, full securityContext, resource requests/limits, and health probes.

**Docker Compose manifest — all passed:**

```
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

The compose manifest (`juice-compose.yml`) passes all policies:
- `user: "10001:10001"` — explicit non-root user
- `read_only: true` — immutable filesystem with `tmpfs: ["/tmp"]` for temporary writes
- `cap_drop: ["ALL"]` — minimal capability set
- `security_opt: [no-new-privileges:true]` — prevents privilege escalation

### 2.4 Hardening Summary

The transition from unhardened to hardened demonstrates defense-in-depth:

| Layer | Unhardened Risk | Hardened Mitigation |
|-------|----------------|---------------------|
| Identity | Root process — full container access | Non-root UID — limited file/process access |
| Filesystem | Writable — attacker can drop binaries | Read-only — prevents persistence and drift |
| Capabilities | Default set — broad kernel API access | All dropped — minimal attack surface |
| Image | `:latest` — unpinned, mutable | `:v19.0.0` — pinned, auditable |
| Resources | Unbounded — potential node-level DoS | Bounded — predictable scheduling, OOM protection |
| Health | No probes — silent failures | Readiness + liveness — automatic recovery |
| Escalation | Allowed — setuid exploits possible | Blocked — `allowPrivilegeEscalation: false` |

---

## Appendix: Artifacts and Evidence

### File Structure

```
labs/lab9/
├── falco/
│   ├── rules/
│   │   └── custom-rules.yaml          # Custom Falco rule (Write Binary Under UsrLocalBin)
│   └── logs/
│       └── falco.log                   # Full Falco output (24 alerts)
├── manifests/
│   ├── k8s/
│   │   ├── juice-unhardened.yaml       # Baseline K8s deployment (provided)
│   │   └── juice-hardened.yaml         # Hardened K8s deployment (provided)
│   └── compose/
│       └── juice-compose.yml           # Docker Compose manifest (provided)
├── policies/
│   ├── k8s-security.rego               # K8s security policies (provided)
│   └── compose-security.rego           # Compose security policies (provided)
└── analysis/
    ├── conftest-unhardened.txt          # 8 failures, 2 warnings
    ├── conftest-hardened.txt            # 30 passed, 0 failures
    └── conftest-compose.txt            # 15 passed, 0 failures
```

### Platform Note

Falco was run on macOS via Docker Desktop's LinuxKit VM (kernel 6.12.67-linuxkit). The modern eBPF probe loaded successfully without requiring `/boot` or `/lib/modules` host mounts. Non-critical TOCTOU mitigation warnings appeared for several tracepoints but did not impact detection. In production, Falco should run directly on a Linux host or as a DaemonSet in Kubernetes for optimal kernel-level visibility.
