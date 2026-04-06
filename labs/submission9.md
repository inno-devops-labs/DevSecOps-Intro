# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco (6 pts)

### 1.1 Helper Container Setup

Started an Alpine (BusyBox) container to serve as the event source:

```
docker run -d --name lab9-helper alpine:3.19 sleep 1d
```

### 1.2 Falco Deployment

Ran Falco containerized with the modern eBPF engine, mounting host `/proc`, `/boot`, `/lib/modules`, `/usr`, and the Docker socket. Custom rules were mounted from `labs/lab9/falco/rules/`:

```
docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true
```

Logs were tailed to `labs/lab9/falco/logs/falco.log`.

### 1.3 Baseline Alerts

**Alert A — Terminal shell in container (Notice)**

Triggered by: `docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'`

```json
{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "time": "2026-04-06T14:46:02.893950357Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "proc.exepath": "/bin/busybox",
    "user.name": "root",
    "proc.tty": 34816
  }
}
```

This rule detects interactive shell sessions inside containers. In production, interactive shells are almost never legitimate — they indicate an attacker has obtained exec access or a developer is bypassing CI/CD to make live changes.

**Alert B — Container drift: write to binary directory**

Triggered by: `docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'`

This write operation was detected by the custom rule (see section 1.4). Writing to binary directories inside a running container is a strong indicator of container drift — the container's filesystem is being modified at runtime beyond what the image defined. This can indicate malware installation, persistence mechanisms, or unauthorized patching.

### 1.4 Custom Falco Rule

Created `labs/lab9/falco/rules/custom-rules.yaml`:

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

**Purpose:** Detect any file creation or modification under `/usr/local/bin/` inside a container. This directory is a common target for attackers planting backdoor binaries, and legitimate images should never write there at runtime.

**When it should fire:**
- An attacker downloads and installs a tool (e.g., `curl`, reverse shell) into `/usr/local/bin/`
- A misconfigured entrypoint script writes binaries at startup
- Container drift from live patching

**When it should NOT fire:**
- Build-time `RUN` instructions (those happen in the image build, not at runtime)
- Host-side writes (`container.id != host` excludes these)

**Validation — Custom rule triggered:**

```json
{
  "rule": "Write Binary Under UsrLocalBin",
  "priority": "Warning",
  "time": "2026-04-06T14:47:04.726266789Z",
  "output_fields": {
    "container.name": "lab9-helper"
  }
}
```

### 1.5 Event Generator Results

Ran the Falco event generator (`falcosecurity/event-generator:latest run syscall`) to produce a burst of detectable syscall activity. The full log captured **22 distinct rules** across 59 alert lines. Key alerts from the event generator:

| Priority | Rule | Count | Description |
|----------|------|------:|-------------|
| Critical | Fileless execution via memfd_create | 27 | Execution from memory-backed file descriptors (runc internals + eventgen) |
| Critical | Drop and execute new binary in container | 1 | New binary dropped into container and executed |
| Critical | Detect release_agent File Container Escapes | 1 | Attempted container escape via cgroup release_agent |
| Warning | Debugfs Launched in Privileged Container | 1 | Debug filesystem access in privileged container |
| Warning | Netcat Remote Code Execution in Container | 1 | Netcat used for potential reverse shell |
| Warning | Execution from /dev/shm | 2 | Fileless execution via shared memory |
| Warning | Remove Bulk Data from Disk | 1 | Mass file deletion (anti-forensics) |
| Warning | Search Private Keys or Passwords | 1 | Searching for credential files |
| Warning | Find AWS Credentials | 1 | Scanning for cloud credentials |
| Warning | Create Hardlink Over Sensitive Files | 1 | Hardlink-based privilege escalation attempt |
| Warning | Create Symlink Over Sensitive Files | 1 | Symlink-based file access attempt |
| Warning | Directory traversal monitored file read | 1 | Path traversal attack pattern |
| Warning | PTRACE attached to process | 1 | Debugger attachment (code injection) |
| Warning | Read sensitive file untrusted | 1 | Untrusted process reading /etc/shadow etc. |
| Warning | Clear Log Activities | 1 | Log tampering / anti-forensics |
| Notice | Disallowed SSH Connection Non Standard Port | 1 | SSH on non-standard port |
| Notice | Packet socket created in container | 1 | Raw packet capture capability |
| Notice | PTRACE anti-debug attempt | 1 | Anti-debugging evasion technique |
| Notice | Run shell untrusted | 1 | Shell spawned by untrusted parent |

These alerts map to MITRE ATT&CK techniques spanning execution (T1059), defense evasion (T1620), credential access, privilege escalation, and container escape tactics.

---

## Task 2 — Policy-as-Code with Conftest (Rego) (4 pts)

### 2.1 Manifest Comparison

**Unhardened manifest** (`juice-unhardened.yaml`): Bare-minimum deployment — no security context, no resource limits, no health probes, uses `:latest` tag.

**Hardened manifest** (`juice-hardened.yaml`): Adds the following hardening controls:

| Control | Unhardened | Hardened |
|---------|-----------|---------|
| Image tag | `:latest` | `:v19.0.0` (pinned) |
| `runAsNonRoot` | not set | `true` |
| `allowPrivilegeEscalation` | not set | `false` |
| `readOnlyRootFilesystem` | not set | `true` |
| `capabilities.drop` | not set | `["ALL"]` |
| CPU requests/limits | not set | `100m` / `500m` |
| Memory requests/limits | not set | `256Mi` / `512Mi` |
| Readiness probe | not set | HTTP GET `/` on port 3000 |
| Liveness probe | not set | HTTP GET `/` on port 3000 |

### 2.2 Rego Policy Review

**`k8s-security.rego`** enforces 11 rules across two severity levels:

- **deny (hard fail):** `:latest` tag, missing `runAsNonRoot`, missing `allowPrivilegeEscalation: false`, missing `readOnlyRootFilesystem: true`, missing `capabilities.drop: ALL`, missing CPU/memory requests and limits (6 resource rules)
- **warn (soft):** missing `readinessProbe`, missing `livenessProbe`

**`compose-security.rego`** enforces 4 rules for Docker Compose:

- **deny:** missing explicit non-root `user`, missing `read_only: true`, missing `cap_drop: ALL`
- **warn:** missing `no-new-privileges` security option

### 2.3 Conftest Results

#### Unhardened K8s Manifest — 8 failures, 2 warnings

```
WARN  - container "juice" should define livenessProbe
WARN  - container "juice" should define readinessProbe
FAIL  - container "juice" missing resources.limits.cpu
FAIL  - container "juice" missing resources.limits.memory
FAIL  - container "juice" missing resources.requests.cpu
FAIL  - container "juice" missing resources.requests.memory
FAIL  - container "juice" must set allowPrivilegeEscalation: false
FAIL  - container "juice" must set readOnlyRootFilesystem: true
FAIL  - container "juice" must set runAsNonRoot: true
FAIL  - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures
```

**Why each failure matters:**

1. **`:latest` tag** — Non-reproducible deployments; no guarantee of what code is running, makes rollback and auditing impossible.
2. **`runAsNonRoot` missing** — Container runs as root by default, giving an attacker full filesystem and process control if they escape the app.
3. **`allowPrivilegeEscalation` not false** — Child processes can gain more privileges than their parent via setuid/setgid binaries.
4. **`readOnlyRootFilesystem` not true** — Attackers can write malware, modify configs, or plant persistence mechanisms on the container filesystem.
5. **Missing resource limits/requests** — No CPU/memory bounds means a compromised container can DoS the node via resource exhaustion; scheduler cannot make informed placement decisions.

#### Hardened K8s Manifest — all pass

```
30 tests, 30 passed, 0 warnings, 0 failures
```

All deny and warn policies satisfied. The hardened manifest addresses every violation by pinning the image tag, setting a restrictive security context, defining resource boundaries, and adding health probes.

#### Docker Compose Manifest — all pass

```
15 tests, 15 passed, 0 warnings, 0 failures
```

The Compose file (`juice-compose.yml`) passes all policies by:
- Setting explicit non-root user (`10001:10001`)
- Enabling read-only root filesystem with a `/tmp` tmpfs mount
- Dropping all capabilities
- Enabling `no-new-privileges`

### Analysis: How Hardening Satisfies Compliance

The policy-as-code approach enforces a baseline aligned with CIS Kubernetes Benchmarks and NIST container security guidelines:

| Compliance Requirement | Policy Rule | Hardened Control |
|----------------------|-------------|-----------------|
| Least privilege | `runAsNonRoot`, `drop ALL` capabilities | Non-root user, all capabilities dropped |
| Immutable infrastructure | `readOnlyRootFilesystem`, pinned image tag | Read-only FS, version-pinned image |
| Resource isolation | CPU/memory requests and limits | Defined resource boundaries |
| Availability | Liveness/readiness probes | HTTP health checks configured |
| Privilege containment | `allowPrivilegeEscalation: false` | No setuid/setgid escalation |

By codifying these checks in Rego and running them in CI, teams get automated, auditable enforcement that blocks insecure manifests before they reach the cluster — shifting security left from runtime detection (Falco) to deployment prevention (Conftest).
