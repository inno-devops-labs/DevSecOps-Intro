# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1: Runtime Security Detection with Falco

### 1.1 Baseline Alerts Observed

The following baseline Falco alerts were triggered and captured in `labs/lab9/falco/logs/falco.log`:

#### Alert 1: Terminal Shell in Container (NOTICE)
- **Time:** 2026-03-18T20:26:55.466105477Z
- **Rule:** `Terminal shell in container`
- **Severity:** NOTICE
- **Trigger:** `docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'`
- **Details:**
  - Container: `lab9-helper`
  - Process: `sh` (pid via execve)
  - User: `root` (uid=0)
  - Command: `sh -lc echo hello-from-shell`
- **Security Significance:** This alert detects when a shell is spawned inside a container with an attached terminal. This is a common first step in container exploitation and lateral movement. In production, interactive shells should be rare and warrant investigation.

#### Alert 2: Custom Rule - Write Binary Under UsrLocalBin (WARNING)
- **Time:** 2026-03-18T20:31:50.831976837Z
- **Rule:** `Write Binary Under UsrLocalBin` (custom rule)
- **Severity:** WARNING
- **Trigger:** `docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'`
- **Details:**
  - Container: `lab9-helper`
  - File written: `/usr/local/bin/custom-rule.txt`
  - User: `root`
  - Flags: `O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER`
- **Security Significance:** This alert fires when a file is written to `/usr/local/bin`, a directory typically reserved for system binaries. Writing files to this directory is a "container drift" indicator — evidence that the container's filesystem has deviated from the intended base image.

---

### 1.2 Custom Rule: `Write Binary Under UsrLocalBin`

**Purpose:**  
Detect unauthorized writes to `/usr/local/bin` inside containers. This directory is part of the standard Linux `$PATH` and is often used to place executable binaries. If an attacker (or misconfigured process) writes files here, it indicates either:
1. **Container drift** — the filesystem is being modified beyond the base image
2. **Privilege escalation attempt** — writing a malicious binary to a PATH directory to hijack or shadow system commands
3. **Supply chain compromise** — an infected process is injecting code into the system

**Rule Definition:**
```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and 
             evt.is_open_write=true and 
             fd.name startswith /usr/local/bin/ and 
             container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

**When It Should Fire:**
- Any write syscall (`open`, `openat`, `openat2`, `creat`) with write permissions to files under `/usr/local/bin`
- Only when inside a container (distinguished by `container.id != host`)
- Regardless of user (root or non-root)

**When It Should NOT Fire:**
- Reads to `/usr/local/bin` (only open_write=true detects)
- Operations on the host system (filtered by `container.id != host`)
- Writes to other directories like `/usr/bin` (outside scope)

**Tuning Notes:**
- **False positives:** Legitimate applications (package managers, build tools) may write to `/usr/local/bin` during startup. In production, baseline the container with a Falco rule learning phase before enforcing.
- **Severity:** Set to `WARNING` because drift is suspicious but not necessarily critical. In strict environments, raise to `CRITICAL`.
- **Enrichment:** The rule captures the filename, user, and open flags, allowing security teams to investigate the exact file being written.

---

## Task 2: Policy-as-Code with Conftest

### 2.1 Conftest Results Summary

**Unhardened Manifest:** 8 FAIL, 2 WARN
```
FAIL - container "juice" uses disallowed :latest tag
FAIL - container "juice" must set runAsNonRoot: true
FAIL - container "juice" must set allowPrivilegeEscalation: false
FAIL - container "juice" must set readOnlyRootFilesystem: true
FAIL - container "juice" must drop ALL capabilities
FAIL - container "juice" missing resources.requests.cpu
FAIL - container "juice" missing resources.requests.memory
FAIL - container "juice" missing resources.limits.cpu
FAIL - container "juice" missing resources.limits.memory
WARN - container "juice" should define readinessProbe
WARN - container "juice" should define livenessProbe
```

**Hardened Manifest:** 30 PASS (0 failures, 0 warnings)

**Docker Compose Manifest:** 15 PASS (0 failures, 0 warnings)

---

### 2.2 Policy Violations in Unhardened Manifest

| Violation | Impact | Why It Matters |
|-----------|--------|----------------|
| `:latest` tag | FAIL | No version pinning → unpredictable updates, supply chain risk |
| `runAsNonRoot: false` | FAIL | Container runs as root → full host compromise if breached |
| `allowPrivilegeEscalation: true` | FAIL | Allows `setuid` binaries → privilege escalation attacks |
| `readOnlyRootFilesystem: false` | FAIL | Writable filesystem → attacker can modify application files |
| No capability drop | FAIL | Full Linux capabilities → expanded attack surface |
| Missing resource limits | FAIL | No CPU/memory constraints → resource exhaustion DoS |
| Missing probes | WARN | No health checks → unhealthy pods stay running |

---

### 2.3 Hardening Changes Applied

**juice-unhardened.yaml → juice-hardened.yaml:**

```yaml
#  BEFORE
image: bkimminich/juice-shop:latest
# No securityContext
# No resources
# No probes

#  AFTER
image: bkimminich/juice-shop:v19.0.0  # Explicit version
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
resources:
  requests: { cpu: "100m", memory: "256Mi" }
  limits:   { cpu: "500m", memory: "512Mi" }
readinessProbe:
  httpGet: { path: /, port: 3000 }
  initialDelaySeconds: 5
livenessProbe:
  httpGet: { path: /, port: 3000 }
  initialDelaySeconds: 10
```

**Result:** All 8 FAIL violations resolved + 2 WARN recommendations implemented.

---

### 2.4 Docker Compose Analysis

The Compose manifest passes all 15 tests with 0 failures:

**Services run as non-root:** `user: "10001:10001"`  
**Read-only filesystem:** `read_only: true` (writable `/tmp` via `tmpfs`)  
**Capabilities dropped:** `cap_drop: ["ALL"]`  
**Privilege escalation blocked:** `security_opt: [no-new-privileges:true]`

**Conclusion:** Docker Compose manifest demonstrates production-ready hardening baseline.

---
