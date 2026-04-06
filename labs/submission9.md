# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### Baseline Alerts Observed from falco.log

**1. Terminal shell in container (Notice)**
- **Timestamp:** 2026-04-06T15:46:54.307254565Z
- **Alert:** `A shell was spawned in a container with an attached terminal`
- **Details:**
  - Container: `lab9-helper` (alpine:3.19)
  - User: `root` (uid=0)
  - Process: `/bin/sh -lc echo hello-from-shell`
  - Rule: `Terminal shell in container` (built-in Falco rule)
  - Tags: T1059, container, shell, MITRE execution
- **Significance:** Detects interactive shell spawning inside containers, which is a common attack vector for container compromise or lateral movement.

**2. Write Binary Under UsrLocalBin (Warning) — Custom Rule**
- **Timestamp:** 2026-04-06T15:47:25.825598210Z
- **Alert:** `Falco Custom: File write in /usr/local/bin`
- **Details:**
  - Container: `lab9-helper`
  - File: `/usr/local/bin/drift.txt`
  - User: `root`
  - Flags: `O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER`
  - Rule: `Write Binary Under UsrLocalBin` (custom rule)
- **Significance:** Indicates potential container drift — unauthorized modifications to binary directories may indicate compromise, malware injection, or unintended configuration changes.

**3. Write Binary Under UsrLocalBin (Warning) — Custom Rule Validation**
- **Timestamp:** 2026-04-06T15:49:39.068645939Z
- **Alert:** `Falco Custom: File write in /usr/local/bin`
- **Details:**
  - Container: `lab9-helper`
  - File: `/usr/local/bin/custom-rule.txt`
  - User: `root`
  - Confirms custom rule fires reliably on repeated writes to `/usr/local/bin`

**4. Event Generator Test Events (Additional Context)**
The event-generator container triggered several high-fidelity alerts demonstrating Falco's detection capability:
- **Critical: Fileless execution via memfd_create** — In-memory code execution without persistent files
- **Warning: Sensitive file opened (/etc/shadow)** — Unauthorized access to sensitive system files
- **Warning: Packet socket created in container** — Network reconnaissance activity
- **Warning: Execution from /dev/shm** — Suspicious execution from shared memory
- **Warning: Bulk data removal** — Evidence of cover-up attempts
- **Warning: Log tampering** — Clearing audit trails
- **Warning: PTRACE attached to process** — Potential privilege escalation attempt

### Custom Rule: `Write Binary Under UsrLocalBin`

**Purpose:**
Detect writes and file creation events under `/usr/local/bin` inside containers. This rule identifies container drift — unauthorized or unexpected modifications to directories where executable binaries are typically stored. Such changes may indicate:
- Malware or unauthorized binary injection
- Container escape attempts
- Unintended configuration drift
- Supply chain compromises

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
- Any write-enabled `open()` or `creat()` syscall targeting `/usr/local/bin/` inside a container
- File creation, modification, or truncation under this directory requires capturing event details

**When It Should NOT Fire:**
- Writes from the host system (`container.id == host` — excluded in condition)
- Read-only opens or non-write operations (condition requires `evt.is_open_write=true`)
- Legitimate package managers running in build containers (e.g., during image creation) — may require tuning via image/container name filters if false positives occur

**Tuning/False Positive Prevention:**
If this rule generates too many alerts during legitimate build processes, add condition filters:
```yaml
condition: ... and container.name != build-container and container.image != builder:*
```
This narrows detection to specific runtime containers while allowing build-time writes.

## Task 2 — Policy-as-Code with Conftest

### Policy Violations from Unhardened Manifest

The `juice-unhardened.yaml` manifest failed **8 critical security checks** (FAIL) and triggered **2 non-blocking warnings** (WARN):

**Critical Failures (Hard Denies):**

1. **Image tag uses `:latest`** — Using mutable image tags creates supply-chain risks; images can change unexpectedly without versioning/audit trail.
2. **Missing `runAsNonRoot: true`** — Containers run as root (uid=0) by default, enabling privilege escalation and lateral movement if compromised.
3. **Missing `allowPrivilegeEscalation: false`** — Allows containers to gain higher privileges, violating least-privilege principle.
4. **Missing `readOnlyRootFilesystem: true`** — Writable filesystem enables attackers to modify application/system binaries and plant persistence mechanisms.
5. **Missing `capabilities.drop: ["ALL"]`** — Containers retain dangerous Linux capabilities (e.g., SYS_ADMIN, NET_ADMIN) that enable escape and privilege escalation.
6. **Missing CPU/Memory `requests`** — No resource reservation; container may get starved or evicted during contention.
7. **Missing CPU/Memory `limits`** — No resource cap; one container can consume all cluster resources (resource exhaustion DoS).

**Non-Blocking Warnings (Guidance):**

- **Missing `readinessProbe`** — Unhealthy pods may receive traffic, degrading service availability.
- **Missing `livenessProbe`** — Failed or stuck containers won't be automatically restarted.

**Result:** 30 total tests, **20 passed / 8 failed / 2 warnings**.

### Specific Hardening Changes in juice-hardened.yaml

The hardened manifest implements all required security controls:

| Control | Unhardened | Hardened | Security Impact |
|---------|-----------|----------|-----------------|
| **Image Tag** | `:latest` (mutable) | `:v19.0.0` (immutable) | Prevents unexpected image changes; enables reproducible deployments |
| **runAsNonRoot** | ✗ (implicit root) | ✓ `true` | Blocks root privilege escalation; enforces least-privilege |
| **allowPrivilegeEscalation** | ✗ (default allow) | ✓ `false` | Prevents setuid/setgid privilege escalation |
| **readOnlyRootFilesystem** | ✗ (writable) | ✓ `true` | Prevents binary modification, persistence, and rootkit installation |
| **Drop Capabilities** | ✗ (all retained) | ✓ `["ALL"]` | Removes dangerous kernel capabilities; reduces kernel-attack surface |
| **CPU Requests** | ✗ | ✓ `100m` | Guarantees minimum compute; prevents starvation |
| **Memory Requests** | ✗ | ✓ `256Mi` | Guarantees minimum memory; prevents OOM eviction |
| **CPU Limits** | ✗ | ✓ `500m` | Caps compute usage; prevents noisy-neighbor DoS |
| **Memory Limits** | ✗ | ✓ `512Mi` | Caps memory usage; enforces predictable QoS |
| **readinessProbe** | ✗ | ✓ HTTP GET / | Traffic sent only to healthy replicas |
| **livenessProbe** | ✗ | ✓ HTTP GET / | Failed pods auto-restart; increases availability |

**Result:** All 30 tests pass; **0 failures, 0 warnings**

### Docker Compose Manifest Analysis

The `juice-compose.yml` manifest was tested against `compose-security.rego` policies:

**Result:** **15 tests passed, 0 failures, 0 warnings**

**Conclusion:** The Docker Compose manifest already implements the required security controls defined in the policy:
- Explicit non-root user declared
- Read-only filesystem enabled
- Dangerous capabilities dropped
- No-new-privileges security option set (best-effort)

This demonstrates that hardening practices are consistent across both Kubernetes and Docker Compose deployment models.
