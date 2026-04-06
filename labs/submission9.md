# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

---

## Task 1 — Runtime Security Detection with Falco (6 pts)

### Setup

- **Falco version:** 0.43.0 (x86_64), modern BPF probe on WSL2 (Linux 5.15.167.4-microsoft-standard-WSL2)
- **Helper container:** `alpine:3.19` (`lab9-helper`)
- **Custom rule loaded:** `/etc/falco/rules.d/custom-rules.yaml`

### Baseline Alerts (Step 1.3)

**A) Terminal shell in container** (Priority: Notice)
```json
{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "output_fields": {
    "container.name": "lab9-helper",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "user.name": "root",
    "evt.type": "execve"
  }
}
```
Triggered by `docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'`. Detects interactive shell sessions inside containers — a common indicator of manual intrusion or unauthorized access.

**B) Write Binary Under UsrLocalBin** — Custom Rule (Priority: Warning)
```json
{
  "rule": "Write Binary Under UsrLocalBin",
  "priority": "Warning",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/usr/local/bin/drift.txt",
    "user.name": "root",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER"
  }
}
```
Triggered by writing to `/usr/local/bin/drift.txt`. Detects container drift — file modifications in binary directories that deviate from the original image.

### Custom Rule (Step 1.4)

**File:** `labs/lab9/falco/rules/custom-rules.yaml`

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and 
             evt.is_open_write=true and 
             fd.name startswith /usr/local/bin/ and 
             container.id != host
  priority: WARNING
  tags: [container, compliance, drift]
```

**When it should fire:** Any write operation to `/usr/local/bin/` inside a container — indicates potential binary injection, backdoor installation, or unauthorized modifications.

**When it should NOT fire:** On the host system (`container.id != host` excludes host events). Also won't fire for read operations or writes to other directories. In production, you might want to add exceptions for known CI/CD build containers that legitimately write binaries during the build phase.

### Event Generator Alerts (Step 1.5)

The event generator triggered 17+ distinct rules across all severity levels:

| Rule | Priority | MITRE ATT&CK |
|------|----------|---------------|
| Fileless execution via memfd_create | Critical | T1620 |
| Drop and execute new binary in container | Critical | T1611 |
| Detect release_agent File Container Escapes | Critical | T1611 |
| Read sensitive file untrusted (`/etc/shadow`) | Warning | T1555 |
| Execution from /dev/shm | Warning | T1059.004 |
| Netcat Remote Code Execution in Container | Warning | T1059 |
| PTRACE attached to process | Warning | T1055.008 |
| Directory traversal monitored file read | Warning | T1555 |
| Remove Bulk Data from Disk | Warning | T1485 |
| Search Private Keys or Passwords | Warning | T1552.001 |
| Create Symlink Over Sensitive Files | Warning | T1555 |
| Clear Log Activities | Warning | T1070 |
| Debugfs Launched in Privileged Container | Warning | T1611 |
| Find AWS Credentials | Warning | T1552 |
| Create Hardlink Over Sensitive Files | Warning | T1555 |
| Grep private keys or passwords | Warning | T1552.001 |
| PTRACE anti-debug attempt | Notice | T1622 |
| Shell spawned by untrusted binary | Notice | T1059.004 |
| Packet socket created in container | Notice | T1557.002 |
| Disallowed SSH Connection Non Standard Port | Notice | T1059 |

Full log: `labs/lab9/falco/logs/falco.log`

---

## Task 2 — Policy-as-Code with Conftest (Rego) (4 pts)

### Unhardened Manifest — Policy Violations

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

Result: 30 tests, 20 passed, 2 warnings, 8 failures
```

**Why each violation matters:**

| Violation | Security Risk |
|-----------|--------------|
| `:latest` tag | No version pinning — unpredictable deployments, supply chain risk |
| `runAsNonRoot` missing | Container runs as root — full filesystem access if compromised |
| `allowPrivilegeEscalation` missing | Process can gain additional privileges (e.g., via SUID) |
| `readOnlyRootFilesystem` missing | Attacker can write malware, backdoors, or modify config |
| Capabilities not dropped | Container retains kernel capabilities that enable escapes |
| No resource limits | Enables DoS via resource exhaustion (CPU/memory bombs) |
| No health probes | Unavailability goes undetected; cascading failures |

### Hardened Manifest — Hardening Changes

```
Result: 30 tests, 30 passed, 0 warnings, 0 failures
```

**Changes applied in `juice-hardened.yaml`:**

| Setting | Unhardened | Hardened |
|---------|-----------|----------|
| Image tag | `:latest` | `:v19.0.0` |
| `runAsNonRoot` | not set | `true` |
| `allowPrivilegeEscalation` | not set | `false` |
| `readOnlyRootFilesystem` | not set | `true` |
| `capabilities.drop` | not set | `["ALL"]` |
| Resource requests | not set | cpu: 100m, memory: 256Mi |
| Resource limits | not set | cpu: 500m, memory: 512Mi |
| Readiness probe | not set | httpGet on `/` port 3000 |
| Liveness probe | not set | httpGet on `/` port 3000 |

### Docker Compose Manifest

```
Result: 15 tests, 15 passed, 0 warnings, 0 failures
```

The compose manifest (`juice-compose.yml`) was already hardened with `user: "10001:10001"`, `read_only: true`, `cap_drop: ["ALL"]`, and `no-new-privileges:true`.

---

## Files Produced

```
labs/lab9/
├── analysis/
│   ├── conftest-unhardened.txt
│   ├── conftest-hardened.txt
│   └── conftest-compose.txt
└── falco/
    ├── logs/
    │   └── falco.log
    └── rules/
        └── custom-rules.yaml
```
