# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### Setup

Falco 0.43.1 was installed natively on Ubuntu 20.04 (kernel 5.4.0-37-generic). The modern eBPF engine is not supported on this kernel (ring buffer requires kernel 5.8+), so the **kernel module (kmod)** driver was used instead. The pre-compiled driver was downloaded via `falcoctl driver install --type kmod` from `https://download.falco.org/driver`. The container plugin required `LD_PRELOAD=/lib/x86_64-linux-gnu/libresolv.so.2` due to a missing `__res_search` symbol on glibc 2.31.

Falco was started with JSON output and ISO 8601 timestamps:
```bash
sudo bash -c 'LD_PRELOAD=/lib/x86_64-linux-gnu/libresolv.so.2 /usr/bin/falco -U \
  -o json_output=true -o time_format_iso_8601=true -o engine.kind=kmod \
  -o "load_plugins[0]=container" \
  -r /etc/falco/falco_rules.yaml \
  -r labs/lab9/falco/rules/custom-rules.yaml'
```

A helper container (`alpine:3.19`) was launched for triggering events:
```bash
docker run -d --name lab9-helper alpine:3.19 sleep 1d
```

### Baseline Alerts

#### Alert 1: Terminal shell in container

**Trigger command:**
```bash
script -qc 'docker exec -it lab9-helper /bin/sh -lc "echo hello-from-shell"' /dev/null
```

**Falco output (JSON):**
```json
{
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "time": "2026-04-15T03:38:48.422632659Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "evt.type": "execve",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "proc.exepath": "/bin/busybox",
    "proc.tty": 34816,
    "user.name": "root"
  },
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"]
}
```

**Why this matters:** Interactive shells in production containers indicate potential unauthorized access or attacker lateral movement (MITRE ATT&CK T1059 — Command and Scripting Interpreter). Containers should be treated as immutable; shell access breaks that model.

#### Alert 2: Read sensitive file untrusted

**Trigger command:**
```bash
docker exec lab9-helper /bin/sh -c 'cat /etc/shadow'
```

**Falco output (JSON):**
```json
{
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "time": "2026-04-15T03:38:49.288471290Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/etc/shadow",
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "user.name": "root"
  },
  "tags": ["T1555", "container", "filesystem", "host", "maturity_stable", "mitre_credential_access"]
}
```

**Why this matters:** Reading `/etc/shadow` is a credential access technique (MITRE T1555). An attacker who gains shell access typically attempts to harvest password hashes for offline cracking or credential reuse.

### Custom Rule: Write Binary Under UsrLocalBin

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

**Purpose:** Detects when any process inside a container writes files to `/usr/local/bin/`. This is a container drift indicator — in immutable containers, the filesystem should not change at runtime. Writes to binary directories suggest an attacker is planting backdoors, installing tools, or modifying existing executables.

**When it should fire:**
- An attacker drops a reverse shell binary into `/usr/local/bin/`
- A process writes a script or binary to the container's PATH
- Any file creation/modification under `/usr/local/bin/`

**When it should NOT fire (tuning considerations):**
- On the host system (excluded by `container.id != host`)
- Build containers where package installation is expected (could add `container.image.repository != "build-*"` exception)
- Init containers that legitimately populate volumes

**Trigger command:**
```bash
docker exec --user 0 lab9-helper /bin/sh -c 'echo boom > /usr/local/bin/drift.txt'
```

**Falco output (JSON):**
```json
{
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "time": "2026-04-15T03:38:52.904559496Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER",
    "fd.name": "/usr/local/bin/drift.txt",
    "user.name": "root"
  },
  "tags": ["compliance", "container", "drift"]
}
```

The custom rule fired again for a second write (`/usr/local/bin/custom-rule.txt`), validating consistent detection.

### Event Generator Results

The Falco event generator (`falcosecurity/event-generator:latest`) produced a burst of detectable syscall actions. The following 23 distinct rules were triggered:

| Rule | Count | Priority |
|------|-------|----------|
| Write Binary Under UsrLocalBin (custom) | 2 | Warning |
| Read sensitive file untrusted | 2 | Warning |
| Execution from /dev/shm | 2 | Warning |
| Terminal shell in container | 1 | Notice |
| System user interactive | 1 | Notice |
| Search Private Keys or Passwords | 1 | Warning |
| Run shell untrusted | 1 | Warning |
| Remove Bulk Data from Disk | 1 | Warning |
| Read sensitive file trusted after startup | 1 | Notice |
| PTRACE attached to process | 1 | Warning |
| PTRACE anti-debug attempt | 1 | Warning |
| Packet socket created in container | 1 | Warning |
| Netcat Remote Code Execution in Container | 1 | Warning |
| Find AWS Credentials | 1 | Warning |
| Fileless execution via memfd_create | 1 | Critical |
| Drop and execute new binary in container | 1 | Critical |
| Disallowed SSH Connection Non Standard Port | 1 | Notice |
| Directory traversal monitored file read | 1 | Warning |
| Detect release_agent File Container Escapes | 1 | Critical |
| Debugfs Launched in Privileged Container | 1 | Warning |
| Create Symlink Over Sensitive Files | 1 | Warning |
| Create Hardlink Over Sensitive Files | 1 | Warning |
| Clear Log Activities | 1 | Warning |

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### Conftest Setup

Conftest was run via Docker (`openpolicyagent/conftest:latest`) against the provided manifests using two Rego policy files:
- `policies/k8s-security.rego` — 9 deny rules + 2 warn rules for Kubernetes Deployments
- `policies/compose-security.rego` — 3 deny rules + 1 warn rule for Docker Compose services

### Unhardened Manifest Results

**Command:**
```bash
docker run --rm -v "$(pwd)/labs/lab9":/project openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-unhardened.yaml -p /project/policies --all-namespaces
```

**Result: 30 tests, 20 passed, 2 warnings, 8 failures**

| Violation | Category | Security Impact |
|-----------|----------|-----------------|
| Uses `:latest` tag | Image provenance | No reproducibility; vulnerable to supply-chain attacks where an attacker pushes a malicious image to the same tag |
| Missing `runAsNonRoot: true` | Privilege management | Container runs as root by default; a container escape gives the attacker root on the host |
| Missing `allowPrivilegeEscalation: false` | Privilege management | Processes can gain more privileges via setuid/setgid binaries or kernel exploits |
| Missing `readOnlyRootFilesystem: true` | Filesystem integrity | Attackers can write malware, modify configs, or plant persistence mechanisms |
| Missing `capabilities.drop: ["ALL"]` | Capability restriction | Retains all Linux capabilities; enables network manipulation, mount operations, etc. |
| Missing `resources.requests.cpu` | Resource management | No guaranteed CPU allocation; enables noisy-neighbor denial-of-service |
| Missing `resources.requests.memory` | Resource management | No guaranteed memory; OOM kills can cascade across pods |
| Missing `resources.limits.cpu` | Resource management | Unbounded CPU allows cryptomining or resource exhaustion attacks |
| Missing `resources.limits.memory` | Resource management | Unbounded memory enables OOM-based denial-of-service |
| **WARN:** Missing `readinessProbe` | Availability | Traffic routed to unready pods causes user-facing errors |
| **WARN:** Missing `livenessProbe` | Availability | Hung processes not restarted; degraded service without detection |

### Hardened Manifest Results

**Command:**
```bash
docker run --rm -v "$(pwd)/labs/lab9":/project openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-hardened.yaml -p /project/policies --all-namespaces
```

**Result: 30 tests, 30 passed, 0 warnings, 0 failures**

The hardened manifest addresses every policy violation:

| Hardening Change | How It Satisfies Policy |
|-----------------|----------------------|
| `image: bkimminich/juice-shop:v19.0.0` | Pinned version tag eliminates `:latest` violation; ensures reproducible, auditable builds |
| `runAsNonRoot: true` | Kubernetes rejects the pod if the container image runs as UID 0 |
| `allowPrivilegeEscalation: false` | Blocks setuid/setgid escalation and `no_new_privs` bit is set |
| `readOnlyRootFilesystem: true` | Makes the container filesystem immutable; drift detection becomes trivial |
| `capabilities.drop: ["ALL"]` | Removes all 40+ Linux capabilities; container can only perform unprivileged operations |
| `requests: {cpu: "100m", memory: "256Mi"}` | Guarantees minimum resources; scheduler can make informed placement decisions |
| `limits: {cpu: "500m", memory: "512Mi"}` | Caps resource usage; prevents resource exhaustion attacks |
| `readinessProbe` (HTTP GET /, port 3000) | Kubernetes only routes traffic to pods that respond successfully |
| `livenessProbe` (HTTP GET /, port 3000) | Kubernetes restarts pods that stop responding; self-healing behavior |

### Docker Compose Manifest Results

**Command:**
```bash
docker run --rm -v "$(pwd)/labs/lab9":/project openpolicyagent/conftest:latest \
  test /project/manifests/compose/juice-compose.yml -p /project/policies --all-namespaces
```

**Result: 15 tests, 15 passed, 0 warnings, 0 failures**

The Docker Compose manifest (`juice-compose.yml`) passes all policy checks:

| Compose Setting | Policy Requirement | How It Complies |
|----------------|-------------------|-----------------|
| `user: "10001:10001"` | Must set explicit non-root user | Runs as unprivileged UID/GID 10001 |
| `read_only: true` | Must set read-only filesystem | Container filesystem is immutable |
| `cap_drop: ["ALL"]` | Must drop all capabilities | All Linux capabilities removed |
| `security_opt: [no-new-privileges:true]` | Should enable no-new-privileges | Prevents privilege escalation via setuid/setgid |
| `tmpfs: ["/tmp"]` | (not enforced by policy) | Provides writable scratch space without compromising immutability |

The Compose manifest mirrors the Kubernetes hardened manifest's security posture, demonstrating that the same security principles apply across orchestration platforms.

---

## Summary

| Aspect | Finding |
|--------|---------|
| Runtime detection | Falco (kmod driver) successfully detected shell access, sensitive file reads, container drift, and 20+ additional threat patterns from the event generator |
| Custom rules | `Write Binary Under UsrLocalBin` reliably catches filesystem drift in binary directories |
| Policy-as-code | Conftest/Rego policies caught 8 failures + 2 warnings in the unhardened manifest; the hardened manifest passes all 30 tests |
| Compliance gap | The unhardened manifest represents a typical "default" Kubernetes deployment with zero security hardening — every production deployment should be validated against policy-as-code before merge |
