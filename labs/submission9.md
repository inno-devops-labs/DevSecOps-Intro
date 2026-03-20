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
2026-03-20T01:44:34+0000: Opening 'syscall' source with modern BPF probe.
2026-03-20T01:44:34+0000: Loaded event sources: syscall
2026-03-20T01:44:34+0000: Enabled event sources: syscall
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

### 1.3 Baseline Alert B — Write Under Binary Directory

**Trigger command:**
```powershell
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

This write occurred before the custom rule was loaded. It was captured after rule reload (see Section 1.4).

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

**Rule reload (SIGHUP):**
```
2026-03-20T01:47:35+0000: SIGHUP received, restarting...
2026-03-20T01:47:35+0000: Loading rules from:
2026-03-20T01:47:35+0000:    /etc/falco/falco_rules.yaml | schema validation: ok
2026-03-20T01:47:35+0000:    /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
```

**Trigger command:**
```powershell
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

**Falco alert (JSON):**
```json
{
  "hostname": "bd43098fe774",
  "output": "2026-03-20T01:47:41.567240227+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/custom-rule.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER)",
  "output_fields": {
    "container.id": "46362388bedc",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "container.name": "lab9-helper",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER",
    "fd.name": "/usr/local/bin/custom-rule.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "source": "syscall",
  "tags": ["compliance", "container", "drift"],
  "time": "2026-03-20T01:47:41.567240227Z"
}
```

**Analysis:**

| Field | Value | Significance |
|-------|-------|--------------|
| Rule | `Write Binary Under UsrLocalBin` | Custom rule — `schema validation: ok` |
| Priority | Warning | Elevated above Notice — binary directory writes are high-fidelity indicators |
| `fd.name` | `/usr/local/bin/custom-rule.txt` | Exact file path captured |
| `evt.arg.flags` | `O_CREAT\|O_WRONLY\|FD_UPPER_LAYER` | New file creation in writable upper layer — classic container drift |
| `user.name` | `root` | Write performed as root, compounding risk |

**When the rule fires:**
- Any `open`/`openat`/`openat2`/`creat` syscall with write intent (`O_WRONLY`, `O_RDWR`, `O_CREAT`) targeting a path under `/usr/local/bin/` inside any container
- Captures file creation, overwrite, and truncation of existing binaries

**When the rule should NOT fire (tuning considerations):**
- Writes to `/usr/local/bin/` during the image build process (`container.id == host` excluded by the `container.id != host` condition)
- Legitimate application installs at container startup could produce false positives — in production this rule should be scoped with `container.image.repository not in (trusted_installer_images)` or suppressed during the init phase using a macro
- CI/CD build containers that legitimately install tools during runtime would need to be allowlisted by image name or label

---

### 1.5 Falco Summary

| Alert | Rule | Priority | Trigger | Time |
|-------|------|----------|---------|------|
| Baseline A | `Terminal shell in container` | Notice | `docker exec -it ... /bin/sh` | 01:47:06 |
| Custom rule | `Write Binary Under UsrLocalBin` | Warning | `echo > /usr/local/bin/custom-rule.txt` | 01:47:41 |

**Total events detected:** 2 across 2 rules (1 NOTICE, 1 WARNING)

---

## Task 2 — Policy-as-Code with Conftest (Rego) (4 pts)

### 2.1 Policies Created

#### `labs/lab9/policies/k8s-security.rego`

Enforces Kubernetes deployment hardening with 3 hard `deny` rules and 2 `warn` advisories:

| Rule type | Check | Rationale |
|-----------|-------|-----------|
| `deny` | `privileged: true` | Privileged containers have full host kernel access — equivalent to running as root on the host |
| `deny` | `runAsUser: 0` | Root inside container maps to root on host in default configurations |
| `deny` | `allowPrivilegeEscalation: true` | Permits setuid binary abuse and capability gain post-start |
| `warn` | `readOnlyRootFilesystem: false` | Writable root enables persistence of malware and binary replacement |
| `warn` | Missing `resources.limits` | Unbounded memory/CPU enables DoS and noisy-neighbour resource exhaustion |

#### `labs/lab9/policies/compose-security.rego`

Enforces Docker Compose security patterns:

| Rule type | Check | Rationale |
|-----------|-------|-----------|
| `deny` | `privileged: true` | Same as K8s — full host kernel exposure |
| `warn` | `user: "0"` | Root user inside service increases blast radius of any exploit |

---

### 2.2 Manifest Analysis

#### Unhardened K8s Manifest (`juice-unhardened.yaml`)

```yaml
securityContext:
  runAsUser: 0           # root
  privileged: true       # full kernel access
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

**FAIL 1 — `privileged: true`**
A privileged container bypasses all Linux namespace isolation. It can access all host devices, load kernel modules, modify iptables rules, and escape the container entirely. This is the highest-risk configuration possible for a container — it provides an attacker with RCE inside the container an immediate path to full host compromise.

**FAIL 2 — `runAsUser: 0` (root)**
Running as UID 0 means file system operations and process spawning occur with root privileges. Any vulnerability in the application (e.g., the confirmed SQL injection or path traversal findings from Lab 5) combined with root execution dramatically widens the blast radius. Combined with `privileged: true`, root inside the container is effectively root on the host.

**FAIL 3 — `allowPrivilegeEscalation: true`**
Permits any process inside the container to gain more privileges than its parent via setuid binaries or file capabilities. Even if the container starts as a non-root user, this flag allows an attacker to escalate using any setuid binary present in the image. The `no-new-privileges` seccomp flag (Lab 7) addresses this at the container runtime level; this manifest field enforces the same restriction at the Kubernetes policy level.

**WARN 1 — No `resources.limits`**
Without memory and CPU limits, a single exploited container (e.g., via the SSRF or RCE vulnerabilities identified in Labs 4–5) can exhaust all node resources, causing a denial-of-service for all other workloads on the same node. Kubernetes scheduling also cannot make informed placement decisions without declared resource requirements.

**WARN 2 — `readOnlyRootFilesystem: false`**
A writable root filesystem allows an attacker who achieves code execution to: install persistence mechanisms, replace application binaries, write web shells, or exfiltrate data to local files. Making the root filesystem read-only forces all writes to explicitly declared volumes, making unauthorized modifications immediately detectable.

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
  runAsUser: 1000          # non-root UID
  runAsNonRoot: true       # enforce at admission
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

**Hardening changes that satisfied each policy:**

| Policy violation (unhardened) | Fix applied (hardened) | Security effect |
|-------------------------------|------------------------|-----------------|
| `privileged: true` → FAIL | `privileged: false` | Removes host kernel access; container isolated in its own namespace |
| `runAsUser: 0` → FAIL | `runAsUser: 1000` + `runAsNonRoot: true` | Process runs as unprivileged UID; file system writes restricted to owned paths |
| `allowPrivilegeEscalation: true` → FAIL | `allowPrivilegeEscalation: false` | Blocks setuid binary abuse; `PR_SET_NO_NEW_PRIVS` equivalent |
| Missing `resources.limits` → WARN | `memory: 512Mi`, `cpu: 1.0` | Caps resource consumption; enables scheduler placement; contains DoS |
| `readOnlyRootFilesystem: false` → WARN | `readOnlyRootFilesystem: true` | Prevents runtime binary modification and persistence |
| *(additional hardening)* | `capabilities.drop: [ALL]` | Removes all Linux capabilities (CAP_NET_RAW, CAP_SYS_CHROOT, etc.) — defense in depth matching Lab 7 production profile |

The hardened manifest achieves a complete pass with zero warnings, demonstrating that all policy requirements are satisfiable without breaking the application deployment structure.

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

**Analysis:**

The Compose manifest exhibits the same two highest-risk misconfigurations as the unhardened K8s manifest — `privileged: true` and `user: 0` — but in a Docker Compose context. This is particularly relevant for local development and CI/CD environments where Compose is commonly used.

The `privileged: true` FAIL carries the same severity as in Kubernetes: the container shares the host's kernel with no namespace isolation, making any container compromise equivalent to host compromise.

The `user: "0"` WARNING reflects that root execution is a risk factor even when the container is not privileged — it expands the scope of what an attacker can do inside the container (read any file, write to any writable path, kill any process).

**Remediation for Compose:**
```yaml
services:
  juice-shop:
    image: bkimminich/juice-shop:v19.0.0
    privileged: false      # remove privileged flag entirely
    user: "1000"           # run as non-root UID
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

The unhardened → hardened transition demonstrates a complete remediation path: all 3 hard failures and both warnings are resolved by applying security context hardening and resource limits. The Compose manifest requires separate remediation as it represents a different deployment path with its own misconfiguration surface.

---

## Conclusion

### Task 1 Key Findings

Falco's modern eBPF engine successfully detected both targeted behaviors in real time:

1. **Interactive shell execution** (`Terminal shell in container`) was detected within milliseconds of the `docker exec` call, demonstrating Falco's ability to catch hands-on-keyboard attacker activity even in ephemeral sessions.

2. **Binary directory write** (`Write Binary Under UsrLocalBin`) was detected via the custom rule, confirming that container drift — modification of the container filesystem at runtime — is detectable and distinguishable from legitimate read-only container operation. The `FD_UPPER_LAYER` flag in the alert output is a direct indicator that the write landed on the container's writable layer rather than the immutable image layers.

The custom rule demonstrated that Falco's rule language is expressive enough to write targeted detection with minimal noise using syscall-level conditions (`evt.type`, `evt.is_open_write`, `fd.name`), and that rules can be loaded hot via SIGHUP without restarting the Falco process.

### Task 2 Key Findings

Policy-as-code with Conftest and Rego provides a deterministic, version-controllable enforcement layer that catches deployment misconfigurations before they reach a cluster. The fail/warn distinction is operationally important:

- **Hard `deny` rules** block deployment of configurations that represent unacceptable risk (privileged containers, root execution, privilege escalation) — these should be enforced in CI/CD admission gates
- **`warn` rules** surface best-practice deviations (missing resource limits, writable root filesystem) that should be remediated but may have legitimate exceptions

The hardened manifest achieved a perfect 7/7 pass by applying the same security controls that were demonstrated at the container runtime level in Lab 7 (`--cap-drop=ALL`, `--no-new-privileges`, resource limits) — but expressed as declarative Kubernetes manifest fields and validated by static policy analysis before deployment. This is the policy-as-code approach: encoding security knowledge into machine-checkable rules that can run in seconds on every pull request.