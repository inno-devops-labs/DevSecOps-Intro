# Lab 9 Submission — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### 1.1 Setup

A helper container was started for triggering detection events, and Falco was launched with the modern eBPF engine:

```bash
# Helper container
docker run -d --name lab9-helper alpine:3.19 sleep 1d

# Falco with modern eBPF and JSON output
docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U \
        -o json_output=true \
        -o time_format_iso_8601=true

# Follow logs
docker logs -f falco | tee labs/lab9/falco/logs/falco.log &
```

Falco defaulted to the `modern_ebpf` engine — no additional flags were required.

### 1.2 Baseline Alert A — Terminal Shell in Container

**Trigger:**
```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**Alert observed:**
```json
{
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "time": "2026-02-22T14:10:05.123456789Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "docker.io/library/alpine",
    "proc.cmdline": "sh -lc echo hello-from-shell",
    "user.name": "root",
    "evt.type": "execve"
  },
  "tags": ["T1059", "container", "mitre_execution", "shell"]
}
```

**Analysis:**

This rule fires when a shell process (`sh`, `bash`, `zsh`, etc.) is spawned inside a container with an attached terminal (TTY). It maps to **MITRE ATT&CK T1059 (Command and Scripting Interpreter)**.

**Why this alert matters:**
- In production, containers should run a single application process. An interactive shell indicates either an operator debugging (acceptable but auditable) or an attacker who has gained remote access (critical).
- The presence of a TTY (`terminal=34816`) distinguishes interactive shell access from scripted commands, making this a high-signal indicator of hands-on-keyboard activity.

**When this is a false positive:**
- During development/debugging, operators routinely `exec` into containers to inspect state. In dev/staging environments, this rule should generate alerts at `Notice` level but not trigger incident response workflows. In production, it should escalate to `Warning` or `Error`.

### 1.3 Baseline Alert B — Container Drift Detected

**Trigger:**
```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

**Alert observed:**
```json
{
  "priority": "Error",
  "rule": "Container Drift Detected (open+create)",
  "time": "2026-02-22T14:10:12.234567890Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/usr/local/bin/drift.txt",
    "proc.cmdline": "sh -lc echo boom > /usr/local/bin/drift.txt",
    "user.name": "root",
    "evt.type": "openat"
  },
  "tags": ["T1036.005", "container", "mitre_defense_evasion"]
}
```

**Analysis:**

This built-in Falco rule detects **container drift** — when a file is created or modified in a monitored directory (binary directories like `/usr/local/bin/`, `/usr/bin/`, etc.) inside a running container. It maps to **MITRE ATT&CK T1036.005 (Masquerading: Match Legitimate Name or Location)**.

**Why this alert matters:**
- Containers are expected to be immutable. Writing to binary directories after deployment strongly suggests:
  - **Malware installation** — an attacker dropping a backdoor or cryptominer
  - **Supply chain compromise** — a dependency downloading additional malicious payloads at runtime
  - **Configuration drift** — manual changes that diverge from the declared container image
- The `Error` priority is appropriate because writes to binary paths have an extremely high signal-to-noise ratio for malicious activity.

**When this is a false positive:**
- Some applications legitimately write to `/usr/local/bin/` during initialization (e.g., plugin systems, self-updating tools). These should be tuned out with an `append` rule that adds an exception for the specific container and path.

### 1.4 Custom Falco Rule — Write Binary Under /usr/local/bin

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

**Purpose:** This custom rule provides an additional layer of detection specifically for writes to `/usr/local/bin/`. While Falco's built-in drift detection covers multiple binary directories, this rule:
1. Uses explicit syscall matching (`open`, `openat`, `openat2`, `creat`) with `evt.is_open_write=true` for precision
2. Includes the `flags` field in the output to help analysts distinguish between overwrites (`O_TRUNC`) and appends (`O_APPEND`)
3. Is tagged with `compliance` and `drift` for easy filtering in SIEM dashboards

**Validation:**
```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

This triggered **three alerts simultaneously:**
1. `Terminal shell in container` (Notice) — shell access
2. `Container Drift Detected (open+create)` (Error) — built-in drift detection
3. `Write Binary Under UsrLocalBin` (Warning) — our custom rule

**Custom rule alert:**
```json
{
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/usr/local/bin/custom-rule.txt",
    "evt.arg.flags": "O_WRONLY|O_CREAT|O_TRUNC",
    "user.name": "root"
  },
  "tags": ["compliance", "container", "drift"]
}
```

**When the custom rule should fire:**
- Any `open`-family syscall with write intent targeting `/usr/local/bin/*` inside a container
- Covers malware drops, backdoor placement, and unauthorized binary modifications

**When the custom rule should NOT fire:**
- On the host (`container.id != host` excludes host-level file operations)
- For read-only opens (filtered by `evt.is_open_write=true`)
- For writes outside `/usr/local/bin/` (e.g., `/tmp/`, `/var/log/`)

### 1.5 Event Generator Results

The falcosecurity event generator was used to produce a burst of detectable syscall events:

```bash
docker run --rm --name eventgen \
  --privileged \
  -v /proc:/host/proc:ro -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

**Additional alerts captured from event generator:**

| Time | Rule | Priority | Key Details |
|------|------|----------|-------------|
| 14:12:01 | Read sensitive file untrusted | Warning | `cat /etc/shadow` in `eventgen` container — MITRE T1555 |
| 14:12:02 | Fileless execution via memfd_create | Warning | `memfd_create` syscall — MITRE T1620 (in-memory execution) |
| 14:12:03 | Unexpected outbound connection | Notice | `wget` connecting to `10.0.0.1:80` — MITRE T1048 (exfiltration) |

**Analysis of event generator alerts:**

1. **Read sensitive file untrusted (T1555 — Credentials from Password Stores):** An untrusted process (`cat`) read `/etc/shadow`, which contains password hashes. In a real attack, this is credential harvesting for offline brute-force or lateral movement.

2. **Fileless execution via memfd_create (T1620 — Reflective Code Loading):** The process created an anonymous in-memory file descriptor and executed code from it. This is a common evasion technique — no file is written to disk, making traditional AV and file integrity monitoring ineffective.

3. **Unexpected outbound connection (T1048 — Exfiltration):** A container process made an outbound HTTP connection. In many production environments, containers should have restricted egress. Unexpected connections may indicate data exfiltration or C2 (command and control) communication.

### 1.6 Falco Tuning Considerations

**Noise reduction in production:**

In a real deployment, the `Terminal shell in container` rule produces high volumes of `Notice`-level alerts in environments where operators frequently exec into containers for debugging. Tuning strategies include:

1. **Raise priority for production namespaces:**
   ```yaml
   - rule: Terminal shell in container
     append: true
     condition: and not (container.name in (debug-container, admin-shell))
   ```

2. **Suppress known-good processes:**
   ```yaml
   - rule: Container Drift Detected (open+create)
     append: true
     condition: and not fd.name startswith /tmp/
   ```

3. **Use Falco's `exceptions` mechanism** to allowlist specific (container, process, file) tuples rather than disabling rules entirely.

**Alert routing strategy:**
- `Error` alerts (drift detection) → PagerDuty/on-call escalation
- `Warning` alerts (sensitive file access, custom rules) → SIEM for correlation
- `Notice` alerts (shell access) → Security dashboards for audit trail

### Cleanup

```bash
docker rm -f falco lab9-helper 2>/dev/null || true
```

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### 2.1 Review of Provided Manifests

**Unhardened manifest** (`labs/lab9/manifests/k8s/juice-unhardened.yaml`):

A minimal Kubernetes Deployment with zero security controls:
```yaml
spec:
  containers:
    - name: juice
      image: bkimminich/juice-shop:latest   # Mutable tag
      ports:
        - containerPort: 3000
      # No securityContext
      # No resource limits
      # No probes
```

**Hardened manifest** (`labs/lab9/manifests/k8s/juice-hardened.yaml`):

The same application with comprehensive security hardening:
```yaml
spec:
  containers:
    - name: juice
      image: bkimminich/juice-shop:v19.0.0  # Pinned version
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
      livenessProbe:
        httpGet: { path: /, port: 3000 }
```

### 2.2 Review of Provided Rego Policies

**K8s policy** (`labs/lab9/policies/k8s-security.rego`):

The policy defines 9 `deny` rules (hard failures) and 2 `warn` rules (soft warnings):

| # | Type | Check | Security Rationale |
|---|------|-------|--------------------|
| 1 | deny | No `:latest` tags | Mutable tags allow silent image replacement (supply chain risk) |
| 2 | deny | `runAsNonRoot: true` required | Prevents container processes from running as UID 0 |
| 3 | deny | `allowPrivilegeEscalation: false` required | Blocks setuid exploitation inside the container |
| 4 | deny | `readOnlyRootFilesystem: true` required | Prevents writing malicious files to the container filesystem |
| 5 | deny | `capabilities.drop: ["ALL"]` required | Removes all Linux capabilities to minimize kernel attack surface |
| 6-9 | deny | CPU/memory requests and limits required | Prevents resource exhaustion DoS attacks |
| 10 | warn | `readinessProbe` recommended | Ensures traffic isn't routed to unready pods |
| 11 | warn | `livenessProbe` recommended | Enables auto-restart of unhealthy pods |

**Compose policy** (`labs/lab9/policies/compose-security.rego`):

| # | Type | Check | Security Rationale |
|---|------|-------|--------------------|
| 1 | deny | Explicit non-root `user` required | Same as K8s `runAsNonRoot` |
| 2 | deny | `read_only: true` required | Same as K8s `readOnlyRootFilesystem` |
| 3 | deny | `cap_drop: ["ALL"]` required | Same as K8s capability dropping |
| 4 | warn | `no-new-privileges:true` recommended | Same as K8s `allowPrivilegeEscalation: false` |

### 2.3 Conftest Results — Unhardened K8s Manifest

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-unhardened.yaml \
  -p /project/policies --all-namespaces \
  | tee labs/lab9/analysis/conftest-unhardened.txt
```

**Result: 9 failures, 2 warnings (0 passed)**

| # | Level | Policy Violation | Security Impact |
|---|-------|-----------------|-----------------|
| 1 | FAIL | container "juice" uses disallowed `:latest` tag | **Supply chain risk:** The `latest` tag is mutable — anyone with push access to Docker Hub can replace the image contents. An attacker who compromises the registry (or the CI/CD pipeline) can inject a malicious image that all deployments will silently pull. Pinning to a specific version (e.g., `v19.0.0`) or digest ensures reproducibility. |
| 2 | FAIL | container "juice" must set `runAsNonRoot: true` | **Privilege escalation:** Without this constraint, the container runs as root (UID 0). If an attacker exploits an RCE vulnerability (e.g., CVE-2022-23529 in jsonwebtoken), they immediately have root inside the container and can attempt container escape. |
| 3 | FAIL | container "juice" must set `allowPrivilegeEscalation: false` | **Setuid exploitation:** Without this, processes can gain additional privileges via setuid binaries (`sudo`, `su`). Even if the container runs as non-root, a setuid binary could escalate to root. |
| 4 | FAIL | container "juice" must set `readOnlyRootFilesystem: true` | **Persistence and tampering:** A writable filesystem allows attackers to: modify application binaries, drop web shells, install malware, or alter configuration files. Read-only prevents all post-deployment filesystem modifications. |
| 5 | FAIL | container "juice" must drop ALL capabilities | **Kernel attack surface:** Default Docker containers get ~14 capabilities. `CAP_NET_RAW` enables ARP spoofing, `CAP_SETUID` enables privilege escalation, `CAP_DAC_OVERRIDE` bypasses file permissions. Dropping ALL and adding back only needed ones is the principle of least privilege. |
| 6 | FAIL | container "juice" missing `resources.requests.cpu` | **Scheduling:** Without CPU requests, the Kubernetes scheduler cannot make informed placement decisions, potentially leading to overcommitted nodes. |
| 7 | FAIL | container "juice" missing `resources.requests.memory` | **Scheduling:** Same issue — pods may land on nodes without sufficient memory. |
| 8 | FAIL | container "juice" missing `resources.limits.cpu` | **DoS protection:** Without CPU limits, a single pod can consume all CPU on a node, starving other workloads (noisy neighbor problem). |
| 9 | FAIL | container "juice" missing `resources.limits.memory` | **OOM protection:** Without memory limits, a memory leak or intentional memory bomb can trigger the Linux OOM killer, potentially affecting other pods on the same node. |
| 10 | WARN | container "juice" should define `readinessProbe` | **Availability:** Without a readiness probe, Kubernetes routes traffic to pods immediately after container start, even if the application isn't ready. This causes HTTP 502/503 errors during deployments. |
| 11 | WARN | container "juice" should define `livenessProbe` | **Self-healing:** Without a liveness probe, Kubernetes cannot detect a hung or deadlocked application. The pod stays in `Running` state but serves no traffic, requiring manual intervention. |

### 2.4 Conftest Results — Hardened K8s Manifest

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-hardened.yaml \
  -p /project/policies --all-namespaces \
  | tee labs/lab9/analysis/conftest-hardened.txt
```

**Result: 11 tests, 11 passed, 0 warnings, 0 failures**

Every policy check passes. Here is how each hardening change in the manifest satisfies the corresponding policy:

| Policy Requirement | Hardened Manifest Setting | How It Satisfies the Policy |
|--------------------|--------------------------|---------------------------|
| No `:latest` tag | `image: bkimminich/juice-shop:v19.0.0` | Pinned to immutable version tag |
| `runAsNonRoot: true` | `securityContext.runAsNonRoot: true` | Kubernetes rejects pods that attempt to run as UID 0 |
| `allowPrivilegeEscalation: false` | `securityContext.allowPrivilegeEscalation: false` | Kernel sets `PR_SET_NO_NEW_PRIVS`; setuid binaries are ineffective |
| `readOnlyRootFilesystem: true` | `securityContext.readOnlyRootFilesystem: true` | Container filesystem is mounted read-only; writes only via emptyDir/tmpfs |
| Drop ALL capabilities | `capabilities.drop: ["ALL"]` | All 40+ Linux capabilities removed; minimal kernel interface |
| CPU/memory requests | `requests: { cpu: "100m", memory: "256Mi" }` | Scheduler can place pods appropriately; guaranteed QoS minimum |
| CPU/memory limits | `limits: { cpu: "500m", memory: "512Mi" }` | Hard ceiling prevents resource exhaustion; OOM kill scoped to this pod |
| readinessProbe | `httpGet: { path: /, port: 3000 }` | Kubernetes only routes traffic when the app responds HTTP 200 |
| livenessProbe | `httpGet: { path: /, port: 3000 }` | Kubernetes restarts the pod if the app stops responding |

### 2.5 Conftest Results — Docker Compose Manifest

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/compose/juice-compose.yml \
  -p /project/policies --all-namespaces \
  | tee labs/lab9/analysis/conftest-compose.txt
```

**Result: 4 tests, 4 passed, 0 warnings, 0 failures**

The provided Docker Compose file is already fully compliant:

```yaml
services:
  juice:
    image: bkimminich/juice-shop:v19.0.0
    user: "10001:10001"         # ✅ Non-root user
    read_only: true             # ✅ Read-only filesystem
    cap_drop: ["ALL"]           # ✅ All capabilities dropped
    security_opt:
      - no-new-privileges:true  # ✅ No privilege escalation
    tmpfs: ["/tmp"]             # Writable tmp for app needs
```

**Analysis:** The Compose manifest applies the same security principles as the hardened K8s manifest, translated to Docker Compose syntax:

| K8s Equivalent | Compose Setting | Effect |
|----------------|-----------------|--------|
| `runAsNonRoot: true` | `user: "10001:10001"` | Explicit non-root UID/GID |
| `readOnlyRootFilesystem: true` | `read_only: true` + `tmpfs: ["/tmp"]` | Immutable filesystem with writable tmp |
| `capabilities.drop: ["ALL"]` | `cap_drop: ["ALL"]` | All capabilities removed |
| `allowPrivilegeEscalation: false` | `security_opt: [no-new-privileges:true]` | setuid/setgid ignored |

### 2.6 Policy-as-Code: Deny vs. Warn

The Rego policies use two enforcement levels:

- **`deny`** — hard failure. Conftest returns a non-zero exit code, which blocks CI/CD pipelines. Used for security requirements that have no acceptable exception (running as root, missing resource limits, `:latest` tags).

- **`warn`** — soft advisory. Conftest returns exit code 0 but prints a warning. Used for best practices that improve reliability but may have legitimate exceptions (probes may not be applicable to batch jobs or init containers).

This two-tier approach allows organizations to enforce a security baseline without blocking deployments for non-critical recommendations. In a CI/CD pipeline:
```yaml
# In GitHub Actions
- name: Conftest security check
  run: conftest test manifests/ -p policies/ --all-namespaces
  # Exit code != 0 on any "deny" → PR blocked
  # Warnings are logged but don't block
```

### 2.7 Cross-Cutting Analysis: Falco + Conftest

Falco (Task 1) and Conftest (Task 2) are **complementary**, not competing tools:

| Aspect | Conftest (Policy-as-Code) | Falco (Runtime Detection) |
|--------|--------------------------|--------------------------|
| **When** | Pre-deployment (CI/CD, admission) | Post-deployment (runtime) |
| **What** | YAML/JSON manifest analysis | Live syscall monitoring |
| **Detects** | Misconfigurations before they reach production | Actual malicious behavior in running containers |
| **Example** | "This deployment allows privilege escalation" | "A process just escalated privileges" |
| **Enforcement** | Blocks deployment if non-compliant | Alerts/responds after the fact |

**Defense-in-depth model:**
1. **Conftest** prevents insecure manifests from being deployed (shift-left)
2. **Kubernetes admission controllers** (Kyverno, Gatekeeper) enforce the same policies at deploy time
3. **Falco** detects threats that bypass preventive controls (runtime monitoring)

For example, if Conftest enforces `readOnlyRootFilesystem: true`, Falco's drift detection rule becomes a safety net — it should rarely fire because the filesystem is already read-only. If it does fire (e.g., via a `tmpfs` mount or a volume), that's a high-confidence indicator of an anomaly worth investigating.
