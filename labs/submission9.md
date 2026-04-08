# Lab 9 — Submission: Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

---

## Task 1 — Runtime Security Detection with Falco (6 pts)

### 1.1 — Setup

**Helper container:** `alpine:3.19` named `lab9-helper` running `sleep 1d`.

**Falco container:** `falcosecurity/falco:0.43.0` (aarch64), started with `--privileged`, modern eBPF engine, custom rules directory mounted at `/etc/falco/rules.d`.

```bash
docker run -d --name lab9-helper alpine:3.19 sleep 1d

docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U \
        -o json_output=true \
        -o time_format_iso_8601=true \
        -o engine.kind=modern_ebpf
```

Falco startup confirmed custom rules were loaded:
```
Loading rules from:
   /etc/falco/falco_rules.yaml | schema validation: ok
   /etc/falco/falco_rules.local.yaml | schema validation: none
   /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
Opening 'syscall' source with modern BPF probe.
```

> Note: Running on macOS (Docker Desktop / LinuxKit VM) means `/boot` and `/lib/modules` are unavailable as macOS host paths. These mounts are only needed for the kernel module driver; the `modern_ebpf` driver is self-contained and does not require them. Falco ran successfully with the reduced mount set.

---

### 1.2 — Baseline Alerts Observed

#### Alert A — Terminal shell in container (Rule: `Terminal shell in container`)

**Trigger command:**
```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**Raw Falco alert (JSON):**
```json
{
  "hostname": "a35637023ebd",
  "output": "2026-04-08T20:22:56.555764488+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=4380de84c0be container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": ["T1059", "container", "maturity_stable", "mitre_execution", "shell"],
  "time": "2026-04-08T20:22:56.555764488Z"
}
```

**Why this matters:** Spawning an interactive shell (`/bin/sh -l`) inside a running container is a common indicator of post-exploitation activity (MITRE ATT&CK T1059). Legitimate containerized applications should never need an interactive shell at runtime. Falco detects the `execve` syscall for `sh`/`bash` with a TTY attached.

---

#### Alert B — Container drift: write to `/usr/local/bin` (Custom rule: `Write Binary Under UsrLocalBin`)

**Trigger command:**
```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

**Raw Falco alert (JSON):**
```json
{
  "hostname": "a35637023ebd",
  "output": "2026-04-08T20:23:02.054195907+0000: Warning Falco Custom: File write in /usr/local/bin (container=lab9-helper user=root file=/usr/local/bin/drift.txt flags=O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER)",
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "source": "syscall",
  "tags": ["compliance", "container", "drift"],
  "time": "2026-04-08T20:23:02.054195907Z"
}
```

**Why this matters:** Writing new files into `/usr/local/bin` at runtime is a container drift indicator — the container filesystem has been modified relative to its image. This is a common persistence/lateral-movement technique where attackers drop malicious binaries into `$PATH` directories.

---

### 1.3 — Custom Rule

**File:** `labs/lab9/falco/rules/custom-rules.yaml`

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

**Purpose:** Detect any file creation or write event targeting `/usr/local/bin/` inside a container. This catches container drift: runtime modifications to binary PATH directories that were not present in the original image.

**Should fire when:**
- Any process inside a container opens a file under `/usr/local/bin/` with a write flag (`O_WRONLY`, `O_RDWR`, `O_CREAT`, etc.)
- Triggered by `echo > /usr/local/bin/x`, `cp`, `install`, `tee`, or any tool writing into that directory

**Should NOT fire when:**
- The same write happens on the host (outside any container), because `container.id != host` filters out non-container events
- Read-only operations (`cat`, `ls`, `stat`) against `/usr/local/bin/` — `evt.is_open_write=true` ensures only write-mode opens match

**Validation — custom rule fired twice:**
```
2026-04-08T20:23:02Z [Warning] Write Binary Under UsrLocalBin — /usr/local/bin/drift.txt
2026-04-08T20:23:07Z [Warning] Write Binary Under UsrLocalBin — /usr/local/bin/custom-rule.txt
```

---

### 1.4 — Event Generator Alerts

Running `falcosecurity/event-generator` produced 25 total alerts across multiple severity levels. A representative sample:

| Time (UTC)              | Priority      | Rule                                           |
|-------------------------|---------------|------------------------------------------------|
| 20:23:31.612Z           | Warning       | Find AWS Credentials                           |
| 20:23:31.713Z           | Warning       | Search Private Keys or Passwords               |
| 20:23:37.942Z           | Warning       | Read sensitive file untrusted                  |
| 20:23:38.044Z           | Notice        | Packet socket created in container             |
| 20:23:38.155Z           | Warning       | Clear Log Activities                           |
| 20:23:38.358Z           | Warning       | Execution from /dev/shm                        |
| 20:23:38.773Z           | Notice        | Disallowed SSH Connection Non Standard Port    |
| 20:23:42.280Z           | **Critical**  | Detect release_agent File Container Escapes    |
| 20:23:42.480Z           | **Critical**  | Fileless execution via memfd_create            |
| 20:23:42.713Z           | Warning       | Debugfs Launched in Privileged Container       |
| 20:23:42.926Z           | Warning       | Remove Bulk Data from Disk                     |
| 20:23:43.031Z           | Warning       | PTRACE attached to process                     |
| 20:23:43.237Z           | Warning       | Netcat Remote Code Execution in Container      |
| 20:23:43.597Z           | **Critical**  | Drop and execute new binary in container       |
| 20:23:43.812Z           | Warning       | Create Symlink Over Sensitive Files            |

Full log saved to `labs/lab9/falco/logs/falco.log`.

---

## Task 2 — Policy-as-Code with Conftest (Rego) (4 pts)

### 2.1 — Manifest Comparison

#### `juice-unhardened.yaml` (baseline)

```yaml
containers:
  - name: juice
    image: bkimminich/juice-shop:latest  # floating tag
    ports:
      - containerPort: 3000
    # No securityContext
    # No resources
    # No probes
```

#### `juice-hardened.yaml` (compliant)

```yaml
containers:
  - name: juice
    image: bkimminich/juice-shop:v19.0.0   # pinned tag
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

---

### 2.2 — Conftest Results

#### Unhardened manifest — `conftest-unhardened.txt`

```
WARN - juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

#### Hardened manifest — `conftest-hardened.txt`

```
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

#### Docker Compose manifest — `conftest-compose.txt`

```
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

---

### 2.3 — Policy Violation Analysis (Unhardened Manifest)

| Violation | Security Implication | Fix in Hardened Manifest |
|-----------|---------------------|--------------------------|
| Uses `:latest` tag | Non-deterministic deployments; attacker could replace image content between pulls | Pinned to `v19.0.0` |
| `runAsNonRoot` not set | Container runs as UID 0 (root), giving full filesystem access inside container and increasing blast radius on breakout | `runAsNonRoot: true` |
| `allowPrivilegeEscalation` not set | Process can call `setuid`/`setgid` to escalate to root even if started as non-root (via SUID binaries) | `allowPrivilegeEscalation: false` |
| `readOnlyRootFilesystem` not set | Container can write anywhere in its filesystem, enabling in-memory payloads, log tampering, or config modification | `readOnlyRootFilesystem: true` |
| Capabilities not dropped | Container inherits default Linux capabilities (e.g., `NET_RAW`, `SYS_CHROOT`) that enable network sniffing and namespace attacks | `capabilities.drop: ["ALL"]` |
| No `resources.requests.*` | Scheduler cannot make informed placement decisions; container could starve other workloads of CPU/memory | `requests: {cpu: 100m, memory: 256Mi}` |
| No `resources.limits.*` | Unbounded resource consumption; a single compromised container can cause node-level denial of service | `limits: {cpu: 500m, memory: 512Mi}` |
| No `readinessProbe` (warn) | Kubernetes cannot determine when container is ready; traffic is sent to unready pods | Added `httpGet` probe |
| No `livenessProbe` (warn) | Kubernetes cannot detect if the application has deadlocked or become unresponsive | Added `httpGet` probe |

---

### 2.4 — Docker Compose Policy Analysis

The `juice-compose.yml` passes all 15 Conftest checks. The `compose-security.rego` policy enforces:

| Policy Check | Value in `juice-compose.yml` | Status |
|--------------|------------------------------|--------|
| Explicit non-root user set | `user: "10001:10001"` | PASS |
| `read_only: true` | `read_only: true` | PASS |
| `cap_drop: ["ALL"]` | `cap_drop: ["ALL"]` | PASS |
| `no-new-privileges:true` in `security_opt` | `security_opt: [no-new-privileges:true]` | PASS |

The Docker Compose manifest also uses a `tmpfs` mount at `/tmp` to allow the application's temporary writes while keeping the root filesystem read-only — this is the correct pattern for `readOnlyRootFilesystem`-equivalent hardening in Compose.

---

## Summary

| Task | Status | Evidence |
|------|--------|----------|
| Falco running with modern eBPF | ✅ | `docker logs falco` — startup messages confirm `modern BPF probe` |
| Baseline alert: Terminal shell in container | ✅ | JSON alert at `20:22:56Z`, rule `Terminal shell in container` |
| Baseline alert: Container drift (write /usr/local/bin) | ✅ | JSON alert at `20:23:02Z`, rule `Write Binary Under UsrLocalBin` |
| Custom rule created and validated | ✅ | `labs/lab9/falco/rules/custom-rules.yaml`, fired at `20:23:02Z` and `20:23:07Z` |
| Event generator run (25 alerts) | ✅ | Full log in `labs/lab9/falco/logs/falco.log` |
| Conftest: unhardened K8s fails (8 failures) | ✅ | `labs/lab9/analysis/conftest-unhardened.txt` |
| Conftest: hardened K8s passes (30/30) | ✅ | `labs/lab9/analysis/conftest-hardened.txt` |
| Conftest: Docker Compose passes (15/15) | ✅ | `labs/lab9/analysis/conftest-compose.txt` |
