# Lab 9 Submission — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### 1.1 Setup

Started a BusyBox helper container and ran Falco 0.43.0 with modern eBPF:

```bash
docker run -d --name lab9-helper alpine:3.19 sleep 1d

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

Falco loaded rules including `custom-rules.yaml` from `/etc/falco/rules.d/`:

```
2026-04-06T12:34:54+0000: Loading rules from:
   /etc/falco/falco_rules.yaml | schema validation: ok
   /etc/falco/falco_rules.local.yaml | schema validation: none
   /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
2026-04-06T12:34:54+0000: Opening 'syscall' source with modern BPF probe.
```

---

### 1.2 Custom Falco Rule

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

**Purpose:** Detects container image drift — any write to `/usr/local/bin/` inside a running container indicates that an attacker (or misconfigured process) is modifying the binary path, which is a common technique for persistence or backdoor injection.

**Should fire when:** A process inside a container creates or writes any file under `/usr/local/bin/` (e.g., an attacker planting a malicious binary, a compromised app downloading and installing tools at runtime).

**Should NOT fire when:** The action occurs on the host (not inside a container), or during a legitimate image build stage (container.id == host). Read-only accesses also do not trigger it.

---

### 1.3 Baseline Alerts from `falco.log`

**Alert A — Custom rule: drift write to `/usr/local/bin/`**

Triggered by:
```bash
docker exec --user 0 lab9-helper /bin/sh -c 'echo boom > /usr/local/bin/drift.txt'
```

Raw JSON alert:
```json
{
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "time": "2026-04-06T12:35:16.520326418Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "container.image.repository": "alpine",
    "container.image.tag": "3.19",
    "fd.name": "/usr/local/bin/drift.txt",
    "user.name": "root",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER"
  }
}
```

**Alert B — Custom rule: second drift write (custom rule validation)**

Triggered by:
```bash
docker exec --user 0 lab9-helper /bin/sh -c 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

Raw JSON alert:
```json
{
  "priority": "Warning",
  "rule": "Write Binary Under UsrLocalBin",
  "time": "2026-04-06T12:35:19.564185157Z",
  "output_fields": {
    "container.name": "lab9-helper",
    "fd.name": "/usr/local/bin/custom-rule.txt",
    "user.name": "root",
    "evt.arg.flags": "O_LARGEFILE|O_TRUNC|O_CREAT|O_WRONLY|O_F_CREATED|FD_UPPER_LAYER"
  }
}
```

Both writes confirmed `FD_UPPER_LAYER` in flags, meaning they were written to the container's writable overlay layer — exactly the drift pattern the rule targets.

---

### 1.4 Event Generator Alerts

Run with `falcosecurity/event-generator:latest run syscall`. Produced 24 alerts across all severity levels:

| Priority     | Rule                                          |
|--------------|-----------------------------------------------|
| Critical     | Fileless execution via memfd_create           |
| Critical     | Drop and execute new binary in container      |
| Critical     | Detect release_agent File Container Escapes   |
| Warning      | Write Binary Under UsrLocalBin (custom)       |
| Warning      | Directory traversal monitored file read       |
| Warning      | Find AWS Credentials                          |
| Warning      | Debugfs Launched in Privileged Container      |
| Warning      | PTRACE attached to process                    |
| Warning      | Remove Bulk Data from Disk                    |
| Warning      | Search Private Keys or Passwords              |
| Warning      | Read sensitive file trusted after startup     |
| Warning      | Clear Log Activities                          |
| Warning      | Execution from /dev/shm                       |
| Warning      | Read sensitive file untrusted                 |
| Warning      | Netcat Remote Code Execution in Container     |
| Warning      | Create Hardlink Over Sensitive Files          |
| Warning      | Create Symlink Over Sensitive Files           |
| Notice       | Run shell untrusted                           |
| Notice       | Packet socket created in container            |
| Notice       | Disallowed SSH Connection Non Standard Port   |
| Notice       | PTRACE anti-debug attempt                     |
| Informational| System user interactive                       |

This confirms the Falco setup is fully functional with modern eBPF on kernel 6.8.0-106-generic.

---

### 1.5 Tuning Notes / Noise Reduction

In production environments the following rules commonly generate false positives and would need tuning:

- **"Read sensitive file trusted after startup"** — legitimate apps (e.g., logging agents, config managers) read `/etc/passwd` at runtime; add trusted images to the macro `trusted_containers`.
- **"Run shell untrusted"** — CI pipeline containers often run shell scripts; exclude by `container.image.repository` using a macro list.
- **"System user interactive"** — monitoring agents that run as system users (uid < 1000) generate this; add them to `user_known_system_user_login_binaries`.
- **Custom "Write Binary Under UsrLocalBin"** — if a container legitimately installs tooling at startup (e.g., a sidecar init container), exclude it by adding `container.name != "my-init-sidecar"` to the condition.

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### 2.1 Manifests Compared

**`juice-unhardened.yaml`** — Bare minimum deployment:
- Image: `bkimminich/juice-shop:latest` (floating tag)
- No `securityContext` defined
- No resource requests or limits
- No readiness/liveness probes

**`juice-hardened.yaml`** — Compliant deployment:
- Image: `bkimminich/juice-shop:v19.0.0` (pinned tag)
- `securityContext.runAsNonRoot: true`
- `securityContext.allowPrivilegeEscalation: false`
- `securityContext.readOnlyRootFilesystem: true`
- `capabilities.drop: ["ALL"]`
- `resources.requests`: cpu=100m, memory=256Mi
- `resources.limits`: cpu=500m, memory=512Mi
- `readinessProbe` and `livenessProbe` defined

---

### 2.2 Policies Summary

**`k8s-security.rego`** (package `k8s.security`):
- `deny`: `:latest` image tag, missing `runAsNonRoot`, `allowPrivilegeEscalation` not false, `readOnlyRootFilesystem` not true, capabilities not dropping ALL, missing CPU/memory requests and limits
- `warn`: missing `readinessProbe` and `livenessProbe`

**`compose-security.rego`** (package `compose.security`):
- `deny`: missing `user`, missing `read_only: true`, capabilities not dropping ALL
- `warn`: missing `no-new-privileges:true` in `security_opt`

---

### 2.3 Conftest Results

#### Unhardened K8s manifest — `conftest-unhardened.txt`

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

**Violation analysis:**

| Violation | Security Impact |
|-----------|----------------|
| `:latest` tag | Non-deterministic deployments; different image may be pulled on each restart, breaking reproducibility and potentially introducing a malicious update |
| `runAsNonRoot: false` | Process runs as UID 0; if exploited, attacker has root inside container and can escape via privilege escalation vectors |
| `allowPrivilegeEscalation: true` | Child processes can gain more privileges than parent (e.g., via setuid binaries), allowing privilege escalation within the container |
| `readOnlyRootFilesystem: false` | Attacker can modify the container filesystem at runtime, plant backdoors, or tamper with application binaries |
| Missing `capabilities.drop: ALL` | Container retains Linux capabilities (e.g., `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`) that could be used for network attacks or host escapes |
| Missing resource limits | Container can consume unlimited CPU/memory, enabling DoS against co-located workloads or the entire node |
| Missing probes | Kubernetes cannot detect a stuck/unhealthy container and will continue routing traffic to it |

---

#### Hardened K8s manifest — `conftest-hardened.txt`

```
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

All 30 policy checks pass. The hardening changes directly address each violation:

| Hardening Change | Policy Satisfied |
|-----------------|-----------------|
| `image: ...v19.0.0` | No `:latest` tag |
| `runAsNonRoot: true` | Container runs as non-root UID |
| `allowPrivilegeEscalation: false` | No child privilege escalation |
| `readOnlyRootFilesystem: true` | Immutable container filesystem |
| `capabilities.drop: ["ALL"]` | Minimal Linux capability surface |
| `resources.requests` + `limits` | CPU/memory bounded (DoS prevention) |
| `readinessProbe` + `livenessProbe` | Health checks for K8s traffic management |

---

#### Docker Compose manifest — `conftest-compose.txt`

```
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

The `juice-compose.yml` is already fully hardened:
- `user: "10001:10001"` — explicit non-root UID/GID (satisfies `deny`)
- `read_only: true` — immutable container filesystem (satisfies `deny`)
- `cap_drop: ["ALL"]` — drops all Linux capabilities (satisfies `deny`)
- `security_opt: [no-new-privileges:true]` — prevents privilege escalation (satisfies `warn`)
- `tmpfs: ["/tmp"]` — provides a writable `/tmp` area despite `read_only: true`

The Docker Compose policy mirrors Kubernetes hardening principles applied to the Compose runtime, demonstrating that the same security controls are important regardless of orchestrator.

---

## Checklist

- [x] Task 1 — Falco runtime detection (alerts + custom rule)
- [x] Task 2 — Conftest policies (fail→pass hardening)
