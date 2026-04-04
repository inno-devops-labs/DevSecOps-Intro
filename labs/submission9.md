# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### 1.1 Baseline alerts observed (Falco log evidence)
From `labs/lab9/falco/logs/falco.log`:
- **Terminal shell in container** (Notice) at `2026-04-04T18:04:19Z` for `lab9-helper` - triggered by `sh -lc echo hello-from-shell` (rule: `Terminal shell in container`).
- **Custom rule hit** (Warning) at `2026-04-04T18:06:49Z` for `lab9-helper` - file write to `/usr/local/bin/custom-rule.txt` (rule: `Write Binary Under UsrLocalBin`).

Additional Falco event-generator alerts captured (evidence that Falco is detecting runtime threats):
- `Disallowed SSH Connection Non Standard Port` (Notice)
- `Drop and execute new binary in container` (Critical)
- `Read sensitive file untrusted` (Warning)
- `Execution from /dev/shm` (Warning)
- `Fileless execution via memfd_create` (Critical)
- `Detect release_agent File Container Escapes` (Critical)

### 1.2 Custom rule summary and tuning
File: `labs/lab9/falco/rules/custom-rules.yaml`

**Rule name:** `Write Binary Under UsrLocalBin`

**Purpose:** Detects any writable file creation or modification under `/usr/local/bin` inside a container. This is a common drift indicator (binaries or scripts dropped into writable paths at runtime).

**When it should fire:**
- Any container writes a file under `/usr/local/bin` (e.g., `echo test > /usr/local/bin/custom-rule.txt`).

**When it should NOT fire (tuning intent):**
- Host processes (condition excludes `container.id == host`).
- Containers that never write to `/usr/local/bin` (normal immutable image behavior).

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### 2.1 Unhardened manifest violations (and why they matter)
Source: `labs/lab9/analysis/conftest-unhardened.txt`

Violations for `juice-unhardened.yaml`:
- Missing `resources.requests.cpu` and `resources.requests.memory` - without requests the scheduler cannot reserve capacity, causing noisy neighbors and unstable QoS.
- Missing `resources.limits.cpu` and `resources.limits.memory` - without limits a container can exhaust node resources (DoS risk).
- Missing `allowPrivilegeEscalation: false` - allows privilege escalation if a process gains extra capabilities.
- Missing `readOnlyRootFilesystem: true` - writable root FS increases attack surface and persistence of malware.
- Missing `runAsNonRoot: true` - running as root is a high‑risk default.
- Uses image tag `:latest` - mutable tags break provenance and reproducibility.

Warnings:
- Missing `readinessProbe` and `livenessProbe` - weak health detection and rollout safety (not a hard security requirement but important for resilience).

### 2.2 Hardening changes that satisfy policies
Comparing `juice-hardened.yaml` to `juice-unhardened.yaml`:
- **Pinned image tag**: `bkimminich/juice-shop:v19.0.0` (removes `:latest`).
- **Security context**:
  - `runAsNonRoot: true`
  - `allowPrivilegeEscalation: false`
  - `readOnlyRootFilesystem: true`
  - `capabilities.drop: ["ALL"]`
- **Resource controls**:
  - `requests`: `cpu: 100m`, `memory: 256Mi`
  - `limits`: `cpu: 500m`, `memory: 512Mi`
- **Health checks**:
  - `readinessProbe` and `livenessProbe` added (HTTP GET on `/`).

Conftest result for hardened manifest: `30 tests, 30 passed, 0 warnings, 0 failures` (`labs/lab9/analysis/conftest-hardened.txt`).

### 2.3 Docker Compose manifest analysis
Manifest: `labs/lab9/manifests/compose/juice-compose.yml`

Conftest result: `15 tests, 15 passed, 0 warnings, 0 failures` (`labs/lab9/analysis/conftest-compose.txt`).

Why it passes the policy checks:
- Explicit **non-root user**: `user: "10001:10001"`.
- **Read-only filesystem**: `read_only: true`.
- **Dropped capabilities**: `cap_drop: ["ALL"]`.
- **No-new-privileges** enabled: `security_opt: ["no-new-privileges:true"]`.
- **Tmpfs for /tmp**: provides a writable temp area without opening the full filesystem.

---

## Files Produced (Evidence)
- `labs/lab9/falco/logs/falco.log`
- `labs/lab9/falco/rules/custom-rules.yaml`
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`
