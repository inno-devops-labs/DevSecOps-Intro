# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### 1.1 Setup

- **Helper container:** `lab9-helper` from `alpine:3.19` (`sleep 1d`), used to generate in-container activity.
- **Falco:** `falcosecurity/falco:latest` with the lab mounts (`/proc`, `/boot`, `/lib/modules`, `/usr`, Docker socket) and custom rules mounted at `labs/lab9/falco/rules` → `/etc/falco/rules.d`.
- **Output:** JSON lines on stdout (`falco -U -o json_output=true -o time_format_iso_8601=true`), matching the lab instructions.

On **Docker Desktop (WSL2 backend)**, the syscall source can take roughly **60–90 seconds** after container start before Falco is fully ready (health endpoint on port 8765 returns HTTP 200). Until then, wait before triggering alerts.

Full capture is saved at **`labs/lab9/falco/logs/falco.log`**.

### 1.2 Baseline alerts (lab workflow)

The lab asks for (A) a shell-related signal and (B) drift under a binary path.

**A) Shell-related detection**

`docker exec` from PowerShell without a real TTY often **does not** trigger the stock rule *Terminal shell in container* (the lab’s “expected” name in the handout), because that rule is sensitive to interactive terminal context.

To still **validate** that Falco raises shell- and execution-related alerts end-to-end, the **`falcosecurity/event-generator`** step (lab §1.5) was run. Example rules that appear in `falco.log` for that workload include:

- **Run shell untrusted** — shell execution patterns associated with untrusted parents (MITRE execution / shell tags).
- **Debugfs Launched in Privileged Container**, **Netcat Remote Code Execution in Container**, and other syscall-suite alerts — they confirm the eBPF pipeline and rule engine are working.

**B) Drift / write under a binary directory**

As root inside `lab9-helper`, writes were performed under `/usr/local/bin/` (e.g. `drift.txt`, then after `SIGHUP` reload, `custom-rule.txt`). These are the primary **lab9-helper**-scoped baseline for “unexpected writes where binaries live.”

### 1.3 Custom rule — *Write Binary Under UsrLocalBin*

**File:** `labs/lab9/falco/rules/custom-rules.yaml`

**Purpose:** Emit a **WARNING** when a process opens a path under `/usr/local/bin/` for write (`open` / `openat` / `openat2` / `creat` with `evt.is_open_write=true`) inside a non-host container context. This supports **compliance / drift** use cases: new or modified content under binary directories is often suspicious in immutable or image-pinned workloads.

**When it should fire:** Legitimate package installs or admin maintenance that write new binaries or scripts under `/usr/local/bin/` inside a container.

**When it should not fire (or may be noisy):** Build images that intentionally populate `/usr/local/bin/` during image build (those events occur at build time, not always at runtime). Tune with `container.image.repository`, namespaces, or macro allowlists if needed in production.

**Evidence in `falco.log` (JSON, `rule` field):**

- `Write Binary Under UsrLocalBin` for `fd.name` `/usr/local/bin/drift.txt` and `/usr/local/bin/custom-rule.txt`, `container.name=lab9-helper`, `user.name=root`.

Rules were reloaded with `docker kill --signal=SIGHUP falco` before the second write, as in the lab text.

### 1.4 Event generator (§1.5)

`falcosecurity/event-generator:latest run syscall` was executed with the documented privileged mounts. The log contains a **burst** of alerts (sensitive file reads, ptrace, SSH patterns, container escape probes, etc.). This matches the lab goal: prove the detector stack is live and noisy in a controlled way.

---

## Task 2 — Policy-as-Code with Conftest (Rego)

Artifacts:

- **`labs/lab9/analysis/conftest-unhardened.txt`** — `juice-unhardened.yaml`
- **`labs/lab9/analysis/conftest-hardened.txt`** — `juice-hardened.yaml`
- **`labs/lab9/analysis/conftest-compose.txt`** — `juice-compose.yml`

### 2.1 Unhardened Kubernetes manifest — failures and why they matter

**Summary:** `30 tests, 20 passed, 2 warnings, 8 failures` (deny rules block; warn rules do not).

| Policy theme | Example violation | Risk |
|--------------|-------------------|------|
| **Image tag** | `:latest` disallowed | Non-reproducible deploys; surprise upgrades and harder incident response. |
| **Security context** | Missing `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]` | Higher chance of container breakout, writable filesystem abuse, and extra Linux capabilities. |
| **Resources** | No CPU/memory requests and limits | Noisy-neighbor issues, easier DoS, unpredictable scheduling. |

**Warnings (non-fatal):** missing `livenessProbe` and `readinessProbe` — availability and safe rollouts, not enforced as hard fails by these policies.

### 2.2 Hardened manifest — what changed

**File:** `labs/lab9/manifests/k8s/juice-hardened.yaml`

Compared to unhardened:

- **Image:** pinned tag `bkimminich/juice-shop:v19.0.0` (not `:latest`).
- **`securityContext`:** `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`.
- **`resources`:** requests and limits for CPU and memory.
- **Probes:** `readinessProbe` and `livenessProbe` on HTTP port 3000.

**Conftest result:** `30 tests, 30 passed, 0 warnings, 0 failures` — all `deny` and `warn` checks satisfied for this Deployment.

### 2.3 Docker Compose manifest

**File:** `labs/lab9/manifests/compose/juice-compose.yml`

The service uses a **pinned image**, **non-root user** (`10001:10001`), **read-only root filesystem** with `tmpfs` for writable `/tmp`, **`no-new-privileges`**, and **`cap_drop: ALL`**. That aligns with the compose-focused Rego checks.

**Conftest result:** `15 tests, 15 passed, 0 warnings, 0 failures`.

---

## Summary

| Deliverable | Location / outcome |
|-------------|----------------------|
| Custom Falco rules | `labs/lab9/falco/rules/custom-rules.yaml` |
| Falco alert evidence | `labs/lab9/falco/logs/falco.log` |
| Conftest outputs | `labs/lab9/analysis/conftest-*.txt` |
| Unhardened K8s | Fails policy (8 denies + 2 warns) |
| Hardened K8s | All tests pass |
| Compose | All tests pass |

Optional cleanup after capture (from `lab9.md`):

```bash
docker rm -f falco lab9-helper 2>/dev/null || true
```
