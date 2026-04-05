# Lab 9 Submission — Falco Runtime Detection + Conftest Policies

## Task 1 — Falco (runtime detection + custom rule)

### Setup

- Helper container: `lab9-helper` (`alpine:3.19`, `sleep 1d`).
- Falco: `falcosecurity/falco:latest` with modern BPF (`Opening 'syscall' source with modern BPF probe`), JSON output enabled.
- Custom rules mounted read-only: `labs/lab9/falco/rules/custom-rules.yaml` → `/etc/falco/rules.d/`.
- Full log capture: `labs/lab9/falco/logs/falco.log`.

### Baseline alerts observed

1. **Container drift / binary path writes (lab helper)**  
   The lab’s write under `/usr/local/bin` inside `lab9-helper` fired the **custom rule** `Write Binary Under UsrLocalBin` (see excerpt in `falco.log` for `drift.txt` and later `custom2.txt`).

2. **Shell / suspicious execution (event generator)**  
   `falcosecurity/event-generator:latest run syscall` produced multiple built-in alerts. Example: rule **`Run shell untrusted`** (shell spawned in the `eventgen` container during the syscall suite). Evidence: JSON line in `falco.log` containing `"rule":"Run shell untrusted"`.

**Note:** The lab’s `docker exec -it ...` baseline expects a TTY; in this non-interactive environment `-it` fails with “not a TTY”, so the classic “Terminal shell in container” style alert may not appear. The event-generator run still validates syscall-based detections.

### Custom rule: purpose and tuning

- **Rule:** `Write Binary Under UsrLocalBin` in `labs/lab9/falco/rules/custom-rules.yaml`.
- **Purpose:** Flag **new writes** under `/usr/local/bin/` from inside a container (common drift / supply-chain persistence pattern).
- **Should fire:** package installs, malware dropping binaries, unexpected writes to “binary” paths.
- **Should not fire (or should be tuned):** legitimate image builds where the app layer writes to `/usr/local/bin` during expected setup (would need narrower `container.image.repository` / `proc.name` allowlists or lower priority).

### Event generator

- Ran: `falcosecurity/event-generator:latest run syscall` (privileged, with `/proc` and `/dev` mounts as in the lab). Additional alerts (e.g. sensitive file reads, memfd execution) appear in `falco.log`.

---

## Task 2 — Conftest (policy-as-code)

### Manifest comparison (unhardened vs hardened)

| Area | `juice-unhardened.yaml` | `juice-hardened.yaml` |
|------|-------------------------|------------------------|
| Image tag | `bkimminich/juice-shop:latest` | Pinned `bkimminich/juice-shop:v19.0.0` |
| `securityContext` | Missing | `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]` |
| Resources | None | Requests + limits for CPU/memory |
| Probes | None | `readinessProbe` + `livenessProbe` HTTP on port 3000 |

### Policy review

- `labs/lab9/policies/k8s-security.rego` — **deny** rules for `:latest`, missing securityContext fields, missing resource requests/limits; **warn** for missing probes.
- `labs/lab9/policies/compose-security.rego` — requires explicit `user`, `read_only: true`, `cap_drop: ["ALL"]`; **warn** if `no-new-privileges` missing.

### Conftest results (evidence files)

- Unhardened (expected failures): `labs/lab9/analysis/conftest-unhardened.txt`  
  - **8 FAIL:** `:latest` tag, missing `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ALL`, and all four resource request/limit fields.  
  - **2 WARN:** missing readiness/liveness probes.

- Hardened (expected pass): `labs/lab9/analysis/conftest-hardened.txt` — **30 tests, 30 passed, 0 warnings, 0 failures.**

- Compose: `labs/lab9/analysis/conftest-compose.txt` — **15 tests, 15 passed** for `labs/lab9/manifests/compose/juice-compose.yml` (explicit user, read-only root, `cap_drop: ALL`, `no-new-privileges`).

### SELinux note (Fedora / enforcing)

Initial Conftest runs with a plain bind mount returned `permission denied` reading K8s YAML inside the container. Re-running with:

`docker run --rm --security-opt label=disable -v "$(pwd)/labs/lab9":/project ...`

resolved the issue. Compose succeeded earlier with `:Z` on the mount.

---

## Acceptance checklist

- [x] Task 1 — Falco runtime detection (alerts + custom rule + event generator); logs in `labs/lab9/falco/logs/falco.log`
- [x] Task 2 — Conftest policies exercised; unhardened fails, hardened passes; compose passes
