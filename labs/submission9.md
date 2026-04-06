# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco (6 pts)

### Execution Summary

- Created Falco directories and custom rule file:
  - `labs/lab9/falco/rules/custom-rules.yaml`
- Started helper container:
  - `docker run -d --name lab9-helper alpine:3.19 sleep 1d`
- Started Falco with modern eBPF and Docker socket context:
  - `docker run -d --name falco --privileged ... falcosecurity/falco:latest falco -U -o json_output=true -o time_format_iso_8601=true`
- Triggered baseline events in `lab9-helper`:
  - shell exec (`sh -lc ...`)
  - write under `/usr/local/bin`
- Reloaded Falco rules using `SIGHUP`.
- Triggered custom-rule validation write under `/usr/local/bin/custom-rule.txt`.
- Ran Falco event generator syscall profile:
  - `docker run --rm --name eventgen --privileged ... falcosecurity/event-generator:latest run syscall`

### Baseline + Custom Alerts Observed

From `labs/lab9/analysis/falco-alert-excerpts.txt`:

- `2026-04-06T19:15:21.952559663Z` — `Terminal shell in container` (built-in baseline)
- `2026-04-06T19:09:48.839682574Z` — `Write Binary Under UsrLocalBin` (custom)
- `2026-04-06T19:10:07.912727790Z` — `Write Binary Under UsrLocalBin` (custom validation)

From event generator runs, Falco additionally detected multiple high-signal behaviors (e.g., `Detect release_agent File Container Escapes`, `Fileless execution via memfd_create`, `Run shell untrusted`).

`labs/lab9/analysis/falco-summary.txt` final count:
- Total alerts: `69`
- Includes both baseline and custom detections plus event-generator bursts.

### Custom Rule Purpose and Tuning Notes

Rule: `Write Binary Under UsrLocalBin`

Purpose:
- Detect container drift / suspicious writes into executable path `/usr/local/bin/`.

Why it should fire:
- Any write/create/open-for-write operation in `/usr/local/bin/` from container context.

Why it should not fire:
- Read-only file opens.
- Writes outside `/usr/local/bin/`.
- Host-side writes (filtered with `container.id != host`).

Noise-tuning choices in rule:
- `evt.is_open_write=true` limits to write intent.
- `fd.name startswith /usr/local/bin/` narrows scope to binary-like path.
- `container.id != host` excludes host process activity.

## Task 2 — Policy-as-Code with Conftest (4 pts)

### Conftest Results

- Unhardened manifest (`juice-unhardened.yaml`): `30 tests, 20 passed, 2 warnings, 8 failures`
- Hardened manifest (`juice-hardened.yaml`): `30 tests, 30 passed, 0 warnings, 0 failures`
- Compose manifest (`juice-compose.yml`): `15 tests, 15 passed, 0 warnings, 0 failures`

### Violations in Unhardened K8s Manifest and Why They Matter

Failures reported:

- `uses disallowed :latest tag`
  - Risk: mutable image tags reduce deploy reproducibility and trust.
- `must set runAsNonRoot: true`
  - Risk: root in container increases blast radius if compromised.
- `must set allowPrivilegeEscalation: false`
  - Risk: process can gain elevated privileges after start.
- `must set readOnlyRootFilesystem: true`
  - Risk: attacker can persist/modify runtime filesystem.
- Missing `resources.requests.*` and `resources.limits.*`
  - Risk: unstable scheduling and potential noisy-neighbor/DoS conditions.

Warnings reported:
- Missing `readinessProbe`
- Missing `livenessProbe`
  - Risk: weaker resilience and health-based recovery behavior.

### Hardening Changes That Satisfy Policies

Using `labs/lab9/manifests/k8s/juice-hardened.yaml` and diff evidence:

- Pinned image to version tag: `bkimminich/juice-shop:v19.0.0`
- Added `securityContext`:
  - `runAsNonRoot: true`
  - `allowPrivilegeEscalation: false`
  - `readOnlyRootFilesystem: true`
  - `capabilities.drop: ["ALL"]`
- Added resources:
  - `requests` CPU/memory
  - `limits` CPU/memory
- Added probes:
  - `readinessProbe`
  - `livenessProbe`

These changes directly map to the deny/warn checks in `labs/lab9/policies/k8s-security.rego`, resulting in full pass.

### Docker Compose Manifest Analysis

`labs/lab9/manifests/compose/juice-compose.yml` already satisfies `compose-security.rego`:

- Explicit non-root user: `user: "10001:10001"`
- `read_only: true`
- `cap_drop: ["ALL"]`
- `security_opt: ["no-new-privileges:true"]`

Therefore Conftest returns full pass (`15/15`) with no warnings.

## Evidence Files

- Falco rule:
  - `labs/lab9/falco/rules/custom-rules.yaml`
- Falco raw logs:
  - `labs/lab9/falco/logs/falco.log`
- Falco analysis:
  - `labs/lab9/analysis/falco-alerts.jsonl`
  - `labs/lab9/analysis/falco-alerts.tsv`
  - `labs/lab9/analysis/falco-alert-excerpts.txt`
  - `labs/lab9/analysis/falco-summary.txt`
  - `labs/lab9/analysis/event-generator-run.txt`
- Conftest outputs:
  - `labs/lab9/analysis/conftest-unhardened.txt`
  - `labs/lab9/analysis/conftest-hardened.txt`
  - `labs/lab9/analysis/conftest-compose.txt`
- Manifest comparison:
  - `labs/lab9/analysis/k8s-hardening-diff.txt`
