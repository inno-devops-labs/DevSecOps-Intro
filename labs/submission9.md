# Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Falco Runtime Detection

### Baseline Alerts

Falco `0.43.0` was run with the modern eBPF engine against the helper container `alpine:3.19` (`lab9-helper`). The saved Falco log contains the following baseline runtime detections:

| Time (UTC) | Priority | Rule | Trigger |
|------------|----------|------|---------|
| `2026-04-05T18:22:11.742815640Z` | Notice | `Terminal shell in container` | `docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'` |
| `2026-04-05T18:22:11.734574300Z` | Warning | `Write Binary Under UsrLocalBin` | `echo boom > /usr/local/bin/drift.txt` |

Evidence: `labs/lab9/falco/logs/falco.log`.

### Custom Rule: `Write Binary Under UsrLocalBin`

| Item | Result |
|------|--------|
| Rule name | `Write Binary Under UsrLocalBin` |
| Purpose | Detect writes under `/usr/local/bin/` inside a container |
| Fires when | A container process opens a file below `/usr/local/bin/` for writing |
| Does not fire when | Activity is on the host, outside `/usr/local/bin/`, or read‑only |

**Tuning notes:**  
- To reduce noise, we can add an exception for trusted containers:  
  `and not container.image.repository = "my-registry/trusted-base"`  
- We can also restrict the rule to specific container names using `and container.name = "lab9-helper"`.  
- For production, consider alerting only on `openat` with `evt.is_open_write=true` to avoid duplicate events.

Validation: The custom rule fired again when writing `custom-rule.txt` to the same directory, confirming that it reliably detects repeated writes under `/usr/local/bin/`.

### Falco Event Generator (Optional)

The `falcosecurity/event-generator:latest run syscall` produced additional alerts, verifying that Falco was correctly detecting more sophisticated attack patterns.

| Time (UTC) | Priority | Rule |
|------------|----------|------|
| `2026-04-05T18:22:22.279443927Z` | Warning | `Execution from /dev/shm` |
| `2026-04-05T18:22:22.387696416Z` | Critical | `Drop and execute new binary in container` |
| `2026-04-05T18:22:26.236215334Z` | Warning | `Read sensitive file untrusted` |
| `2026-04-05T18:22:32.984835754Z` | Critical | `Detect release_agent File Container Escapes` |
| `2026-04-05T18:22:33.129770245Z` | Critical | `Fileless execution via memfd_create` |

## Conftest Policy Analysis

### Kubernetes Manifest Results

| Manifest | Result |
|----------|--------|
| `juice-unhardened.yaml` | `30 tests, 20 passed, 2 warnings, 8 failures` |
| `juice-hardened.yaml` | `30 tests, 30 passed, 0 warnings, 0 failures` |

Evidence: `labs/lab9/analysis/conftest-unhardened.txt`, `labs/lab9/analysis/conftest-hardened.txt`.

### Unhardened Manifest Violations

The unhardened deployment failed the following checks:

- uses disallowed `:latest` tag
- missing `runAsNonRoot: true`
- missing `allowPrivilegeEscalation: false`
- missing `readOnlyRootFilesystem: true`
- missing `resources.requests.cpu`
- missing `resources.requests.memory`
- missing `resources.limits.cpu`
- missing `resources.limits.memory`

Warnings:

- missing `readinessProbe`
- missing `livenessProbe`

**Why these matter for security:**  
- `:latest` weakens reproducibility and safe rollback.  
- Missing non‑root / privilege controls increases impact after compromise.  
- Writable root filesystem makes tampering and persistence easier.  
- Missing resource controls increases noisy‑neighbour and DoS risk.  
- Missing probes reduces runtime visibility and recovery quality.

### Hardened Manifest Changes

The hardened manifest satisfies the policy by applying:

- pinned image `bkimminich/juice-shop:v19.0.0`
- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- drops all capabilities with `capabilities.drop: ["ALL"]`
- adds CPU and memory requests / limits
- adds `readinessProbe` and `livenessProbe`

### Docker Compose Policy Analysis

| Manifest | Result |
|----------|--------|
| `juice-compose.yml` | `15 tests, 15 passed, 0 warnings, 0 failures` |

Evidence: `labs/lab9/analysis/conftest-compose.txt`.

**Why Compose passes:**  
- explicit non‑root user `10001:10001`  
- `read_only: true`  
- drops all capabilities with `cap_drop: ["ALL"]`  
- enables `no-new-privileges: true`

The provided policies behave as intended: the unhardened Kubernetes manifest fails, the hardened manifest passes, and the Compose manifest already meets the enforced security baseline.
