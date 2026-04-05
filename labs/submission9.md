# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Goal

Detect suspicious container behavior with Falco, add and validate one custom Falco rule, and review hardening/compliance with Conftest policies.

## Task 1 — Falco Runtime Detection

I ran Falco in a container with modern eBPF enabled and collected the alert output in:

- `labs/lab9/falco/logs/falco.log`
- `labs/lab9/falco/logs/falco-full.log`

I used two sources of activity to exercise the rules:

- a shell-enabled Alpine helper container (`lab9-helper`)
- the Falco event generator (`eventgen`) to produce a burst of known detection patterns

The refreshed Falco log contains 16 warning-level alerts in total.

Representative built-in alerts observed:

- `Run shell untrusted`
- `Read sensitive file untrusted`
- `Read sensitive file trusted after startup`

Other built-in detections also fired during the event-generator run, including fileless execution, network tool execution, ptrace activity, and sensitive file access patterns.

### Custom rule

Custom rule file:

- `labs/lab9/falco/rules/custom-rules.yaml`

Rule purpose:

- Detect writes under `/usr/local/bin` inside any container

Why it matters:

- Writing into a binary directory is a strong drift signal and can indicate unauthorized tooling, persistence, or tampering

When it should fire:

- when a container writes a new file under `/usr/local/bin`
- when application behavior changes and drops executables or scripts into a binary path

When it should not fire:

- normal writes outside binary directories
- host-side file writes
- read-only workloads that do not modify the container filesystem

Custom rule evidence:

- two warning alerts fired for writes to `/usr/local/bin` inside `lab9-helper`
- the rule matched both `drift.txt` and `custom-rule.txt`

## Task 2 — Conftest Policies

I reviewed the provided policies:

- `labs/lab9/policies/k8s-security.rego`
- `labs/lab9/policies/compose-security.rego`

I tested the provided manifests with Conftest and saved the results in:

- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`

### Unhardened Kubernetes manifest

File:

- `labs/lab9/manifests/k8s/juice-unhardened.yaml`

Result:

- 20 passed, 2 warnings, 8 failures

Main violations and why they matter:

- `:latest` tag is disallowed because it is mutable and not reproducible
- `runAsNonRoot: true` is missing, which allows root execution
- `allowPrivilegeEscalation: false` is missing, which leaves privilege escalation paths open
- `readOnlyRootFilesystem: true` is missing, which makes filesystem tampering easier
- CPU and memory requests/limits are missing, which weakens scheduling safety and resource isolation
- readiness and liveness probes are missing, which reduces health-check and rollout reliability

### Hardened Kubernetes manifest

File:

- `labs/lab9/manifests/k8s/juice-hardened.yaml`

Result:

- 30 passed, 0 warnings, 0 failures

Hardening changes that satisfy the policy:

- pinned image tag instead of `latest`
- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- dropped all capabilities
- CPU and memory requests/limits
- readiness and liveness probes

### Docker Compose manifest

File:

- `labs/lab9/manifests/compose/juice-compose.yml`

Result:

- 15 passed, 0 warnings, 0 failures

Why it passes:

- sets a non-root `user`
- uses `read_only: true`
- adds `tmpfs` for `/tmp`
- sets `security_opt: no-new-privileges:true`
- drops all capabilities with `cap_drop: ["ALL"]`

## Notes

- Falco ran successfully with modern eBPF in this environment.
- The Docker Desktop environment did not need the full `/boot`, `/lib/modules`, and `/usr` mounts from the lab example; the reduced mount set in `labs/lab9/run-falco-lite.sh` was sufficient.
- The custom rule is intentionally narrow and should only trigger on writes into `/usr/local/bin`, not on ordinary container writes.

## Evidence

- `labs/lab9/falco/rules/custom-rules.yaml`
- `labs/lab9/falco/logs/falco.log`
- `labs/lab9/falco/logs/falco-full.log`
- `labs/lab9/falco/logs/falco-inspect.json`
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`
- `labs/lab9/run-falco-lite.sh`
