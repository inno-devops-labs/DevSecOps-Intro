# Lab 9 — Monitoring & Compliance (Falco + Conftest)

## Task 1 — Falco Runtime Detection

### Baseline alerts observed
Falco log review (`labs/lab9/falco/logs/falco.log`) shows runtime detections after triggering test actions in `lab9-helper`.

**Alert 1:**
- Rule: `Terminal shell in container`
- Priority: `Notice`
- What happened: an interactive shell (`sh`) was executed inside a running container.
- Why it matters: shell access in containers is a common post-exploitation behavior and should be monitored even when used for debugging.

**Alert 2:**
- Rule: `Write Binary Under UsrLocalBin` (custom)
- Priority: `Warning`
- What happened: a file write was detected under `/usr/local/bin` (`drift.txt`).
- Why it matters: runtime writes in binary paths are a strong indicator of container drift or persistence attempts.

### Custom rule behavior
Custom rule file: `labs/lab9/falco/rules/custom-rules.yaml`

Intent of the rule:
- Trigger when a container process opens/creates a writable file under `/usr/local/bin`.
- Avoid noise from regular container startup and read-only operations.

Expected behavior:
- **Should trigger:** creation/modification in `/usr/local/bin/*` during container runtime.
- **Should not trigger:** read-only file access and non-write operations.

---

## Task 2 — Conftest Policy Evaluation

### 2.1 Kubernetes manifest results
Evaluated manifests:
- `labs/lab9/manifests/k8s/juice-unhardened.yaml`
- `labs/lab9/manifests/k8s/juice-hardened.yaml`

Results from `labs/lab9/analysis/conftest-unhardened.txt`:

```
FAIL - juice-unhardened.yaml - Container 'juice-shop' must not run as root
FAIL - juice-unhardened.yaml - CPU and memory limits must be defined
FAIL - juice-unhardened.yaml - Privileged mode is not allowed
FAIL - juice-unhardened.yaml - readOnlyRootFilesystem should be true
FAIL - juice-unhardened.yaml - No livenessProbe configured
FAIL - juice-unhardened.yaml - No readinessProbe configured
```

Why these findings are important:
- Running as root increases blast radius in case of compromise.
- Missing resource limits allows potential DoS by resource exhaustion.
- Privileged mode weakens container isolation from host.
- Writable root filesystem enables easier persistence/tampering.
- Missing health probes reduces resilience and delays remediation of unhealthy workloads.

### 2.2 Hardening controls in the compliant manifest
`juice-hardened.yaml` addresses the above gaps with:
- `runAsNonRoot: true` and `runAsUser: 1000`
- `privileged: false`
- `readOnlyRootFilesystem: true`
- CPU and memory limits
- `livenessProbe` and `readinessProbe`
- Dropped Linux capabilities (`capDrop: [ALL]`)

Result:
- `labs/lab9/analysis/conftest-hardened.txt` reports a passing policy evaluation for the hardened manifest.

### 2.3 Docker Compose policy check
Evaluated compose file:
- `labs/lab9/manifests/compose/juice-compose.yml`

Results from `labs/lab9/analysis/conftest-compose.txt`:

```
FAIL - juice-compose.yml - service 'juice-shop' must define non-root user
FAIL - juice-compose.yml - service 'juice-shop' should use read-only filesystem
FAIL - juice-compose.yml - service 'juice-shop' should limit CPU/memory usage
```

Interpretation:
- Compose policy checks mirror K8s controls to keep a consistent baseline across environments.
- The service still needs explicit non-root user, read-only filesystem, and resource constraints.

---

## Conclusion
- Falco successfully detected interactive shell behavior and file-write drift activity in a container.
- Custom Falco rule for `/usr/local/bin` writes worked as intended for runtime drift monitoring.
- Conftest correctly differentiates insecure (`juice-unhardened.yaml`) and hardened (`juice-hardened.yaml`) K8s configurations.
- Compose checks highlight remaining hardening work for local/containerized deployments.
