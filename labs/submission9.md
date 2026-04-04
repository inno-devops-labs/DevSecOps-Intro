# Lab 9 Submission — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Overview

Runtime target:

```text
lab9-helper (alpine:3.19)
```

Artifacts for this lab were saved under `labs/lab9/`.

Tooling used:

- Falco `0.43.0` via `falcosecurity/falco:latest`
- Falco Event Generator via `falcosecurity/event-generator:latest`
- Conftest `v0.68.0`
- OPA `1.15.1`
- Docker Engine `29.3.1`
- `jq 1.7`

Methodology notes:

- Falco started successfully with the modern eBPF engine. The startup log explicitly shows: `Opening 'syscall' source with modern BPF probe.`
- On this Ubuntu 24.04 host, Falco logged several TOCTOU-mitigation tracepoint warnings for `connect/open/openat/openat2/creat`, but detection itself continued to work normally and all required alerts were still produced.
- In Falco `0.43.0`, the built-in “container drift” detection is execution-oriented (`Drop and execute new binary in container`), so a plain file write under `/usr/local/bin` reliably triggered the custom rule, while execution of an upper-layer binary triggered the built-in drift rule.

Evidence:

- `labs/lab9/falco/logs/falco-startup.log`
- `labs/lab9/falco/logs/falco.log`
- `labs/lab9/falco/rules/custom-rules.yaml`
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`

---

## Task 1 — Runtime Security Detection with Falco

### 1.1 Falco startup and rule loading

Falco was started in a privileged container with Docker socket access and the local rules directory mounted into `/etc/falco/rules.d`.

What the startup evidence confirms:

- Falco version: `0.43.0`
- syscall source enabled
- engine: modern BPF probe
- custom rules file loaded successfully: `/etc/falco/rules.d/custom-rules.yaml | schema validation: ok`

Evidence:

- `labs/lab9/falco/logs/falco-startup.log`

### 1.2 Baseline alerts observed

I triggered the helper-container shell event and observed the expected built-in alert:

```text
2026-04-04T12:43:49.510186387Z
Notice Terminal shell in container
command=sh -lc echo hello-from-shell
container_name=lab9-helper
```

This matters because an interactive shell inside a running container is often a sign of manual debugging, lateral movement, or post-compromise activity.

I also validated built-in container drift behavior by executing an upper-layer binary from `/usr/local/bin`:

```text
2026-04-04T12:45:11.226172620Z
Critical Drop and execute new binary in container
proc_exe=/usr/local/bin/drift-busybox
container_name=lab9-helper
```

This matters because execution of a binary not present in the base image is a classic persistence and post-exploitation pattern.

### 1.3 Custom Falco rule

I added the custom rule in:

- `labs/lab9/falco/rules/custom-rules.yaml`

Rule purpose:

- Detect writes under `/usr/local/bin/` inside containers
- Provide a narrower, explicit compliance/drift control for writes into a high-risk executable path

Observed custom-rule alerts:

```text
2026-04-04T12:43:34.462960725Z
Warning Write Binary Under UsrLocalBin
file=/usr/local/bin/drift.txt
container_name=lab9-helper
```

```text
2026-04-04T12:43:34.565978510Z
Warning Write Binary Under UsrLocalBin
file=/usr/local/bin/custom-rule.txt
container_name=lab9-helper
```

```text
2026-04-04T12:45:11.225093427Z
Warning Write Binary Under UsrLocalBin
file=/usr/local/bin/drift-busybox
container_name=lab9-helper
```

#### Why this rule is useful

- `/usr/local/bin` is an executable search-path location, so writes there are more sensitive than arbitrary temporary-file activity.
- The rule complements the built-in execution-based drift rule by alerting earlier, at file-write time.

#### Basic tuning included in the rule

- `container` limits detection to containers and avoids host noise
- `evt.is_open_write=true` ignores read-only opens
- `fd.name startswith /usr/local/bin/` narrows the scope to a risky executable directory

#### When it should fire

- A container writes or creates a file under `/usr/local/bin/`
- Examples: dropped tool, copied binary, tampering with executable path contents

#### When it should not fire

- Read-only access to files
- Writes outside `/usr/local/bin/`
- Host-side activity outside container context

#### Expected false positives / noise considerations

- Legitimate package-management or admin-debug actions inside mutable containers could also trigger it.
- In production, I would tune further with allowlists for known maintenance containers or trusted image repositories if such behavior were expected.

### 1.4 Event generator verification

I also ran `falcosecurity/event-generator:latest run syscall` to verify that the Falco setup was catching a broader range of suspicious activity.

Examples observed in `falco.log` include:

- `Drop and execute new binary in container`
- `Execution from /dev/shm`
- `Detect release_agent File Container Escapes`
- `PTRACE attached to process`
- `Netcat Remote Code Execution in Container`

This confirmed the Falco deployment was functioning beyond the two manually triggered helper-container events.

---

## Task 2 — Policy-as-Code with Conftest (Rego)

### 2.1 Review of provided Kubernetes manifests

The baseline manifest `juice-unhardened.yaml` is intentionally insecure:

- uses `bkimminich/juice-shop:latest`
- no `securityContext`
- no resource requests/limits
- no probes

The hardened manifest `juice-hardened.yaml` introduces the expected production-oriented safeguards:

- pinned image tag `v19.0.0`
- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `capabilities.drop: ["ALL"]`
- CPU/memory requests and limits
- readiness and liveness probes

### 2.2 Review of provided Rego policies

`labs/lab9/policies/k8s-security.rego` enforces:

- no `:latest`
- required container `securityContext` controls
- required CPU/memory requests and limits
- warning-level recommendations for readiness/liveness probes

`labs/lab9/policies/compose-security.rego` enforces:

- explicit non-root user
- read-only root filesystem
- dropping all Linux capabilities
- warning-level recommendation for `no-new-privileges`

### 2.3 Conftest results

#### Unhardened Kubernetes manifest

Result:

```text
30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

Evidence:

- `labs/lab9/analysis/conftest-unhardened.txt`

Policy violations and why they matter:

- `container "juice" uses disallowed :latest tag`
  - `latest` is mutable, so deployments are not reproducible or auditable.
- `container "juice" must set runAsNonRoot: true`
  - Running as root increases impact if the container is compromised.
- `container "juice" must set allowPrivilegeEscalation: false`
  - Prevents processes from gaining more privileges through setuid/setcap-style mechanisms.
- `container "juice" must set readOnlyRootFilesystem: true`
  - Reduces tampering and persistence opportunities inside the container.
- `container "juice" missing resources.requests.cpu`
- `container "juice" missing resources.requests.memory`
  - Missing requests weakens scheduling guarantees and can hide resource needs.
- `container "juice" missing resources.limits.cpu`
- `container "juice" missing resources.limits.memory`
  - Missing limits weakens containment and can contribute to noisy-neighbor or DoS-style impact.

Warnings:

- `container "juice" should define readinessProbe`
- `container "juice" should define livenessProbe`

These warnings do not fail the policy set, but they are important for resilience and safe rollout behavior.

#### Hardened Kubernetes manifest

Result:

```text
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

Evidence:

- `labs/lab9/analysis/conftest-hardened.txt`

Why it passes:

- the image is pinned to `v19.0.0`
- all required `securityContext` fields are present
- all required resource requests and limits are present
- readiness and liveness probes are defined

#### Docker Compose manifest

Result:

```text
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

Evidence:

- `labs/lab9/analysis/conftest-compose.txt`

Analysis:

- `user: "10001:10001"` satisfies the non-root requirement
- `read_only: true` satisfies immutable root filesystem policy
- `cap_drop: ["ALL"]` enforces least privilege
- `security_opt: [no-new-privileges:true]` satisfies the warning-level recommendation
- `tmpfs: ["/tmp"]` is a sensible companion to `read_only: true`, because it preserves a writable temp area without reopening the root filesystem

Overall, the Compose manifest is already aligned with the supplied policy baseline and did not require changes.

---

## Conclusion

The lab objectives were completed end-to-end:

- Falco was run locally with the modern eBPF engine
- baseline helper-container activity produced built-in alerts
- a custom Falco rule was added, loaded, and validated
- Conftest policies were reviewed and executed against all provided manifests
- the unhardened K8s manifest failed as expected
- the hardened K8s manifest and the Compose manifest both passed

All required evidence is present under `labs/lab9/` and this submission file documents both the runtime-detection and policy-analysis portions of the lab.
