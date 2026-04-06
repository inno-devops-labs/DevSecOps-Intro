# Lab 9 Submission — Falco Runtime Detection + Conftest Policies

## Student
- GitHub username: `ellilin`
- Branch: `feature/lab9`

## Environment Notes
- Host: macOS with Docker Desktop
- Falco needed a Docker Desktop-compatible startup instead of the exact Linux-host mount list from the lab.
- Working Falco command:

```bash
docker run -d --name falco \
  --privileged \
  --pid=host \
  -e HOST_ROOT=/ \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true
```

- Why this change was needed:
  - Docker Desktop on macOS does not expose Linux host paths like `/boot` and `/lib/modules` as bind mounts to containers.
  - Falco initially failed because it expected `/host/proc`; setting `HOST_ROOT=/` and sharing the host PID namespace let it initialize against the LinuxKit VM kernel.
  - Falco still printed some tracepoint attachment warnings on Docker Desktop, but runtime detection worked and alerts were generated successfully.

## Task 1 — Runtime Security Detection with Falco

### 1.1 Helper Container

```bash
docker run -d --name lab9-helper alpine:3.19 sleep 1d
```

### 1.2 Custom Falco Rule
Created file: `labs/lab9/falco/rules/custom-rules.yaml`

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and evt.is_open_write=true and fd.name startswith /usr/local/bin/ and container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

### 1.3 Baseline and Validation Commands

```bash
docker exec -it lab9-helper /bin/sh -lc 'echo terminal-shell-check; sleep 1'
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
docker run --rm --name eventgen \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

### 1.4 Falco Alert Evidence
Full log: `labs/lab9/falco/logs/falco.log`

Focused alert extract: `labs/lab9/falco/logs/falco-alerts.txt`

Observed baseline and custom alerts:

```text
2026-04-06T19:58:47.213437300+0000: Warning Falco Custom: File write in /usr/local/bin ... file=/usr/local/bin/drift.txt ...
2026-04-06T19:58:52.270358678+0000: Warning Falco Custom: File write in /usr/local/bin ... file=/usr/local/bin/custom-rule.txt ...
2026-04-06T19:59:01.422909307+0000: Notice A shell was spawned in a container with an attached terminal ... rule="Terminal shell in container" ...
```

Additional event-generator alerts observed:

```text
2026-04-06T19:59:42.585374867+0000: Warning Sensitive file opened for reading by non-trusted program ... rule="Read sensitive file untrusted"
2026-04-06T19:59:42.693337201+0000: Warning Hardlinks created over sensitive files ... rule="Create Hardlink Over Sensitive Files"
2026-04-06T19:59:42.897884784+0000: Notice Packet socket was created in a container ... rule="Packet socket created in container"
2026-04-06T19:59:43.385267243+0000: Critical Fileless execution via memfd_create ... rule="Fileless execution via memfd_create"
2026-04-06T19:59:50.578211079+0000: Critical Executing binary not part of base image ... rule="Drop and execute new binary in container"
```

### 1.5 Custom Rule Analysis and Tuning
- Purpose: detect container drift by flagging writes into `/usr/local/bin/`, which is commonly part of the executable path and should usually remain immutable at runtime.
- Why it fired:
  - `drift.txt` and `custom-rule.txt` were written under `/usr/local/bin/` from inside `lab9-helper`.
  - The rule checks write-oriented open syscalls and excludes host-only activity with `container.id != host`.
- When it should fire:
  - Unexpected binary drops, script drops, or persistence attempts in container executable directories.
  - Runtime tampering in images expected to behave immutably.
- When it should not fire:
  - Builds or init-style workflows that intentionally generate files in `/usr/local/bin/`.
  - Containers designed for package installation or mutable tool injection.
- Basic tuning used:
  - Narrow scope to `/usr/local/bin/` only, which reduces noise compared with watching every writable path.
  - Set priority to `WARNING` because this is suspicious but not automatically malicious.

### 1.6 Notes on Built-in Drift Detection
- The lab notes say writes under `/usr/local/bin` should also hit Falco's built-in drift logic.
- In this Docker Desktop environment, the custom rule fired reliably, while the built-in drift alert was not consistently emitted.
- Falco also logged LinuxKit tracepoint warnings during startup, so the most likely explanation is partial feature degradation in the Docker Desktop kernel environment rather than a rule syntax issue.
- Even with that limitation, the runtime detection objective was satisfied with:
  - a shell alert from the baseline task,
  - custom drift alerts from the write tests,
  - multiple additional runtime detections from `event-generator`.

## Task 2 — Policy-as-Code with Conftest

### 2.1 Files Reviewed
- Kubernetes manifests:
  - `labs/lab9/manifests/k8s/juice-unhardened.yaml`
  - `labs/lab9/manifests/k8s/juice-hardened.yaml`
- Policies:
  - `labs/lab9/policies/k8s-security.rego`
  - `labs/lab9/policies/compose-security.rego`
- Docker Compose manifest:
  - `labs/lab9/manifests/compose/juice-compose.yml`

### 2.2 Conftest Commands

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-unhardened.yaml -p /project/policies --all-namespaces

docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-hardened.yaml -p /project/policies --all-namespaces

docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/compose/juice-compose.yml -p /project/policies --all-namespaces
```

Saved outputs:
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`

### 2.3 Results Summary

| Target | Result |
| --- | --- |
| `juice-unhardened.yaml` | 20 passed, 2 warnings, 8 failures |
| `juice-hardened.yaml` | 30 passed, 0 warnings, 0 failures |
| `juice-compose.yml` | 15 passed, 0 warnings, 0 failures |

### 2.4 Unhardened Manifest Violations and Why They Matter
Failures from `conftest-unhardened.txt`:

1. `container "juice" uses disallowed :latest tag`
   - Security impact: `:latest` is mutable, so deployments are less reproducible and may pull an unreviewed image unexpectedly.

2. `container "juice" must set runAsNonRoot: true`
   - Security impact: running as root increases the impact of application compromise and weakens isolation boundaries.

3. `container "juice" must set allowPrivilegeEscalation: false`
   - Security impact: prevents processes from gaining more privileges via setuid binaries or similar escalation paths.

4. `container "juice" must set readOnlyRootFilesystem: true`
   - Security impact: reduces runtime tampering, persistence, and accidental modification of application files.

5. `container "juice" missing resources.requests.cpu`
6. `container "juice" missing resources.requests.memory`
7. `container "juice" missing resources.limits.cpu`
8. `container "juice" missing resources.limits.memory`
   - Security impact: lack of requests/limits makes noisy-neighbor and denial-of-service conditions easier and weakens workload governance.

Warnings from `conftest-unhardened.txt`:

1. `container "juice" should define readinessProbe`
   - Operational/security value: helps keep broken instances out of service and reduces exposure during failed startup states.

2. `container "juice" should define livenessProbe`
   - Operational/security value: helps recover stuck or unhealthy workloads automatically.

### 2.5 Hardening Changes That Satisfy the Policies
The hardened manifest addresses every failed control from the baseline:

1. Fixed image pinning
   - Changed `bkimminich/juice-shop:latest` to `bkimminich/juice-shop:v19.0.0`.

2. Added container security context
   - `runAsNonRoot: true`
   - `allowPrivilegeEscalation: false`
   - `readOnlyRootFilesystem: true`
   - `capabilities.drop: ["ALL"]`

3. Added resource governance
   - Requests:
     - CPU `100m`
     - Memory `256Mi`
   - Limits:
     - CPU `500m`
     - Memory `512Mi`

4. Added health probes
   - `readinessProbe` on `/`
   - `livenessProbe` on `/`

Because of these changes, the hardened manifest passed all 30 policy checks with no warnings or failures.

### 2.6 Docker Compose Policy Analysis
The Compose policy enforces:
- explicit `user`
- `read_only: true`
- `cap_drop: ["ALL"]`
- recommended `security_opt: ["no-new-privileges:true"]`

The provided Compose file already satisfies all of them:
- `user: "10001:10001"`
- `read_only: true`
- `cap_drop: ["ALL"]`
- `security_opt: [no-new-privileges:true]`

It also mounts `/tmp` as `tmpfs`, which is a sensible complement to a read-only root filesystem because it still gives the container a writable temporary area.

## Conclusion
- Falco was run successfully in a Docker Desktop-compatible configuration and produced the required runtime detections.
- The custom rule under `labs/lab9/falco/rules/custom-rules.yaml` worked as intended and detected writes under `/usr/local/bin/`.
- Conftest clearly showed the difference between an insecure Kubernetes deployment and a hardened one.
- The hardened Kubernetes manifest and the Docker Compose manifest both comply with the provided Rego policies.

## Bonus Task
- No separate bonus task was listed in `labs/lab9.md`.
