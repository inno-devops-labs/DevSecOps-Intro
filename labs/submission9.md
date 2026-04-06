# Lab 9 - Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Scope

- Analysis date: `2026-04-06`
- Runtime target container: `lab9-helper` (`alpine:3.19`)
- Policy targets:
  - `labs/lab9/manifests/k8s/juice-unhardened.yaml`
  - `labs/lab9/manifests/k8s/juice-hardened.yaml`
  - `labs/lab9/manifests/compose/juice-compose.yml`
- Tools used:
  - `falcosecurity/falco:latest` (Falco `0.43.0`, modern eBPF)
  - `falcosecurity/event-generator:latest`
  - `openpolicyagent/conftest:latest`

## Environment Notes

- Falco started with modern eBPF (`Opening 'syscall' source with modern BPF probe.`).
- In this PowerShell session, `docker exec -it` fails (`input device is not a TTY`). For the terminal-shell alert, `docker exec -t` was used instead.
- I copied the active Falco rules file to `labs/lab9/analysis/falco_rules.yaml` for inspection. It contains `Terminal shell in container` and `Drop and execute new binary in container` rules. There is no default rule in this ruleset that directly matches generic writes under `/usr/local/bin`, so a custom rule was added for that check.

## Task 1 - Falco Runtime Security Detection

### Commands used

```bash
mkdir -p labs/lab9/falco/{rules,logs} labs/lab9/analysis
docker run -d --name lab9-helper alpine:3.19 sleep 1d

docker run -d --name falco --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules:/etc/falco/rules.d:ro" \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true

# Baseline shell alert (TTY attached)
docker exec -t lab9-helper /bin/sh -lc 'echo hello-from-shell-tty-only'

# Custom drift write test
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'

# Extra baseline drift-like execution signal
docker exec --user 0 lab9-helper /bin/sh -lc 'cp /bin/busybox /tmp/sh && chmod +x /tmp/sh && /tmp/sh -lc "echo helper-newbinary"'

# Event generator for additional runtime detections
docker run --rm --name eventgen --privileged \
  -v /proc:/host/proc:ro -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

### Baseline alerts observed

Evidence file: `labs/lab9/falco/logs/falco.log` (selected lines in `labs/lab9/analysis/falco-alerts-selected.txt`).

1. `Terminal shell in container` (`Notice`)
   - Example: line `149` in `falco-alerts-selected.txt`
   - Context: `process=sh`, `container_name=lab9-helper`, `proc.tty=34816`.

2. `Drop and execute new binary in container` (`Critical`)
   - Example: lines `152-154` in `falco-alerts-selected.txt`
   - Context: execution of `/tmp/newbusy` or `/tmp/sh` from upper layer in `lab9-helper`.

3. Additional baseline detections from `event-generator`
   - `Debugfs Launched in Privileged Container` (`Warning`) line `128`
   - `Fileless execution via memfd_create` (`Critical`) line `143`

### Custom Falco rule

Custom rule file: `labs/lab9/falco/rules/custom-rules.yaml`

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and evt.is_open_write=true and fd.name startswith /usr/local/bin/ and container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

Custom alert evidence:
- Line `127`: write to `/usr/local/bin/custom-rule.txt`
- Lines `150-151`: write/append to `/usr/local/bin/drift-exec.sh`

### Custom rule purpose and tuning notes

- Purpose: catch container drift behavior where files are created/modified under `/usr/local/bin`, which is commonly part of executable search paths.
- Should fire:
  - Any write/create/open-for-write event in `/usr/local/bin/*` from container processes.
- Should not fire:
  - Host-only activity (`container.id == host`).
  - Read-only opens (`evt.is_open_write=false`).
- Tuning guidance:
  - To reduce false positives during expected package install/build actions, add allowlist exceptions for known maintenance containers or package-manager processes.
  - Example approach: extend condition with `and not (container.image.repository in (...) and proc.name in (...))`.

## Task 2 - Conftest Policy-as-Code (Rego)

### Conftest results

Evidence:
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`

Summary:
- Unhardened K8s manifest: `30 tests, 20 passed, 2 warnings, 8 failures`
- Hardened K8s manifest: `30 tests, 30 passed, 0 warnings, 0 failures`
- Docker Compose manifest: `15 tests, 15 passed, 0 warnings, 0 failures`

### Unhardened manifest policy violations and security impact

From `conftest-unhardened.txt`, denied controls:

1. `uses disallowed :latest tag`
   - Risk: mutable tag can introduce unreviewed image changes and weak traceability.
2. `must set runAsNonRoot: true`
   - Risk: root runtime increases blast radius on compromise.
3. `must set allowPrivilegeEscalation: false`
   - Risk: setuid/setcap paths can enable privilege escalation.
4. `must set readOnlyRootFilesystem: true`
   - Risk: writable root filesystem enables persistence/tampering.
5. `missing resources.requests.cpu`
6. `missing resources.requests.memory`
7. `missing resources.limits.cpu`
8. `missing resources.limits.memory`
   - Risk for 5-8: no resource governance increases noisy-neighbor/DoS impact.

Warnings:
- Missing `readinessProbe`
- Missing `livenessProbe`

### Hardening changes that satisfy policies

Compared `juice-hardened.yaml` vs `juice-unhardened.yaml` (diff in `labs/lab9/analysis/k8s-manifest-diff.txt`):

- Image pinning: `bkimminich/juice-shop:latest` -> `bkimminich/juice-shop:v19.0.0`
- Added container `securityContext`:
  - `runAsNonRoot: true`
  - `allowPrivilegeEscalation: false`
  - `readOnlyRootFilesystem: true`
  - `capabilities.drop: ["ALL"]`
- Added resource `requests` and `limits` for CPU/memory
- Added `readinessProbe` and `livenessProbe`

These changes remove all deny findings and warning findings for the hardened manifest.

### Docker Compose manifest analysis

`juice-compose.yml` passes all compose policy checks because it already includes:
- Explicit non-root `user: "10001:10001"`
- `read_only: true`
- `cap_drop: ["ALL"]`
- `security_opt: ["no-new-privileges:true"]`

No `deny` or `warn` results were reported by Conftest for Compose.

## Generated Artifacts

- `labs/lab9/falco/rules/custom-rules.yaml`
- `labs/lab9/falco/logs/falco.log`
- `labs/lab9/analysis/falco-alerts-selected.txt`
- `labs/lab9/analysis/falco_rules.yaml`
- `labs/lab9/analysis/falco-rule-search.txt`
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`
- `labs/lab9/analysis/k8s-manifest-diff.txt`
