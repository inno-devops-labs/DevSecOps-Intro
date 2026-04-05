# Lab 9 Submission - Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Student / Context
- Name: `Danil Fishchenko`
- Branch: `feature/lab9`
- Work date: `2026-04-05 15:44 MSK`
- Repository root: `DevSecOps-Intro/`
- Host OS: `macOS 26.3.1 (a) / Darwin 25.3.0 arm64`
- Docker Desktop / Engine: `29.2.1`
- Kubernetes context used for runtime check: `kind-devops-lab9`
- Falco image used for reproducible checks: `falcosecurity/falco:0.43.0`
- Conftest image used for reproducible checks: `openpolicyagent/conftest:latest` -> `Conftest v0.68.0`, `OPA 1.15.1`
- Helper container image: `alpine:3.19`

Official references used:
- Falco container deployment docs: `https://falco.org/docs/setup/container/`
- Falco kernel event source / modern eBPF docs: `https://falco.org/docs/concepts/event-sources/kernel/`
- Falco rules override / custom rules loading docs: `https://falco.org/docs/concepts/rules/overriding/`
- Falco sample events / event generator docs: `https://falco.org/docs/concepts/event-sources/kernel/sample-events/`
- Conftest docs: `https://www.conftest.dev/`
- Kubernetes security context docs: `https://kubernetes.io/docs/tasks/configure-pod-container/security-context/`
- Kubernetes Pod Security Standards docs: `https://kubernetes.io/docs/concepts/security/pod-security-standards/`
- OPA/Rego policy reference: `https://www.openpolicyagent.org/docs/policy-reference`

Important implementation notes:
- The stock Falco command from `labs/lab9.md` was not directly reproducible on this macOS Docker Desktop host because the `/boot`-style bind-mount approach from the lab text is not compatible here.
- I checked the current official Falco docs and used a working container launch with `tracefs`, `/proc`, `/etc`, Docker socket access, and mounted local rules.
- The initial "make the whole `/juice-shop` tree writable" workaround was functionally correct but too broad: it left server-side application files writable. I tightened the final manifests after manual runtime probing so that only the exact runtime-required paths stay writable.
- On Falco `0.43.0`, a plain write under `/usr/local/bin` reliably triggered the custom rule, while the built-in drift-style evidence was `Drop and execute new binary in container`, triggered by executing a dropped upper-layer binary.

## Repository Changes Made

### 1. Falco artifacts added
- Added custom rule file: `labs/lab9/falco/rules/custom-rules.yaml`
- Saved full Falco log: `labs/lab9/falco/logs/falco.log`
- Saved focused alert evidence: `labs/lab9/analysis/falco-alert-highlights.jsonl`

### 2. Hardened manifests corrected to be policy-compliant and runtime-viable
The provided hardened manifests passed policy checks but were not practically startable under `readOnlyRootFilesystem` with the current Juice Shop image. Runtime probing showed that Juice Shop mutates several paths during startup.

Final hardening strategy:
- keep the container root filesystem read-only
- keep server-side code immutable
- expose only the exact writable runtime paths Juice Shop actually needs

Fixes applied:
- `labs/lab9/manifests/compose/juice-compose.yml`
  - bound the published port to `127.0.0.1` for local-only exposure
  - switched to the image's real non-root identity: `65532:65532`
  - kept `read_only: true`
  - kept `cap_drop: ["ALL"]`
  - kept `security_opt: ["no-new-privileges:true"]`
  - added `tmpfs` for `/tmp`
  - replaced the broad `/juice-shop` mount with named volumes only for:
    - `/juice-shop/.well-known/csaf`
    - `/juice-shop/data`
    - `/juice-shop/ftp`
    - `/juice-shop/frontend/dist/frontend`
    - `/juice-shop/i18n`
    - `/juice-shop/logs`
    - `/juice-shop/uploads/complaints`
- `labs/lab9/manifests/k8s/juice-hardened.yaml`
  - kept required container hardening fields
  - set `automountServiceAccountToken: false`
  - isolated the hardened workload labels/selectors from the unhardened manifest
  - made runtime identity explicit: `runAsUser: 65532`, `runAsGroup: 65532`
  - added pod `fsGroup: 65532`
  - added pod `seccompProfile: RuntimeDefault`
  - added memory-backed writable `/tmp` volume
  - replaced the broad `/juice-shop` mount with dedicated `emptyDir` volumes only for:
    - `/juice-shop/.well-known/csaf`
    - `/juice-shop/data`
    - `/juice-shop/ftp`
    - `/juice-shop/frontend/dist/frontend`
    - `/juice-shop/i18n`
    - `/juice-shop/logs`
    - `/juice-shop/uploads/complaints`
  - added a non-root init container `seed-juice-writable-paths` that copies only those exact image subtrees into the mounted writable volumes before the main container starts
  - added explicit init-container resource requests and limits

Why this matters:
- the broad `/juice-shop` writable overlay was practical but weaker than necessary
- with the final manifests, `/juice-shop/package.json` and `/juice-shop/build/server.js` are no longer writable
- at the same time, the app still starts cleanly and serves `HTTP 200`

### 3. Policy quality improved
- `labs/lab9/policies/k8s-security.rego`
  - fixed capability-drop detection so a missing `capabilities.drop: ["ALL"]` is now denied reliably
  - extended security and resource checks to `initContainers`, closing a gap where an insecure init container could previously pass policy
  - added seccomp enforcement (`RuntimeDefault` or `Localhost`) to align the policy with Kubernetes restricted-style hardening
  - accepts `runAsNonRoot: true` from either container-level or pod-level security context, avoiding a false positive on valid pod-level configurations
- `labs/lab9/policies/compose-security.rego`
  - rejects explicit root users (`0`, `0:0`, `root`, `root:root`)
  - safely checks `cap_drop`
  - safely checks `security_opt`
- Added policy unit tests:
  - `labs/lab9/policies/k8s-security_test.rego`
  - `labs/lab9/policies/compose-security_test.rego`

## Task 1 - Runtime Security Detection With Falco

### 1.1 Commands Used
Preparation:

```bash
mkdir -p labs/lab9/{falco/{rules,logs},analysis}
docker run -d --name lab9-helper alpine:3.19 sleep 1d
```

Falco launch used for the verified run:

```bash
docker run -d --name falco-lab9 \
  --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:0.43.0 \
  falco -U \
        -o engine.kind=modern_ebpf \
        -o json_output=true \
        -o time_format_iso_8601=true
```

Rule validation:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:0.43.0 \
  falco -V /etc/falco/rules.d/custom-rules.yaml
```

Manual trigger commands:

```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
docker exec --user 0 lab9-helper /bin/sh -lc 'cp /bin/sh /usr/local/bin/sh && /usr/local/bin/sh -c "echo copied-binary-exec"'
```

Event generator:

```bash
docker run --rm --name eventgen \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /dev:/host/dev \
  falcosecurity/event-generator:latest run syscall
```

Evidence capture:

```bash
docker logs falco-lab9 > labs/lab9/falco/logs/falco.log 2>&1
```

### 1.2 Custom Rule
File:
- `labs/lab9/falco/rules/custom-rules.yaml`

Rule purpose:
- detect writes under `/usr/local/bin` inside containers as a practical filesystem-drift or payload-staging signal

Implemented tuning:
- ignores common package-manager writers (`apk`, `dpkg`, `rpm`, `yum`, `dnf`, `microdnf`, `pip`, `pip3`)
- uses an explicit syscall match (`open`, `openat`, `openat2`, `creat`) plus `evt.is_open_write=true` and `container.id != host`, so the rule validates standalone with `falco -V`
- scopes alerts only to `/usr/local/bin`

When it should fire:
- `docker exec` writes into `/usr/local/bin`
- copied or staged binaries dropped into `/usr/local/bin`

When it should not fire:
- common package-management noise from known install tools

### 1.3 Observed Falco Alerts
Focused evidence file:
- `labs/lab9/analysis/falco-alert-highlights.jsonl`

Confirmed relevant alerts:

| Scenario | Observed rule | Evidence |
|---|---|---|
| Interactive shell in helper container | `Terminal shell in container` | `falco-alert-highlights.jsonl` |
| Write `/usr/local/bin/drift.txt` | `Write Binary Under UsrLocalBin` | `falco-alert-highlights.jsonl` |
| Write `/usr/local/bin/custom-rule.txt` | `Write Binary Under UsrLocalBin` | `falco-alert-highlights.jsonl` |
| Copy and execute `/usr/local/bin/sh` | `Drop and execute new binary in container` | `falco-alert-highlights.jsonl` |
| Synthetic attacks from event-generator | multiple rules including `Drop and execute new binary in container`, `Execution from /dev/shm`, `Detect release_agent File Container Escapes`, `Read sensitive file untrusted`, `Netcat Remote Code Execution in Container`, `Remove Bulk Data from Disk` | `falco-alert-highlights.jsonl`, `falco.log` |

Important observed nuance:
- On this Falco version and ruleset, the plain write under `/usr/local/bin` did not itself produce a built-in drift alert.
- The built-in drift-style evidence was the rule `Drop and execute new binary in container`, triggered by executing a dropped binary from the container upper layer.
- That difference is preserved honestly in this submission instead of pretending the older wording from the lab text still matched current behavior.

### 1.4 Event Generator Result
Saved stdout:
- `labs/lab9/analysis/event-generator-syscall.txt`

Representative extra Falco detections seen after running it:
- `Drop and execute new binary in container`
- `Execution from /dev/shm`
- `Detect release_agent File Container Escapes`
- `Netcat Remote Code Execution in Container`
- `Read sensitive file untrusted`
- `Remove Bulk Data from Disk`

### 1.5 Runtime Caveats
- Falco startup on Docker Desktop's LinuxKit kernel reported TOCTOU mitigation tracepoint warnings for some syscalls.
- Falco explicitly continued detection despite those warnings.
- The full `falco.log` also contains unrelated alerts from already running local containers; the highlights file isolates the lab-relevant evidence for `lab9-helper` and `eventgen`.

## Task 2 - Policy-As-Code With Conftest

### 2.1 Commands Used
Main policy evaluation:

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

Policy unit verification:

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  verify --policy /project/policies
```

Saved outputs:
- `labs/lab9/analysis/conftest-unhardened.txt`
- `labs/lab9/analysis/conftest-hardened.txt`
- `labs/lab9/analysis/conftest-compose.txt`
- `labs/lab9/analysis/conftest-verify.txt`

### 2.2 Final Policy Results
Observed results with the final policy tree:

- Unhardened Kubernetes manifest:
  - `38 tests, 26 passed, 2 warnings, 10 failures, 0 exceptions`
- Hardened Kubernetes manifest:
  - `38 tests, 38 passed, 0 warnings, 0 failures, 0 exceptions`
- Compose manifest:
  - `19 tests, 19 passed, 0 warnings, 0 failures, 0 exceptions`
- Policy unit tests:
  - `6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped`

### 2.3 Unhardened Kubernetes Violations And Why They Matter
Observed deny results:
- `container "juice" uses disallowed :latest tag`
  - mutable tags weaken reproducibility and promotion trust
- `container "juice" must set runAsNonRoot: true`
  - root increases post-compromise blast radius
- `container "juice" must set allowPrivilegeEscalation: false`
  - blocks gaining extra privileges through `setuid`-style paths
- `container "juice" must set readOnlyRootFilesystem: true`
  - reduces persistence and runtime tampering
- `container "juice" must drop ALL capabilities`
  - removes unnecessary Linux privilege surface
- `container "juice" must set seccompProfile.type to RuntimeDefault or Localhost`
  - keeps the workload on an approved syscall-filtering profile instead of the unbounded default
- missing resource requests and limits:
  - `resources.requests.cpu`
  - `resources.requests.memory`
  - `resources.limits.cpu`
  - `resources.limits.memory`
  - these are operationally important for isolation and abuse control

Observed warning results:
- missing `readinessProbe`
- missing `livenessProbe`

### 2.4 Why The Hardened Kubernetes Manifest Now Passes And Is Practical
Hardening controls present:
- pinned image `bkimminich/juice-shop:v19.0.0`
- `runAsNonRoot: true`
- explicit `runAsUser: 65532`, `runAsGroup: 65532`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `capabilities.drop: ["ALL"]`
- CPU and memory requests and limits
- readiness and liveness probes
- `automountServiceAccountToken: false`
- pod `fsGroup: 65532`
- pod `seccompProfile: RuntimeDefault`
- memory-backed writable `/tmp`
- seeded writable subpaths only for:
  - `/juice-shop/.well-known/csaf`
  - `/juice-shop/data`
  - `/juice-shop/ftp`
  - `/juice-shop/frontend/dist/frontend`
  - `/juice-shop/i18n`
  - `/juice-shop/logs`
  - `/juice-shop/uploads/complaints`

Why the init-container seeding strategy was necessary:
- Juice Shop modifies several files under `/juice-shop` at startup
- mounting an empty `emptyDir` directly on those paths would hide required image contents
- the init container copies only the runtime-required subtrees into dedicated writable volumes
- this keeps the rest of the application tree on the immutable image layer instead of making the whole app directory writable

Saved runtime evidence:
- `labs/lab9/analysis/k8s-runtime.log`
- `labs/lab9/analysis/k8s-http-head.txt`

Manual hardening checks performed on the running Kubernetes pod:
- confirmed the process runs as `65532:65532`
- confirmed writes to `/tmp` succeed
- confirmed writes to `/etc` fail with `EROFS`
- confirmed `/juice-shop/package.json` is not writable
- confirmed `/juice-shop/build/server.js` is not writable
- confirmed `/juice-shop/frontend/dist/frontend/index.html` is writable as intended for Juice Shop startup customization
- confirmed writes succeed in `/juice-shop/data`, `/juice-shop/logs`, and `/juice-shop/.well-known/csaf`
- confirmed the default service-account token is not mounted
- confirmed the deployment rolled out successfully on the local `kind-devops-lab9` cluster and served `HTTP/1.1 200 OK` through `kubectl port-forward`

### 2.5 Why The Compose Manifest Now Passes And Is Practical
Final Compose hardening:
- `ports: ["127.0.0.1:3006:3000"]`
- `user: "65532:65532"`
- `read_only: true`
- `tmpfs` for `/tmp`
- `security_opt: ["no-new-privileges:true"]`
- `cap_drop: ["ALL"]`
- named volumes only for:
  - `/juice-shop/.well-known/csaf`
  - `/juice-shop/data`
  - `/juice-shop/ftp`
  - `/juice-shop/frontend/dist/frontend`
  - `/juice-shop/i18n`
  - `/juice-shop/logs`
  - `/juice-shop/uploads/complaints`

Why this version is better than the broad `/juice-shop` mount:
- Docker named volumes auto-populate the mounted directory with image contents on first use, so the app still gets the files it needs
- only the runtime-required subtrees stay writable
- server-side application files remain immutable even though the app starts successfully with `read_only: true`

Saved runtime evidence:
- `labs/lab9/analysis/compose-runtime.log`
- `labs/lab9/analysis/compose-http-head.txt`

Manual hardening checks performed on the running Compose container:
- confirmed the process runs as `65532:65532`
- confirmed writes to `/tmp` succeed
- confirmed writes to `/etc` fail with `EROFS`
- confirmed `/juice-shop/package.json` is not writable
- confirmed `/juice-shop/build/server.js` is not writable
- confirmed `/juice-shop/frontend/dist/frontend/index.html` is writable as intended for Juice Shop startup customization
- confirmed writes succeed in `/juice-shop/data`, `/juice-shop/logs`, and `/juice-shop/.well-known/csaf`
- confirmed the service served `HTTP/1.1 200 OK` on `127.0.0.1:3006`

## Additional Verification Performed
- `docker compose -f labs/lab9/manifests/compose/juice-compose.yml config -q`
- `docker compose -f labs/lab9/manifests/compose/juice-compose.yml -p lab9audit up -d`
- `curl -sSI http://localhost:3006/` -> `HTTP/1.1 200 OK`
- `kubectl apply -n lab9-audit -f labs/lab9/manifests/k8s/juice-hardened.yaml`
- `kubectl rollout status deployment/juice-hardened -n lab9-audit --timeout=180s`
- `kubectl port-forward -n lab9-audit svc/juice-hardened 3028:80`
- `curl -sSI http://localhost:3028/` -> `HTTP/1.1 200 OK`
- `docker run --rm -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro falcosecurity/falco:0.43.0 falco -V /etc/falco/rules.d/custom-rules.yaml` -> rule file validated successfully
- `docker run --rm -v "$(pwd)/labs/lab9":/project openpolicyagent/conftest:latest verify --policy /project/policies` -> `6/6` tests passed

## Acceptance Criteria Checklist
- [x] Branch `feature/lab9` contains Falco setup, logs, and a custom rule file
- [x] At least two Falco alerts were captured and explained
- [x] Conftest policies were reviewed and tested against manifests
- [x] Unhardened K8s manifest fails; hardened K8s manifest passes
- [x] `labs/submission9.md` includes evidence and analysis for both tasks

## Evidence Files
- Custom Falco rule: `labs/lab9/falco/rules/custom-rules.yaml`
- Full Falco log: `labs/lab9/falco/logs/falco.log`
- Focused Falco highlights: `labs/lab9/analysis/falco-alert-highlights.jsonl`
- Event generator stdout: `labs/lab9/analysis/event-generator-syscall.txt`
- Conftest fail baseline: `labs/lab9/analysis/conftest-unhardened.txt`
- Conftest hardened pass: `labs/lab9/analysis/conftest-hardened.txt`
- Conftest Compose pass: `labs/lab9/analysis/conftest-compose.txt`
- Conftest policy unit verification: `labs/lab9/analysis/conftest-verify.txt`
- Compose runtime log: `labs/lab9/analysis/compose-runtime.log`
- Compose HTTP evidence: `labs/lab9/analysis/compose-http-head.txt`
- Kubernetes runtime log: `labs/lab9/analysis/k8s-runtime.log`
- Kubernetes runtime HTTP evidence: `labs/lab9/analysis/k8s-http-head.txt`
