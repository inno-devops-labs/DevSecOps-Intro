# Lab 9 Submission — Monitoring & Compliance


## Task 1 — Falco Runtime Detection


### 1.2 Baseline/runtime alerts observed

The following Falco alerts were captured:

1. `Terminal shell in container`
   - Trigger: `docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'`
   - Evidence: Falco logged a Notice for a shell spawned in container `lab9-helper`
   - Why it matters: Interactive shells in containers are often suspicious because they can indicate debugging, manual tampering, or post-compromise activity

2. `Read sensitive file untrusted`
   - Trigger: `falcosecurity/event-generator:latest run syscall`
   - Evidence: Falco logged a Warning for reading `/etc/shadow` from container `eventgen`
   - Why it matters: Access to sensitive files such as `/etc/shadow` can indicate credential harvesting attempts

3. `Drop and execute new binary in container`
   - Trigger: `falcosecurity/event-generator:latest run syscall`
   - Evidence: Falco logged a Critical alert for executing a binary not present in the base image
   - Why it matters: Dropping and executing a new binary is a strong indicator of persistence or unauthorized modification inside a container

4. `Fileless execution via memfd_create`
   - Trigger: `falcosecurity/event-generator:latest run syscall`
   - Evidence: Falco logged a Critical alert for execution from `memfd:program`
   - Why it matters: Fileless execution is commonly associated with defense evasion because code runs without a normal on-disk executable

5. `Detect release_agent File Container Escapes`
   - Trigger: `falcosecurity/event-generator:latest run syscall`
   - Evidence: Falco logged a Critical alert for an attempt involving `/release_agent`
   - Why it matters: This maps to a known container escape technique and is high severity

### 1.3 Custom Falco rule

Custom rule file created: `labs/lab9/falco/rules/custom-rules.yaml`

Rule summary:
- Rule name: `Write Binary Under UsrLocalBin`
- Purpose: Detect writes under `/usr/local/bin/` inside any container
- Intended use: Catch container drift or unauthorized file creation in a directory commonly associated with executables or helper scripts

Rule content summary:
- Watches `open`, `openat`, `openat2`, and `creat`
- Requires `evt.is_open_write=true`
- Matches files whose path starts with `/usr/local/bin/`
- Excludes host activity with `container.id != host`

When the rule should fire:
- A process inside a container writes a file under `/usr/local/bin/`
- Example: `echo custom-test > /usr/local/bin/custom-rule.txt`

When the rule should not fire:
- Activity occurs on the host rather than in a container
- Files are opened read-only rather than written
- The path is outside `/usr/local/bin/`

### 1.4 Custom rule validation and tuning notes

Falco successfully loaded the custom rule and reloaded cleanly after `SIGHUP`. This was confirmed by the log entry showing:

- `/etc/falco/rules.d/custom-rules.yaml`
- `SIGHUP received, restarting...`

The custom rule was successfully validated on `2026-04-06`.

Validation evidence:
- Writing `drift.txt` under `/usr/local/bin/` triggered `Write Binary Under UsrLocalBin`
- Writing `custom-rule.txt` under `/usr/local/bin/` also triggered `Write Binary Under UsrLocalBin`
- Falco output included `Falco Custom: File write in /usr/local/bin (...)`

Analysis:
- This is likely caused by the macOS Docker Desktop/LinuxKit runtime rather than a syntax problem in the rule file
- The same Falco instance also detected many other syscall-based alerts correctly
- Even though Falco still reported some tracepoint warnings during startup, the custom file-write rule did trigger successfully in this run


## Task 2 — Policy-as-Code with Conftest

### 2.1 Unhardened Kubernetes manifest results

Command run:

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-unhardened.yaml -p /project/policies --all-namespaces | tee labs/lab9/analysis/conftest-unhardened.txt
```

Result:
- `30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions`

Warnings:
- container `juice` should define `livenessProbe`
- container `juice` should define `readinessProbe`

Failures:
- missing `resources.limits.cpu`
- missing `resources.limits.memory`
- missing `resources.requests.cpu`
- missing `resources.requests.memory`
- missing `allowPrivilegeEscalation: false`
- missing `readOnlyRootFilesystem: true`
- missing `runAsNonRoot: true`
- disallowed `:latest` image tag

Why these matter:
- Resource requests/limits help prevent noisy-neighbor issues and improve scheduling and stability
- `runAsNonRoot: true` reduces impact if the application is compromised
- `allowPrivilegeEscalation: false` blocks privilege escalation paths inside the container
- `readOnlyRootFilesystem: true` reduces container drift and tampering opportunities
- Avoiding `:latest` improves reproducibility, patch tracking, and change control
- Readiness/liveness probes improve reliability and recovery behavior

### 2.2 Hardened Kubernetes manifest results

Command run:

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/k8s/juice-hardened.yaml -p /project/policies --all-namespaces | tee labs/lab9/analysis/conftest-hardened.txt
```

Result:
- `30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions`

Hardening changes that satisfied the policies:
- Pinned image from `bkimminich/juice-shop:latest` to `bkimminich/juice-shop:v19.0.0`
- Added `securityContext.runAsNonRoot: true`
- Added `securityContext.allowPrivilegeEscalation: false`
- Added `securityContext.readOnlyRootFilesystem: true`
- Added `securityContext.capabilities.drop: ["ALL"]`
- Added CPU and memory requests
- Added CPU and memory limits
- Added `readinessProbe`
- Added `livenessProbe`

These changes align directly with the rules in `labs/lab9/policies/k8s-security.rego`.

### 2.3 Docker Compose manifest results

Command run:

```bash
docker run --rm -v "$(pwd)/labs/lab9":/project \
  openpolicyagent/conftest:latest \
  test /project/manifests/compose/juice-compose.yml -p /project/policies --all-namespaces | tee labs/lab9/analysis/conftest-compose.txt
```

Result:
- `15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions`

Why the Compose manifest passed:
- Uses explicit image tag `bkimminich/juice-shop:v19.0.0`
- Sets a non-root user: `10001:10001`
- Enables `read_only: true`
- Drops all capabilities with `cap_drop: ["ALL"]`
- Enables `no-new-privileges:true`
- Uses `tmpfs` for `/tmp`, which supports operation while keeping the root filesystem read-only
