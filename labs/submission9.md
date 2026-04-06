# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Student
- Name: Palkina Sofia
- Date: `2026-03-19`


## Task 1 — Runtime Security Detection with Falco

### Baseline detections observed
I triggered baseline runtime activity and captured Falco alerts.  
Examples from `falco-final.log` include:
- `Packet socket created in container` (Notice)
- `Debugfs Launched in Privileged Container` (Warning)
- `Read sensitive file untrusted` (Warning)
- `Drop and execute new binary in container` (Critical)
- `Detect release_agent File Container Escapes` (Critical)
- `Execution from /dev/shm` (Warning)
- `Netcat Remote Code Execution in Container` (Warning)

These detections confirm Falco was actively monitoring container runtime behavior and identifying suspicious syscall patterns.

### Custom Falco rule
File: `labs/lab9/falco/rules/custom-rules.yaml`

Rule added:
- **Name:** `Write Binary Under UsrLocalBin`
- **Purpose:** detect file writes under `/usr/local/bin/` inside containers (possible container drift / tampering).
- **Severity:** `WARNING`

Observed alert evidence:
- `Falco Custom: File write in /usr/local/bin ... file=/usr/local/bin/custom-rule.txt ...`
- Rule field in event: `"rule":"Write Binary Under UsrLocalBin"`

### Tuning notes
- The custom rule is useful for immutable-image enforcement/drift detection.
- It should fire on unexpected writes into binary directories in running containers.
- In real environments it may require scoped exceptions (trusted init/update jobs) to reduce false positives.

## Task 2 — Policy-as-Code with Conftest (OPA/Rego)

### 2.1 Policy violations from `juice-unhardened.yaml` and why they matter

Conftest result (`labs/lab9/analysis/conftest-unhardened.txt`):
- **30 tests, 20 passed, 2 warnings, 8 failures**

#### Warnings
1. `container "juice" should define livenessProbe`  
   **Why it matters:** without liveness probes, unhealthy containers may continue running indefinitely, reducing service reliability and increasing MTTR during incidents.

2. `container "juice" should define readinessProbe`  
   **Why it matters:** without readiness probes, traffic can be routed to containers that are not ready, causing avoidable errors and unstable rollouts.

#### Failures
1. `missing resources.limits.cpu`  
2. `missing resources.limits.memory`  
3. `missing resources.requests.cpu`  
4. `missing resources.requests.memory`  
   **Why these matter:** missing requests/limits weakens resource governance and can cause noisy-neighbor effects, scheduling unpredictability, and denial-of-service-like behavior due to unbounded consumption.

5. `must set allowPrivilegeEscalation: false`  
   **Why it matters:** if privilege escalation is allowed, a compromised process can potentially gain higher privileges inside the container, increasing attack impact.

6. `must set readOnlyRootFilesystem: true`  
   **Why it matters:** writable root filesystem enables easier persistence/tampering (dropping tools, modifying binaries/config), which directly conflicts with immutable-container principles.

7. `must set runAsNonRoot: true`  
   **Why it matters:** running as root increases blast radius after compromise and makes container breakout attempts more dangerous.

8. `uses disallowed :latest tag`  
   **Why it matters:** `latest` is mutable and breaks reproducibility/auditability; pinning versions is required for deterministic deployments and supply-chain traceability.

### 2.2 Specific hardening changes in `juice-hardened.yaml` that satisfy policies

Conftest result (`labs/lab9/analysis/conftest-hardened.txt`):
- **30 tests, 30 passed, 0 warnings, 0 failures**

The hardened manifest addresses the above by applying standard security controls:

1. **Image pinning (no `:latest`)**  
   - Uses a fixed version tag (or digest) for deterministic deployments.

2. **Container privilege restrictions**  
   - `allowPrivilegeEscalation: false`
   - `runAsNonRoot: true`
   - (typically accompanied by explicit non-root UID in hardened patterns)

3. **Filesystem hardening**  
   - `readOnlyRootFilesystem: true` to prevent runtime tampering/persistence in root FS.

4. **Resource governance**  
   - Adds `resources.requests` and `resources.limits` for CPU/memory to enforce predictable scheduling and containment.

5. **Operational health controls**  
   - Adds `livenessProbe` and `readinessProbe` so orchestration can correctly manage health and traffic routing.

Together, these changes move the deployment from insecure/default posture to a policy-compliant baseline suitable for production hardening.


### 2.3 Analysis of Docker Compose manifest results

Conftest result (`labs/lab9/analysis/conftest-compose.txt`):
- **15 tests, 15 passed, 0 warnings, 0 failures**

Interpretation:
- The Compose file complies with all checks in `compose-security.rego`.
- No denied patterns (e.g., privileged mode, insecure defaults, missing required controls according to policy) were detected.
- This demonstrates policy consistency beyond Kubernetes manifests: the same security intent is enforceable for local/dev Compose workflows as well.

Security takeaway:
- Passing Compose policies reduces configuration drift between development and deployment environments and helps catch insecure runtime settings early.