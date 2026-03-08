# Lab 9 — Runtime and Configuration Policy Enforcement (Falco + Conftest)

## Task 1 — Falco Runtime Security

### Observed Baseline Alerts (from `labs/lab9/falco/logs/falco.log`)
Falco detected two container runtime security events:

```
Rule: Terminal shell in container
Priority: Notice
Details:
  - A shell (`sh`) was spawned in a container with an attached terminal.
  - Container: lab9-helper (alpine:3.19)
  - User: root (UID 0)
  - Command: sh -lc "echo hello-from-shell"
```

**Explanation:**  
This is a built-in Falco rule that alerts whenever an interactive shell is launched inside a running container.  
Such behavior is often used for debugging but also correlates with potential intrusions or privilege escalations.

```
Rule: Write Binary Under UsrLocalBin
Priority: Warning
Details:
  - File write detected: /usr/local/bin/drift.txt
  - Container: lab9-helper (alpine:3.19)
  - User: root
  - Flags: O_CREAT | O_WRONLY | FD_UPPER_LAYER
```

**Explanation:**  
This was the custom rule created for this lab to detect unexpected file modifications under `/usr/local/bin`.  
It should fire when new executables or files are written in that directory — a common sign of container drift (a running container diverging from its original image).  
It should **not** trigger during normal read-only operations or package installs during build time.

| Rule | Severity | Purpose | Should Trigger When | Should Not Trigger When |
|------|-----------|----------|--------------------|--------------------------|
| Terminal shell in container | Notice | Detects interactive shell sessions inside containers | A shell (`sh`, `bash`, etc.) is executed with a TTY | Non-interactive background processes |
| Write Binary Under UsrLocalBin | Warning | Detects runtime writes to binary directories | Any file or binary is created or modified under `/usr/local/bin` | Container starts normally or reads files |

---

## Task 2 — Conftest Policy Evaluation

### Kubernetes Manifests Review

Two deployment manifests were provided:

- `labs/lab9/manifests/k8s/juice-unhardened.yaml` — baseline (insecure)
- `labs/lab9/manifests/k8s/juice-hardened.yaml` — compliant (after security hardening)

#### 2.1 Policy Violations in Unhardened Manifest

The `conftest test` output (`conftest-unhardened.txt`) flagged multiple issues:

```
FAIL - juice-unhardened.yaml - Container 'juice-shop' must not run as root
FAIL - juice-unhardened.yaml - CPU and memory limits must be defined
FAIL - juice-unhardened.yaml - Privileged mode is not allowed
FAIL - juice-unhardened.yaml - readOnlyRootFilesystem should be true
FAIL - juice-unhardened.yaml - No livenessProbe configured
FAIL - juice-unhardened.yaml - No readinessProbe configured
```

**Why These Violations Matter:**
| Policy | Security Impact |
|---------|-----------------|
| **runAsRoot** | Containers running as root can modify system files or escalate privileges if the node is compromised. |
| **Resource limits** | Without CPU/memory caps, a compromised container can cause denial of service by resource exhaustion. |
| **Privileged mode** | Provides full host access (devices, kernel capabilities), defeating container isolation. |
| **readOnlyRootFilesystem** | Prevents modification of application binaries; without it, malware can persist. |
| **Health probes missing** | Without `livenessProbe` and `readinessProbe`, orchestrator cannot detect or restart unhealthy pods, increasing downtime and attack persistence. |

#### 2.2 Hardening changes in the hardened manifest that satisfy policies

`juice-hardened.yaml` introduces the following remediations:

| Control | Change Applied | Security Benefit |
|----------|----------------|------------------|
| RunAsUser / RunAsNonRoot | Added `securityContext.runAsUser: 1000` and `runAsNonRoot: true` | Drops root privileges in container. |
| Privileged | Set `securityContext.privileged: false` | Prevents host-level access. |
| Read-only filesystem | Added `readOnlyRootFilesystem: true` | Protects binaries from modification. |
| Resource limits | Added `resources.limits.cpu` and `resources.limits.memory` | Prevents DoS via excessive resource usage. |
| Probes | Added `livenessProbe` and `readinessProbe` | Ensures auto-healing and resiliency. |
| Capabilities | Added `capDrop: [ALL]` | Removes unnecessary Linux kernel privileges. |

Result:  
The hardened manifest passes all tests (`conftest-hardened.txt` shows “PASS” for all policies).

---

### 2.3 Analysis of the Docker Compose manifest results

The Docker Compose manifest was also scanned with `conftest test` using `compose-security.rego`.

**Results (from `conftest-compose.txt`):**
```
FAIL - docker-compose.yml - service 'juice-shop' must define non-root user
FAIL - docker-compose.yml - service 'juice-shop' should use read-only filesystem
FAIL - docker-compose.yml - service 'juice-shop' should limit CPU/memory usage
```

**Analysis:**
These checks mirror Kubernetes policies and ensure consistent security posture across environments:
- Compose services should define `user: "1000"` or similar to avoid root.
- Read-only volumes prevent tampering with application code.
- Resource limits (`cpus`, `mem_limit`) mitigate denial-of-service risk in local/dev environments.
