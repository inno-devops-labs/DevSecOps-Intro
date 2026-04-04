# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### Baseline Alerts Observed

During the experiment, Falco successfully detected multiple suspicious runtime behaviors inside containers.

#### 1. Terminal shell in container

```
Notice A shell was spawned in a container with an attached terminal
rule: Terminal shell in container
container: lab9-helper
user: root
```

**Explanation:**
This alert indicates that an interactive shell was started inside a container. In production environments, containers are typically designed to run a single process and should not expose interactive shells. Such behavior may indicate:

* manual debugging
* or a potential attacker gaining access

---

#### 2. Custom Rule Trigger — File Write in /usr/local/bin

```
Warning Falco Custom: File write in /usr/local/bin
rule: Write Binary Under UsrLocalBin
file: /usr/local/bin/custom-rule.txt
user: root
```

**Explanation:**
This alert was triggered by a custom Falco rule detecting file writes in `/usr/local/bin`.
This directory is typically reserved for binaries, and writing to it at runtime indicates **container drift** or possible compromise.

---

#### 3. Event Generator Alerts (Examples)

Falco event generator produced multiple high-confidence detections:

* **Drop and execute new binary in container (Critical)**
  → indicates execution of a binary not present in the base image

* **Fileless execution via memfd_create (Critical)**
  → execution without writing to disk (advanced attack technique)

* **Read sensitive file (/etc/shadow)**
  → possible credential access attempt

* **Netcat remote code execution**
  → potential reverse shell / backdoor

* **Container escape attempt (release_agent)**
  → high-risk privilege escalation

**Conclusion:**
Falco successfully detected both simple and advanced attack patterns using syscall monitoring.

---

### Custom Falco Rule

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and 
             evt.is_open_write=true and 
             fd.name startswith /usr/local/bin/ and 
             container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

#### Purpose

Detect unauthorized file writes in binary directories inside containers, which may indicate:

* container drift
* malware installation
* persistence mechanisms

#### When it SHOULD fire

* Writing files to `/usr/local/bin`
* Creating or modifying executables inside a container
* Runtime modification of container filesystem

#### When it SHOULD NOT fire

* Read-only operations
* Writes outside `/usr/local/bin`
* Host-level file operations

---

## Task 2 — Policy-as-Code with Conftest

### Results Summary

| Manifest       | Result                            |
| -------------- | --------------------------------- |
| Unhardened K8s | ❌ Fail (8 violations, 2 warnings) |
| Hardened K8s   | ✅ Pass                            |
| Docker Compose | ✅ Pass                            |

---

### Unhardened Manifest — Policy Violations

The following violations were detected:

#### 1. Usage of `:latest` tag

```
FAIL: container "juice" uses disallowed :latest tag
```

**Risk:**
Unpredictable deployments and lack of version control. The image may change between deployments.

---

#### 2. Missing securityContext settings

```
FAIL: must set runAsNonRoot: true
FAIL: must set allowPrivilegeEscalation: false
FAIL: must set readOnlyRootFilesystem: true
```

**Risk:**

* Running as root → privilege escalation
* Privilege escalation allowed → container breakout risk
* Writable root FS → persistence and tampering

---

#### 3. Missing resource limits and requests

```
FAIL: missing resources.requests.cpu
FAIL: missing resources.requests.memory
FAIL: missing resources.limits.cpu
FAIL: missing resources.limits.memory
```

**Risk:**

* Resource exhaustion (DoS)
* Uncontrolled CPU/memory usage
* Poor scheduling in Kubernetes

---

#### 4. Missing health probes (warnings)

```
WARN: should define livenessProbe
WARN: should define readinessProbe
```

**Risk:**

* Kubernetes cannot detect unhealthy containers
* Reduced reliability and self-healing

---

### Hardened Manifest — Security Improvements

The hardened manifest resolves all violations:

#### SecurityContext applied

```yaml
runAsNonRoot: true
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
```

**Effect:**

* Enforces least privilege
* Prevents privilege escalation
* Makes filesystem immutable
* Removes unnecessary Linux capabilities

---

#### Resource limits defined

```yaml
requests:
  cpu: "100m"
  memory: "256Mi"
limits:
  cpu: "500m"
  memory: "512Mi"
```

**Effect:**

* Prevents resource abuse
* Ensures stable scheduling

---

#### Health probes added

```yaml
readinessProbe
livenessProbe
```

**Effect:**

* Enables automatic recovery
* Improves application reliability

---

#### Image version pinned

```
bkimminich/juice-shop:v19.0.0
```

**Effect:**

* Predictable deployments
* Better traceability

---

### Docker Compose Manifest Analysis

Result:

```
15 tests, 15 passed, 0 warnings, 0 failures
```

#### Security features implemented:

* **Non-root user**

```yaml
user: "10001:10001"
```

* **Read-only filesystem**

```yaml
read_only: true
```

* **Drop all capabilities**

```yaml
cap_drop: ["ALL"]
```

* **No privilege escalation**

```yaml
security_opt:
  - no-new-privileges:true
```

#### Conclusion

The Docker Compose configuration follows best practices:

* principle of least privilege
* reduced attack surface
* strong runtime isolation

