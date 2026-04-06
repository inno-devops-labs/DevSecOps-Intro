# Task 1 — Falco Runtime Security Detection

## Baseline Alerts Observed

During runtime monitoring with Falco, the following security-relevant events were detected:

### 1. Terminal Shell in Container

**Trigger:**

```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

**Observation:**
Falco generated an alert indicating that an interactive shell was opened inside a container.

**Security Risk:**

* Interactive shells inside containers are uncommon in production environments
* This behavior may indicate:

  * Manual debugging (acceptable in dev)
  * Post-exploitation activity (attacker gaining access)

---

### 2. Container Drift (Write to /usr/local/bin)

**Trigger:**

```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

**Observation:**
Falco detected a write operation inside a binary directory.

**Security Risk:**

* `/usr/local/bin` is typically immutable in production containers
* Writing to this path indicates:

  * Container drift (runtime modification)
  * Possible malware persistence or tampering

---

## Custom Falco Rule

### Rule Definition

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

---

### Validation

**Trigger:**

```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

**Result:**

* Built-in Falco drift rule triggered
* Custom rule (`Falco Custom:`) triggered successfully

---

### Purpose of the Custom Rule

The rule is designed to detect unauthorized file writes in binary directories within containers.

---

### When It Should Fire

* Unexpected runtime modifications
* Malicious activity (e.g., persistence mechanisms)
* Debugging in production environments

---

### When It Should NOT Fire

* Controlled build-time operations
* Legitimate initialization scripts (if explicitly allowed)

---

### Noise / False Positives Considerations

* CI/CD pipelines modifying containers at runtime
* Debug sessions in non-production environments


# Task 2 — Policy-as-Code with Conftest

## Unhardened Manifest Analysis

**File:** `juice-unhardened.yaml`

### Warnings

1. **Missing livenessProbe**

   * Containers may not be automatically restarted if unhealthy

2. **Missing readinessProbe**

   * Traffic may be routed to unready containers

---

### Failures

#### 1. Missing Resource Limits and Requests

* `resources.limits.cpu`
* `resources.limits.memory`
* `resources.requests.cpu`
* `resources.requests.memory`

**Risk:**

* No isolation of compute resources
* Potential Denial-of-Service (DoS)
* Unpredictable scheduling behavior

---

#### 2. allowPrivilegeEscalation not set to false

**Risk:**

* Processes may gain additional privileges
* Increased risk of container breakout

---

#### 3. readOnlyRootFilesystem not enabled

**Risk:**

* Attackers can modify filesystem
* Enables persistence mechanisms

---

#### 4. runAsNonRoot not enforced

**Risk:**

* Container runs as root
* Higher impact in case of compromise

---

#### 5. Usage of `:latest` Tag

**Risk:**

* Non-deterministic deployments
* Potential for unverified or vulnerable image versions

---

## Hardened Manifest Analysis

**File:** `juice-hardened.yaml`

**Result:**

* All tests passed (30/30)
* No warnings or failures

---

### Security Improvements Applied

#### 1. Non-root Execution

* `runAsNonRoot: true`
* Reduces privilege escalation risk

---

#### 2. Resource Constraints

* CPU and memory limits/requests defined
* Prevents resource exhaustion

---

#### 3. Filesystem Hardening

* `readOnlyRootFilesystem: true`
* Prevents runtime modification

---

#### 4. Privilege Restriction

* `allowPrivilegeEscalation: false`
* Enforces least privilege principle

---

#### 5. Image Version Pinning

* Removed `:latest`
* Ensures deterministic deployments

---

#### 6. Health Probes Added

* `livenessProbe`
* `readinessProbe`

Improves reliability and availability

---

## Docker Compose Analysis

**File:** `juice-compose.yml`

### Findings

Depending on policy results, typical issues include:

* Missing security constraints
* Running as root
* Lack of restart policies

---

### Security Risks

* Increased attack surface
* Lack of isolation controls
* Reduced operational resilience
