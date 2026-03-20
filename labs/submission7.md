# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1. Top 5 Critical/High Vulnerabilities

Based on scanning with Docker Scout, the image contains `118 vulnerabilities` (11 Critical, 65 High).

#### Top 5 vulnerabilities:

#### 1. CVE-2026-22709
- Package: vm2
- Severity: Critical (CVSS 9.8)
- Impact: Protection mechanism failure → allows sandbox escape and arbitrary code execution
- Risk: Attacker can fully compromise the container

#### 2. CVE-2023-37903
- Package: vm2
- Severity: Critical (CVSS 9.8)
- Impact: OS Command Injection
- Risk: Remote attacker can execute system commands

#### 3. CVE-2025-55130
- Package: Node.js
- Severity: Critical
- Impact: Vulnerability in runtime environment
- Risk: Compromise of application execution environment

#### 4. CVE-2019-10744
- Package: lodash
- Severity: Critical (CVSS 9.1)
- Impact: Prototype Pollution
- Risk: Can manipulate application logic and potentially lead to RCE

#### 5. CVE-2023-46233
- Package: crypto-js
- Severity: Critical (CVSS 9.1)
- Impact: Use of insecure cryptographic algorithms
- Risk: Sensitive data exposure and weak encryption

### 2. Dockle Configuration Findings
Scan performed using Dockle.

#### Findings:

#### INFO: Missing HEALTHCHECK
- Issue: No HEALTHCHECK instruction
- Risk:
    - No way to detect unhealthy containers
    - Makes monitoring and auto-recovery harder

#### INFO: Content trust not enabled
- Issue: `DOCKER_CONTENT_TRUST` not enabled
- Risk:
    - Images may be tampered with
    - No verification of image integrity

#### INFO: Unnecessary files in image
- Issue: `.DS_Store` files present
- Risk:
    - Information leakage
    - Larger attack surface

### 3. Security Posture Assessment

#### Does the image run as root?
- The image likely runs as a non-root user (UID 65532) based on Dockerfile
- However, no strict enforcement is visible in runtime → still a risk

#### Overall Security Assessment

The container has a weak security posture:
- Large number of vulnerabilities (118 total)
- Multiple critical RCE vulnerabilities
- Outdated dependencies
- Missing best practices (HEALTHCHECK, content trust)

#### Recommended Improvements
- Update all vulnerable dependencies (Node.js, npm packages)
- Use minimal base image (e.g., distroless already used — good)
- Enforce non-root execution explicitly (USER directive)
- Add HEALTHCHECK instruction
- Enable Docker Content Trust
- Regularly rebuild image with security patches

## Task 2 — Docker Host Security Benchmarking

Scan performed using Docker Bench for Security.

### 1. Summary Statistics
- **PASS**: ~20+
- **WARN**: ~15
- **FAIL**: 0
- **INFO**: Remaining checks

Score: 6/50

Note: Results are affected by running Docker on macOS (Docker Desktop), not a native Linux host.

### 2. Analysis of Warnings

#### 1. No separate partition for containers
- Risk: Disk exhaustion affects entire system
- Fix: Use dedicated partition for /var/lib/docker

#### 2. Auditing not configured
- Risk: No tracking of suspicious activity
- Fix: Enable auditd logging

#### 3. Inter-container communication not restricted
- Risk: Containers can attack each other
- Fix: Configure Docker network policies

#### 4. User namespace not enabled
- Risk: Container root == host root
- Fix: Enable user namespace remapping

#### 5. Docker socket ownership issue
- Risk: Unauthorized users may control Docker daemon
- Fix: Restrict permissions on /var/run/docker.sock

#### 6. No HEALTHCHECK in images
- Risk: Hard to detect failures
- Fix: Add HEALTHCHECK in Dockerfile

#### 7. Content trust not enabled
- Risk: Pulling unverified images
- Fix: Enable:

```bash
export DOCKER_CONTENT_TRUST=1
```

#### 8. No-new-privileges not enforced globally
- Risk: Privilege escalation
- Fix: Configure daemon-wide security options

## Task 3 — Deployment Security Configuration Analysis

### 1. Configuration Comparison Table

| Setting          | Default   | Hardened          | Production                     |
| ---------------- | --------- | ----------------- | ------------------------------ |
| Capabilities     | Full      | Dropped ALL       | Dropped ALL + NET_BIND_SERVICE |
| Security Options | None      | no-new-privileges | no-new-privileges + seccomp    |
| Memory           | Unlimited | 512MB             | 512MB                          |
| CPU              | Unlimited | 1 core            | 1 core                         |
| PIDs             | Unlimited | Unlimited         | 100                            |
| Restart Policy   | No        | No                | on-failure                     |

### 2. Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**Linux capabilities** — a mechanism for dividing root privileges into separate rights.

- `--cap-drop=ALL`:
    - Removes ALL privileges
    - Protects against privilege escalation and container breakout
- `--cap-add=NET_BIND_SERVICE`:
    - Allows the use of ports <1024

Trade-off:
- `+` security
- `-` may break the functionality

#### b) `--security-opt=no-new-privileges`

- Prohibits processes from gaining new privileges
- Blocks:
    - setuid attacks
    - rivilege escalation attacks

**Minus**: it can break applications that require elevation of rights

#### c) `--memory and --cpus`
- No limits:
    - the container can use all resources.
- Protects against:
    - DoS attacks

**The risk of limits being too low**:
- the app may crash

#### d) `--pids-limit=100`
- Protects against fork bomb (mass creation of processes)

**How to choose a limit**:
- analyze the normal behavior of the application

#### e) `--restart=on-failure:3`
- Restarts the container upon failure (up to 3 times)

**Positive**:
- increases availability

**Cons**:
- it can hide the problem.

**Comparison**:
- `on-failure` is safer
- `always` — the risk of an endless cycle

### 3. Critical Thinking Questions

#### 1. Which profile for DEVELOPMENT? Why?

**Default**:
- Maximum flexibility
- Minimum restrictions
- Convenient for debugging

#### 2. Which profile for PRODUCTION? Why?

**Production**:
- Minimum privileges
- Resource limitation
- Protection against attacks

#### 3. What real-world problem do resource limits solve?

- Prevent:
    - DoS attacks
    - resource exhaustion
- Ensure the stability of the system

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

**Default**:
- May increase privileges
- Can use all resources
- Can create a fork bomb

**Production**:
- no privileges
- resources are limited
- the number of processes is limited

#### 5. What additional hardening would you add?

- Run container as non-root
- Use read-only filesystem
- Enable AppArmor/SELinux
- Use custom seccomp profile
- Network segmentation
- Secrets management (Docker secrets)