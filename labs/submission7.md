# Lab 7 --- Container Security: Image Scanning & Deployment Hardening

## Task 1 --- Image Vulnerability & Configuration Analysis

### Top 5 Critical/High Vulnerabilities

1.  CVE-2025-69421 (openssl/libssl3) --- High\
    Impact: Cryptographic vulnerability that may allow data compromise
    or MITM attacks.

2.  SNYK-UPSTREAM-NODE-14928492 (node) --- Critical\
    Impact: Race condition leading to unpredictable execution or
    security bypass.

3.  SNYK-JS-MARSDB-480405 (marsdb) --- Critical\
    Impact: Arbitrary code execution.

4.  SNYK-JS-VM2-5772823 (vm2) --- Critical\
    Impact: Remote Code Execution (RCE).

5.  SNYK-JS-SEQUELIZE-15456219 (sequelize) --- High\
    Impact: SQL Injection vulnerability.

------------------------------------------------------------------------

### Dockle Configuration Findings

No FATAL or WARN issues detected.

However, INFO findings: - Missing HEALTHCHECK → container health cannot
be monitored - Content trust disabled → images may be unverified -
Unnecessary files (.DS_Store) → increases attack surface

------------------------------------------------------------------------

### Security Posture Assessment

-   The image likely runs as root (no USER specified)
-   Large number of vulnerabilities (128 total)

Recommendations: - Use non-root user - Update dependencies - Add
HEALTHCHECK - Enable Docker Content Trust - Remove unnecessary files

------------------------------------------------------------------------

## Task 2 --- Docker Host Security Benchmarking

### Summary Statistics

-   PASS: \~20+
-   WARN: \~15+
-   FAIL: 0
-   INFO: many

------------------------------------------------------------------------

### Analysis of Failures

No explicit FAIL, but many WARN issues:

1.  No TLS for Docker daemon\
    Impact: Remote unauthorized access\
    Fix: Enable TLS authentication

2.  No user namespaces\
    Impact: Privilege escalation\
    Fix: Enable userns-remap

3.  No auditing\
    Impact: No traceability\
    Fix: Configure auditd

4.  Docker socket wrong ownership\
    Impact: Root access via socket\
    Fix: Restrict permissions

5.  No resource/security restrictions\
    Impact: Containers can abuse host\
    Fix: Apply limits and policies

------------------------------------------------------------------------

## Task 3 — Deployment Security Configuration Analysis

### Configuration Comparison Table


| Profile | Capabilities | Security Options | Memory | CPU | PIDs | Restart |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Default** | Default | None | No | No | No | No |
| **Hardened** | Drop ALL | no-new-privileges | 512MB | 1 | No | No |
| **Production** | Drop ALL + NET_BIND | no-new-privileges + seccomp | 512MB | 1 | 100 | on-failure |


------------------------------------------------------------------------

### Security Measure Analysis

#### a) Capabilities

Linux capabilities = fine-grained root privileges.

Dropping ALL: - prevents privilege escalation - blocks dangerous
syscalls

NET_BIND_SERVICE: - allows binding to low ports

Trade-off: - security vs functionality

------------------------------------------------------------------------

#### b) no-new-privileges

Prevents gaining new privileges via setuid.

Prevents: - privilege escalation attacks

Downside: - may break some apps

------------------------------------------------------------------------

#### c) Resource limits

Without limits: - DoS possible

Prevents: - memory exhaustion attacks

Risk: - app crashes if limits too low

------------------------------------------------------------------------

#### d) PID limit

Fork bomb = infinite process creation.

PID limit: - prevents system exhaustion

Choosing value: - based on app needs

------------------------------------------------------------------------

#### e) Restart policy

on-failure: restart 3 times

Useful: - improves reliability

Risk: - restart loops

Difference: - always = infinite restart

------------------------------------------------------------------------

### Critical Thinking

Development: - Default (easy debugging)

Production: - Production profile (secure)

Resource limits solve: - DoS attacks and resource abuse

Attack difference: - Production blocks privilege escalation, limits
damage

Additional hardening: - run as non-root - read-only filesystem - network
isolation - secrets management
