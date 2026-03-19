# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

**Student:** Sarmat Lutfullin
**Date:** March 19, 2026

---

## Task 1 — Image Vulnerability & Configuration Analysis

### Vulnerability Scanning with Docker Scout

Scanned `bkimminich/juice-shop:v19.0.0` using Docker Scout:

```
118 vulnerabilities found in 48 packages
  CRITICAL     11
  HIGH         65
  MEDIUM       30
  LOW           5
  UNSPECIFIED   7
```

### Top 5 Critical/High Vulnerabilities

1. **CVE-2024-47764** — `cookie` npm package < 0.7.0
   - Severity: LOW (but widely exploited pattern)
   - Type: Injection via improper neutralization of special elements
   - Impact: Cookie header manipulation, potential session hijacking

2. **CVE-2026-24001** — `diff` npm package >= 4.0.0, < 4.0.4
   - Severity: LOW, CVSS 2.7
   - Type: Inefficient Regular Expression Complexity (ReDoS)
   - Impact: Denial of service via crafted input causing regex backtracking

3. **Critical vulnerabilities in base OS packages** (11 total)
   - Outdated Node.js base image with unpatched system libraries
   - Impact: Remote code execution potential in worst-case scenarios

4. **High severity npm dependency vulnerabilities** (65 total)
   - Multiple outdated transitive dependencies
   - Impact: Varies — XSS, prototype pollution, path traversal

5. **Unspecified vulnerabilities** (7 total)
   - Packages with known issues but no assigned CVE
   - Impact: Unknown, requires manual review

### Dockle Configuration Findings

```
INFO  - CIS-DI-0005: Enable Content trust for Docker
        export DOCKER_CONTENT_TRUST=1 before docker pull/build

INFO  - CIS-DI-0006: Add HEALTHCHECK instruction to the container image
        not found HEALTHCHECK statement

INFO  - DKL-LI-0003: Only put necessary files
        unnecessary file: juice-shop/node_modules/extglob/lib/.DS_Store
        unnecessary file: juice-shop/node_modules/micromatch/lib/.DS_Store
```

**Analysis of findings:**

- **No HEALTHCHECK** — Docker cannot detect if the app is unhealthy and restart it automatically. In production this means a crashed app stays "running" from Docker's perspective.
- **No Content Trust** — Images are not cryptographically verified, allowing supply chain attacks via tampered images.
- **Unnecessary files (.DS_Store)** — macOS metadata files leaked into the image, indicating poor `.dockerignore` hygiene. Not a direct vulnerability but increases image size and reveals development environment details.

### Security Posture Assessment

- The image runs as **root** (no USER instruction in Dockerfile) — this is the most critical finding. If an attacker escapes the container, they have root on the host.
- 118 vulnerabilities with 11 critical indicate the base image and dependencies are significantly outdated.
- No resource limits, no healthcheck, no content trust by default.

**Recommendations:**
1. Add `USER node` in Dockerfile to run as non-root
2. Update base image to latest Node.js LTS
3. Add `HEALTHCHECK` instruction
4. Pin dependency versions and audit with `npm audit`
5. Use multi-stage builds to minimize final image size

---

## Task 2 — Docker Host Security Benchmarking

### CIS Docker Benchmark Results

```
Checks: 74
Score:  5

PASS:  19
WARN:  32
INFO:  95
NOTE:   7
FAIL:   0
```

### Summary

No outright FAIL results, but 32 WARNings indicate significant room for improvement. The score of 5/74 reflects that this is a development macOS environment, not a hardened production Linux host.

### Key WARN Findings

**Section 1 — Host Configuration:**
- Auditing rules not configured for Docker files (`/var/lib/docker`, `/etc/docker`)
- On macOS, auditd is not available — this is a platform limitation

**Section 2 — Docker Daemon Configuration:**
- No TLS authentication configured for Docker daemon
- Logging driver not set to a centralized solution
- No user namespace remapping (`--userns-remap`)
- Live restore not enabled

**Section 4 — Container Images:**
- Multiple images without HEALTHCHECK (juice-shop, checkov, kics, etc.)
- Some images use `ADD` instead of `COPY` in Dockerfile history
- Images without specific non-root USER

**Section 6 — Operations:**
- 19 images present (image sprawl warning)
- 12 total containers (1 running)

### Remediation for Key Warnings

| Warning | Fix |
|---------|-----|
| No TLS on daemon | Configure `--tlsverify` with certs |
| No user namespace | Add `--userns-remap=default` to daemon config |
| No centralized logging | Set `--log-driver=json-file` with rotation |
| Image sprawl | Regular `docker image prune` in CI/CD |
| No HEALTHCHECK | Add to Dockerfiles |

---

## Task 3 — Deployment Security Configuration Analysis

### Configuration Comparison Table

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| CapDrop | none | ALL | ALL |
| CapAdd | none | none | NET_BIND_SERVICE |
| SecurityOpt | none | no-new-privileges | no-new-privileges |
| Memory Limit | none (7.6GB host) | 512MB | 512MB |
| Memory Swap | none | unlimited | 512MB (no swap) |
| CPU Quota | none | 1.0 core | 1.0 core |
| PIDs Limit | none | none | 100 |
| Restart Policy | no | no | on-failure:3 |

### Functionality Test Results

All three profiles returned HTTP 200 — security hardening did not break functionality.

### Resource Usage

| Container | CPU % | Memory Used | Memory Limit |
|-----------|-------|-------------|--------------|
| juice-default | 0.41% | 105 MB | 7.6 GB (host) |
| juice-hardened | 1.28% | 95 MB | 512 MB |
| juice-production | 1.30% | 93 MB | 512 MB |

### Security Measure Analysis

**a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`**

Linux capabilities divide root privileges into distinct units. By default, Docker grants ~14 capabilities to containers (e.g., `NET_RAW`, `SYS_CHROOT`, `SETUID`). Dropping ALL removes every capability, preventing privilege escalation, raw socket creation, and filesystem manipulation even if the container process is compromised.

`NET_BIND_SERVICE` is added back because binding to ports below 1024 requires it. Without it, the app cannot listen on port 80/443 in production.

Trade-off: Some legitimate operations (e.g., `ping` uses `NET_RAW`) stop working. Must test thoroughly.

**b) `--security-opt=no-new-privileges`**

Prevents processes inside the container from gaining new privileges via `setuid`/`setgid` binaries or Linux capabilities. Specifically blocks privilege escalation attacks where an attacker runs a setuid binary (like `sudo`) to become root.

No meaningful downside for web applications — they don't need to escalate privileges at runtime.

**c) `--memory=512m` and `--cpus=1.0`**

Without limits, a single container can consume all host memory, causing OOM kills of other containers or the host itself. This is the primary vector for a **Denial of Service** attack — an attacker triggers memory-intensive operations to starve other services.

Risk of setting too low: app crashes under legitimate load. 512MB is sufficient for Juice Shop (~95MB actual usage), leaving headroom for traffic spikes.

**d) `--pids-limit=100`**

A **fork bomb** (`:(){ :|:& };:`) spawns processes exponentially until the system runs out of PIDs, crashing everything. PID limiting caps the total processes a container can create, containing the blast radius.

100 PIDs is reasonable for a Node.js app. Determine the right limit by running `docker stats` under load and observing peak PID count, then add 20-30% headroom.

**e) `--restart=on-failure:3`**

Automatically restarts the container if it exits with a non-zero code, up to 3 times. Provides resilience against transient crashes without masking persistent failures (after 3 attempts, it stops).

`always` restarts even on clean exit — risky because it can hide bugs and create restart loops. `on-failure:3` is the safer production choice.

### Critical Thinking Questions

**1. Which profile for DEVELOPMENT?**
Default — developers need full capabilities for debugging, no resource constraints that could mask performance issues, and no restart policy that hides crashes.

**2. Which profile for PRODUCTION?**
Production — all hardening flags active. The functionality test confirmed HTTP 200 on all three, so there's no reason not to use maximum hardening in production.

**3. What real-world problem do resource limits solve?**
Noisy neighbor problem — one misbehaving container consuming all resources and degrading or crashing co-located services. Also prevents DoS amplification where an attacker triggers expensive operations.

**4. If an attacker exploits Default vs Production, what's blocked in Production?**
- Cannot create raw sockets (no `NET_RAW`) — blocks network sniffing
- Cannot change file ownership (no `CHOWN`) — limits persistence
- Cannot load kernel modules (no `SYS_MODULE`) — blocks rootkits
- Cannot escalate via setuid binaries (`no-new-privileges`)
- Fork bomb contained to 100 PIDs
- Memory exhaustion capped at 512MB

**5. Additional hardening to add:**
- `--read-only` filesystem with explicit tmpfs mounts for writable paths
- `--user 1000:1000` to run as non-root
- Custom seccomp profile blocking unused syscalls (e.g., `ptrace`, `mount`)
- Network policy to restrict egress
- Image signing with Docker Content Trust
