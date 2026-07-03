# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Vulnerability Scanning (Docker Scout)

Docker Scout found **195 vulnerabilities** across **57 packages** in `bkimminich/juice-shop:v19.0.0`:

| Severity    | Count |
|-------------|-------|
| CRITICAL    | 29    |
| HIGH        | 85    |
| MEDIUM      | 54    |
| LOW         | 9     |
| UNSPECIFIED | 18    |

#### Top 5 Critical/High Vulnerabilities

| CVE ID | Package | CVSS | Description | Impact |
|--------|---------|------|-------------|--------|
| CVE-2026-47208 | vm2 3.9.17 | 10.0 | Improper Control of Dynamically-Managed Code Resources | Full sandbox escape — RCE, data exfiltration |
| CVE-2026-47140 | vm2 3.9.17 | 10.0 | Protection Mechanism Failure | Sandbox escape allowing arbitrary code execution on host |
| CVE-2026-44006 | vm2 3.9.17 | 10.0 | Code Injection via `vm2` | Remote code execution with full system compromise |
| CVE-2026-26996 | minimatch <3.1.3 | 8.7 | Inefficient Regular Expression Complexity (ReDoS) | DoS via crafted glob patterns, CPU exhaustion |
| CVE-2026-23950 | tar <=7.5.3 | 8.8 | Improper Handling of Unicode Encoding | Remote code execution via crafted tar archives |

All 21 CVE entries in `vm2` are Critical (CVSS 9.8–10.0), making it the single riskiest dependency.

### 1.2 Snyk Scan

Snyk was unable to complete the scan due to network connectivity restrictions (firewall/proxy timeout). The Docker Scout scan above covers the vulnerability analysis.

### 1.3 Dockle Configuration Assessment

Dockle found no FATAL or WARN issues. The findings were all informational:

| Code | Severity | Finding | Security Concern |
|------|----------|---------|-----------------|
| CIS-DI-0005 | INFO | Content trust not enabled | Without `DOCKER_CONTENT_TRUST`, images could be tampered with during pull |
| CIS-DI-0006 | INFO | No HEALTHCHECK instruction | Containers cannot be automatically restarted when unhealthy |
| DKL-LI-0003 | INFO | Unnecessary files (`.DS_Store`) | Build cache leakage; metadata exposure |

### 1.4 Security Posture Assessment

- **Root user**: The image runs as root (no `USER` directive in Dockerfile)
- **Recommendations**:
  1. Update `vm2` to >=3.11.4 (most critical CVEs fixed there)
  2. Run as non-root user via `USER` directive
  3. Add `HEALTHCHECK` instruction
  4. Enable Docker Content Trust for image pulls
  5. Add `.dockerignore` to exclude `.DS_Store` and other metadata files

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Summary Statistics

| Result | Count |
|--------|-------|
| PASS   | 44    |
| WARN   | 95    |
| INFO   | 74    |
| NOTE   | 10    |

**Total checks**: 105 | **Score**: 15

### 2.2 Analysis of Key Failures

| Check | Finding | Security Impact | Remediation |
|-------|---------|----------------|-------------|
| 1.1 | No separate partition for containers | Container writes can fill host filesystem causing DoS | Use dedicated partition/volume for `/var/lib/docker` |
| 2.1 | Inter-container traffic not restricted on default bridge | Containers on default bridge can reach each other increasing attack surface | Create user-defined networks with `--opt com.docker.network.bridge.name` |
| 2.8 | User namespace support not enabled | Container root = host root for some operations, enabling privilege escalation | Start dockerd with `--userns-remap=default` |
| 5.10 | No memory limits on running containers | Unbounded memory usage can lead to host OOM | Add `--memory` to all `docker run` commands |
| 5.12 | Root filesystem mounted read/write | Compromised container can modify binaries/persistence | Use `--read-only` rootfs with tmpfs for write locations |
| 5.25 | New privileges not restricted | Process can gain additional capabilities via `suid` binaries | Add `--security-opt=no-new-privileges` |
| 5.28 | PIDs cgroup limit not used | Fork bomb can exhaust host process table | Add `--pids-limit` to container run commands |

### 2.3 Overall Assessment

The host scored **15** on the CIS Docker Benchmark, indicating significant room for improvement. The main gaps are lack of resource constraints, no AppArmor/SELinux profiles, and unconfined inter-container traffic. Production Docker hosts should enforce user namespace remapping, resource limits, and read-only root filesystems.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| CapDrop | (none) | ALL | ALL |
| CapAdd | (none) | (none) | NET_BIND_SERVICE |
| SecurityOpt | (none) | no-new-privileges | no-new-privileges |
| Memory | unlimited | 512 MiB | 512 MiB |
| Memory+Swap | unlimited | 1024 MiB | 512 MiB (swap disabled) |
| CPU | unlimited | 1.0 core | 1.0 core |
| PIDs limit | unlimited | unlimited | 100 |
| Restart policy | none | none | on-failure:3 |
| HTTP status | 200 OK | 200 OK | 200 OK |
| Mem usage | 104.1 MiB | 93.6 MiB | 93.5 MiB |

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**Linux capabilities** are granular privileges that partition the power of root into independent units (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`). By default, Docker containers get a restricted set of capabilities.

Dropping **ALL** capabilities eliminates attack vectors that abuse kernel features — e.g., `CAP_SYS_ADMIN` (mount, namespace ops), `CAP_NET_RAW` (packet crafting), `CAP_DAC_OVERRIDE` (bypass file permissions).

Adding back `NET_BIND_SERVICE` is required because a web server needs to bind to privileged ports (<1024). The trade-off: each added capability modestly expands the attack surface, but `CAP_NET_BIND_SERVICE` only allows binding to low ports — no kernel-exploit risk.

#### b) `--security-opt=no-new-privileges`

Prevents processes from gaining additional privileges via `setuid`/`setgid` binaries or `capabilities`-granting syscalls. This blocks a common container escape pattern: exploit a process, then escalate via a SUID binary. No real downsides — all modern apps should work without gaining new privileges at runtime.

#### c) `--memory=512m` and `--cpus=1.0`

Without limits, a single container can consume all host resources, causing **resource starvation** for neighbors (noisy neighbor problem). Memory limits specifically prevent **OOM killer** scenarios where the kernel kills arbitrary processes. Setting limits too low causes premature OOM kills — limits should be based on load testing.

#### d) `--pids-limit=100`

A **fork bomb** rapidly spawns processes until the system runs out of PIDs, making the host unresponsive. PID limits cap the number of simultaneous processes per container. The right limit depends on the app: for Juice Shop (~20 processes baseline), 100 provides headroom while preventing runaway forks.

#### e) `--restart=on-failure:3`

Automatically restarts the container if it exits with a non-zero code, up to 3 retries. Beneficial for transient failures (e.g., startup race conditions). Risky if the crash is due to an exploit — the attacker gets repeated attempts. `always` restarts even on manual stop (via `docker stop`), which is less desirable during maintenance.

### 3.3 Critical Thinking

1. **Development**: Default profile. Developers need flexibility to debug, exec into containers, test configurations. Restrictions hinder productivity.

2. **Production**: Production profile. Maximum hardening prevents real-world attacks: no kernel capabilities, resource isolation, privilege escalation blocked, fork bombs prevented, auto-healing from crashes.

3. **Resource limits** prevent the "noisy neighbor" problem in multi-tenant environments and protect against DoS attacks that exhaust host resources.

4. **In Production vs. Default**, an attacker exploiting the container would be blocked from:
   - Using kernel capabilities for container escape
   - Fork bombing the host (PID limit)
   - Escalating privileges via SUID binaries
   - Starving host memory/CPU (resource limits)

5. **Additional hardening**: read-only rootfs, AppArmor/SELinux profile, dropped `NET_RAW` capability, user namespace remapping, seccomp profile restriction beyond default, and vulnerability scanning in CI/CD pipeline.
