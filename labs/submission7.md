# Lab 7 — Container Security: Image Scanning & Deployment Hardening


## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout (CVE scan) summary
- Vulnerabilities: **11 Critical / 65 High / 30 Medium / 5 Low / 7 Unspecified**
- Packages analyzed: **1004**
- Image size: **172 MB**

### 1.2 Top 5 Critical/High Vulnerabilities (from Docker Scout output)

| # | CVE | Package (version) | Severity | Impact (from scan description) |
|---|-----|-------------------|----------|--------------------------------|
| 1 | CVE-2026-22709 | `vm2` (3.9.17) | Critical | Protection mechanism failure in the sandbox library, which can allow sandbox escape or arbitrary code execution. |
| 2 | CVE-2023-37903 | `vm2` (3.9.17) | Critical | OS command injection risk due to improper neutralization of special elements. |
| 3 | CVE-2023-37466 | `vm2` (3.9.17) | Critical | Code injection risk through improper control of code generation. |
| 4 | CVE-2023-32314 | `vm2` (3.9.17) | Critical | Injection via improper neutralization of special elements in output used by downstream components. |
| 5 | CVE-2019-10744 | `lodash` (2.4.2) | Critical | Prototype pollution allowing attacker-controlled object property injection. |

### 1.3 Snyk comparison highlights
- **OS package finding:** High severity `openssl/libssl3` (CVE-2025-69421), fixed in `3.0.18-1~deb12u2`.
- **Node runtime:** 1 critical + 4 high issues in `node@22.18.0` (fixed in `22.22.0`).
- **Application dependencies:** 47 issues across 975 dependencies; many are High severity (ReDoS, command injection, SSRF, auth bypass, DoS, etc.).

### 1.4 Dockle configuration findings
- **FATAL:** None
- **WARN:** None
INFO / SKIP observations:
- `CIS-DI-0005`: Content trust is not enabled (`DOCKER_CONTENT_TRUST=1` suggested).
- `CIS-DI-0006`: No `HEALTHCHECK` instruction found.
- `DKL-LI-0003`: Unnecessary `.DS_Store` files in the image.
- `DKL-LI-0001`: SKIP (could not detect `/etc/shadow`).

### 1.5 Security posture assessment
- **Does the image run as root?** The Dockle scan did **not** report any root-user warnings, so no explicit root issue was detected from the available outputs.
- **Main risks:** Numerous critical/high CVEs (notably in `vm2`, `lodash`, `jsonwebtoken`, and Node runtime). Missing healthcheck and content trust.
- **Recommended improvements:**
  - Update vulnerable libraries (especially `vm2`, `lodash`, `jsonwebtoken`) and Node runtime.
  - Add `HEALTHCHECK` to the image.
  - Enable Docker Content Trust for pulled/build images.
  - Remove unnecessary files (e.g., `.DS_Store`) and reduce image size.
  - Prefer non-root user and drop Linux capabilities in runtime configuration.

---

## TTask 2 — Docker Host Security Benchmarking

### 2.1 Summary statistics
- **PASS:** 21
- **WARN:** 15
- **FAIL:** 0
- **INFO:** 99

### 2.2 Analysis of failures
- **No FAIL findings** were reported.

### 2.3 Warnings and remediation

1. **1.1.1 Separate partition for containers** — Risk: mixed host/containers data increases blast radius.  
   Remediation: place `/var/lib/docker` on a dedicated partition or filesystem.

2. **1.1.3 Audit Docker daemon** — Risk: no audit trail for daemon activity.  
   Remediation: enable audit rules for Docker daemon binaries and sockets.

3. **1.1.4 Audit `/run/containerd`** — Risk: containerd events not logged.  
   Remediation: add audit rules for containerd runtime paths.

4. **1.1.5 Audit `/var/lib/docker`** — Risk: container storage changes not audited.  
   Remediation: add audit rules for Docker data directory.

5. **2.2 Restrict inter-container traffic on default bridge** — Risk: container-to-container lateral movement.  
   Remediation: enable `--icc=false` or use user-defined networks with proper isolation.

6. **2.9 Enable user namespace support** — Risk: UID 0 inside container maps to UID 0 on host.  
   Remediation: enable user namespaces (`userns-remap`) to reduce privilege impact.

7. **2.12 Docker client authorization** — Risk: any local user with Docker socket access can control the daemon.  
   Remediation: enable authorization plugins and restrict socket access.

8. **2.13 Centralized/remote logging** — Risk: local logs can be lost or tampered with.  
   Remediation: configure remote log drivers (e.g., syslog, fluentd, ELK).

9. **2.14 Restrict new privileges** — Risk: containers can gain privileges via setuid/capabilities.  
   Remediation: set daemon default `no-new-privileges` or use per-container flag.

10. **2.15 Enable live restore** — Risk: daemon restart stops containers.  
    Remediation: enable `"live-restore": true` in `daemon.json`.

11. **2.16 Disable userland proxy** — Risk: extra network attack surface.  
    Remediation: set `"userland-proxy": false`.

12. **4.5 Docker Content Trust** — Risk: unsigned images can be pulled.  
    Remediation: enable content trust and enforce signed images in pipelines.

13. **4.6 Add HEALTHCHECK** — Risk: no automated health verification.  
    Remediation: add `HEALTHCHECK` in Dockerfiles (at least for `juice-shop` image).

14. **4.6 (detail)** No healthcheck for `alpine:latest`.  
    Remediation: add healthcheck in the base image or wrap it with a custom Dockerfile.

15. **4.6 (detail)** No healthcheck for `bkimminich/juice-shop:v19.0.0`.  
    Remediation: add image-level healthcheck or runtime equivalent.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Functionality test
All profiles responded with **HTTP 200**:
- Default: 200
- Hardened: 200
- Production: 200

### 3.2 Resource usage snapshot
- Default: **113.5 MiB / 7.623 GiB (1.45%)**
- Hardened: **95.48 MiB / 512 MiB (18.65%)**
- Production: **95.61 MiB / 512 MiB (18.67%)**

### 3.3 Configuration comparison table (from `docker inspect` output)

| Setting | Default | Hardened | Production |
|--------|---------|----------|------------|
| CapDrop | `<no value>` | `[ALL]` | `[ALL]` |
| CapAdd | Not reported in captured output | Not reported in captured output | Not reported in captured output |
| SecurityOpt | `<no value>` | `[no-new-privileges]` | `[no-new-privileges]` |
| Memory | `0` (no limit) | `536870912` (512 MiB) | `536870912` (512 MiB) |
| CPU (CpuQuota) | `0` | `0` | `0` |
| PIDs limit | `<no value>` | `<no value>` | `100` |
| Restart policy | `no` | `no` | `on-failure` |

### 3.4 Security measure analysis

**a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`**
- **Linux capabilities** split root privileges into fine-grained permissions. Dropping them reduces the attack surface.
- **Dropping ALL** prevents many privilege-based attacks (e.g., raw socket use, module loading).
- **NET_BIND_SERVICE** is re-added to allow binding to low ports (<1024).
- **Trade-off:** stronger isolation vs. potential functionality limitations if the app needs extra privileges.

**b) `--security-opt=no-new-privileges`**
- Prevents processes from gaining additional privileges via setuid binaries or file capabilities.
- **Prevents:** privilege escalation after compromise.
- **Downside:** apps that rely on setuid helpers may break.

**c) `--memory=512m` and `--cpus=1.0`**
- Without limits, a container can consume host resources and starve other services (DoS / noisy neighbor).
- **Memory limits** mitigate memory exhaustion attacks and runaway processes.
- **Risk of low limits:** app crashes, OOM kills, or degraded performance if limits are too tight.

**d) `--pids-limit=100`**
- A **fork bomb** rapidly creates processes to exhaust system resources.
- **PID limiting** caps process creation, preventing process table exhaustion.
- **Choosing a limit:** profile typical workload + safety margin, then monitor and adjust.

**e) `--restart=on-failure:3`**
- Restarts the container up to 3 times only when it exits with a non-zero status.
- **Beneficial:** improves availability for transient failures.
- **Risky:** repeated crashes can hide bugs or create restart loops.
- **on-failure vs always:** `on-failure` is safer for predictable recovery; `always` restarts even for clean exits and can mask deliberate shutdowns.

### 3.5 Critical thinking questions

1. **Which profile for DEVELOPMENT? Why?**
   - **Default**, because it is closest to upstream defaults and easiest for debugging with fewer restrictions.

2. **Which profile for PRODUCTION? Why?**
   - **Production**, because it combines capability drops, no-new-privileges, memory + PID limits, and controlled restart policy.

3. **What real-world problem do resource limits solve?**
   - They prevent a single compromised or buggy container from consuming all host resources, protecting service availability for other workloads.

4. **If an attacker exploits Default vs Production, what actions are blocked in Production?**
   - Fewer Linux capabilities available, no privilege escalation via setuid, bounded memory/CPU usage, and limited process spawning due to PID limits.

5. **What additional hardening would you add?**
   - Run as a non-root user, add a read-only filesystem where possible, mount volumes with `noexec`, enable seccomp/AppArmor profiles, and isolate networking with dedicated bridge or service mesh policies.

---
