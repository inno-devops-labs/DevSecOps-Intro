# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Environment

- Date: 2026-03-16
- OS: macOS (Darwin 25.3.0)
- Branch: `feature/lab7`
- Docker: 29.2.0
- Docker Scout CLI: 1.19.0
- Dockle: latest
- Target image: `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout CVE Scan Results

Docker Scout indexed **1004 packages** and detected **49 vulnerable packages** with a total of **118 vulnerabilities**:

| Severity | Count |
|----------|------:|
| CRITICAL | 11 |
| HIGH | 64 |
| MEDIUM | 31 |
| LOW | 5 |
| UNSPECIFIED | 7 |
| **Total** | **118** |

### 1.2 Top 5 Critical/High Vulnerabilities

| # | CVE ID | Package | Severity | CVSS | Impact |
|---|--------|---------|----------|------|--------|
| 1 | CVE-2026-22709 | vm2 3.9.17 | CRITICAL | 9.8 | Protection Mechanism Failure — sandbox escape allows arbitrary code execution on the host. The vm2 library is used to isolate untrusted code; this CVE completely bypasses that isolation. |
| 2 | CVE-2023-37903 | vm2 3.9.17 | CRITICAL | 9.8 | OS Command Injection — allows executing arbitrary OS commands from within the sandboxed VM context. No fix available for the affected range (<=3.9.19). |
| 3 | CVE-2019-10744 | lodash 2.4.2 | CRITICAL | 9.1 | Prototype Pollution — `defaultsDeep` function can be tricked into modifying `Object.prototype`, enabling denial of service or property injection attacks across the entire application. |
| 4 | CVE-2023-46233 | crypto-js 3.3.0 | CRITICAL | 9.1 | Broken Cryptographic Algorithm — default PBKDF2 uses only 1 iteration of MD5 instead of the standard SHA-256 with high iterations, making encrypted data trivially brute-forceable. |
| 5 | CVE-2015-9235 | jsonwebtoken 0.1.0 / 0.4.0 | CRITICAL | — | Improper Input Validation — allows crafting tokens that bypass signature verification, enabling authentication bypass and token forgery. |

**Additional noteworthy findings:**

- **Node.js 22.18.0** has 1 Critical + 4 High vulnerabilities (CVE-2025-55130, CVE-2026-21637, CVE-2025-59466, CVE-2025-59465, CVE-2025-55131) — all fixed in 22.22.0
- **express** 4.21.0 has 4 High severity vulnerabilities related to resource consumption and request smuggling
- **jsonwebtoken** appears in two versions (0.1.0, 0.4.0), both critically vulnerable — indicating the application ships intentionally vulnerable JWT implementations

### 1.3 Snyk Comparison

Snyk scanning was not performed because no `SNYK_TOKEN` was configured in the environment. In a production workflow, Snyk would provide additional vendor-specific vulnerability intelligence and license compliance checks. Docker Scout's findings are sufficient for this lab's analysis, as it identified 118 vulnerabilities across 49 packages with CVSS scoring.

### 1.4 Dockle Configuration Findings

Dockle identified **3 issues** (all INFO-level) and 1 SKIP:

| Level | Code | Finding | Security Concern |
|-------|------|---------|-----------------|
| **SKIP** | DKL-LI-0001 | Avoid empty password — failed to detect `etc/shadow` | Image uses distroless base (no traditional `/etc/shadow`), so the check cannot run. Distroless images are inherently more secure since they lack shell and user management utilities. |
| **INFO** | CIS-DI-0005 | Enable Content Trust for Docker | Without Docker Content Trust enabled (`DOCKER_CONTENT_TRUST=1`), pulled images are not verified for integrity. An attacker performing a registry MITM could inject a tampered image. |
| **INFO** | CIS-DI-0006 | Add HEALTHCHECK instruction | Without a HEALTHCHECK, Docker cannot determine if the application inside the container is healthy. Orchestrators (Kubernetes, Swarm) rely on health signals for automated restart and load balancing. |
| **INFO** | DKL-LI-0003 | Only put necessary files | Unnecessary `.DS_Store` files found in `node_modules/` (`micromatch/lib/.DS_Store`, `extglob/lib/.DS_Store`). These macOS metadata files are not security-critical but indicate the build was done on macOS without a proper `.dockerignore`. |

### 1.5 Security Posture Assessment

**Does the image run as root?**
No. The image uses a distroless base (`gcr.io/distroless/nodejs22-debian12`) and the Dockerfile uses `--chown=65532:0`, meaning the application runs as UID 65532 (the `nonroot` user in distroless). This is a strong security practice.

**Recommended improvements:**

1. **Update vm2 to 3.10.2+** or migrate to an alternative sandbox (vm2 is largely deprecated — the maintainer recommends `isolated-vm`).
2. **Update Node.js** from 22.18.0 to 22.22.0+ to fix 5 known vulnerabilities.
3. **Pin and update lodash** from 2.4.2 to 4.17.21 to fix prototype pollution and command injection.
4. **Update jsonwebtoken** from 0.1.0/0.4.0 to 9.0.0+ to fix authentication bypass vulnerabilities.
5. **Add HEALTHCHECK** instruction to the Dockerfile for better orchestration integration.
6. **Enable Docker Content Trust** in CI/CD pipelines to ensure image provenance.
7. **Add `.dockerignore`** with `.DS_Store` to prevent macOS metadata from leaking into images.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 CIS Docker Benchmark Summary

Docker Bench for Security v1.6.0 was run against the Docker Desktop environment (macOS). The tool executed 86 checks.

**Note:** Many filesystem and systemd checks returned "File not found" or "Directory not found" because Docker Desktop on macOS uses a Linux VM rather than native Linux filesystem paths. This is expected behavior.

| Result | Count |
|--------|------:|
| **PASS** | 17 |
| **WARN** | 14 |
| **NOTE** | 9 |
| **INFO** | 46 |
| **Score** | **-3** |

### 2.2 Analysis of WARN Findings

| Check | Finding | Security Impact | Remediation |
|-------|---------|----------------|-------------|
| **1.1.1** | No separate partition for containers | All container data shares the host filesystem. A container filling its storage can cause host-wide denial of service. | On production Linux hosts, mount `/var/lib/docker` on a dedicated partition. Not applicable to Docker Desktop. |
| **1.1.3** | Docker daemon auditing not configured | No audit trail for Docker daemon operations. Forensics and incident response cannot track who started/stopped containers or changed configuration. | Configure `auditd` rules for Docker daemon on Linux production hosts. |
| **1.1.4** | No auditing for `/run/containerd` | Container runtime events are not logged for security audit. | Add audit rules: `auditctl -w /run/containerd -k docker` |
| **2.2** | Network traffic not restricted between containers on default bridge | Containers on the default bridge network can freely communicate with each other. A compromised container can pivot laterally to attack other containers. | Set `"icc": false` in `/etc/docker/daemon.json` to restrict inter-container communication. |
| **2.9** | User namespace support not enabled | Containers share the host's UID/GID namespace. A container breakout running as root inside maps to root on the host. | Enable user namespace remapping in daemon configuration: `"userns-remap": "default"` |
| **2.12** | Docker client authorization not enabled | Any user with Docker socket access has full control. No RBAC or authorization plugin restricts API commands. | Deploy an authorization plugin (e.g., Open Policy Agent for Docker). |
| **2.13** | Centralized logging not configured | Container logs are stored only locally and may be lost on container removal. No aggregation for security monitoring. | Configure `"log-driver": "syslog"` or `"json-file"` with remote forwarding to a SIEM. |
| **2.14** | Containers not restricted from acquiring new privileges | Containers can escalate privileges via setuid/setgid binaries. An attacker could exploit SUID binaries to gain root. | Set `"no-new-privileges": true` in daemon configuration as a default. |
| **2.15** | Live restore not enabled | Restarting the Docker daemon kills all running containers, causing downtime. | Set `"live-restore": true` in daemon configuration. |
| **2.16** | Userland proxy not disabled | The userland proxy creates a process per published port, increasing attack surface and memory overhead. | Set `"userland-proxy": false` in daemon configuration. |
| **3.15** | Wrong ownership for Docker socket | Docker socket has incorrect ownership, potentially allowing unauthorized users to interact with the Docker daemon. | On Linux: `chown root:docker /var/run/docker.sock` |
| **3.16** | Wrong permissions for Docker socket | Docker socket permissions are too permissive. | On Linux: `chmod 660 /var/run/docker.sock` |
| **4.5** | Docker Content Trust not enabled | Images are pulled without signature verification. | `export DOCKER_CONTENT_TRUST=1` before pulling/building images. |
| **4.6** | No HEALTHCHECK in container images | 18 local images lack HEALTHCHECK instructions, including `bkimminich/juice-shop:v19.0.0`. Orchestrators cannot detect unhealthy containers. | Add `HEALTHCHECK` to Dockerfiles. |

### 2.3 PASS Highlights

- **2.3** — Logging level is set to `info` (proper verbosity for operations and security)
- **2.4** — Docker is allowed to manage iptables (required for proper network isolation)
- **2.5** — No insecure registries configured (all pulls go through TLS)
- **2.6** — AUFS storage driver not used (modern overlay2 is more secure and performant)
- **1.2.2** — Docker version 29.2.0 is current
- **5.1** — Swarm mode is not enabled (reduces attack surface)

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| **Capabilities dropped** | None | ALL | ALL |
| **Capabilities added** | Default set (~14 caps) | None | NET_BIND_SERVICE |
| **Security options** | None | no-new-privileges | no-new-privileges |
| **Memory limit** | Unlimited (7.65 GiB host) | 512 MiB | 512 MiB |
| **Memory swap** | Unlimited | Unlimited | 512 MiB (no swap) |
| **CPU limit** | Unlimited | 1.0 CPU | 1.0 CPU |
| **PID limit** | Unlimited | Unlimited | 100 |
| **Restart policy** | no | no | on-failure:3 |

### 3.2 Functionality Verification

All three profiles returned HTTP 200, confirming that security hardening does not break the application:

```
Default:    HTTP 200
Hardened:   HTTP 200
Production: HTTP 200
```

### 3.3 Resource Usage Comparison

| Container | CPU % | Memory Usage | Memory % |
|-----------|------:|-------------|--------:|
| juice-default | 2.16% | 172.9 MiB / 7.65 GiB | 2.21% |
| juice-hardened | 0.23% | 91.72 MiB / 512 MiB | 17.91% |
| juice-production | 1.61% | 93.78 MiB / 512 MiB | 18.32% |

The hardened and production containers used approximately the same memory (~92 MiB), well within the 512 MiB limit. The default container used more memory (172.9 MiB) — this variance is likely due to startup timing differences rather than security configuration.

### 3.4 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**Linux capabilities** are fine-grained privilege units that decompose the traditional root/non-root binary. Instead of granting full root access, specific capabilities (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_CHOWN`) can be assigned individually.

By default, Docker grants containers approximately 14 capabilities including `CAP_NET_RAW` (raw sockets for network sniffing), `CAP_SYS_CHROOT`, `CAP_SETUID`, `CAP_SETGID`, and `CAP_MKNOD`. Dropping ALL capabilities removes the ability to:

- Modify file ownership (`CAP_CHOWN`)
- Bind to privileged ports below 1024 (`CAP_NET_BIND_SERVICE`)
- Create raw network sockets for packet sniffing (`CAP_NET_RAW`)
- Change process UIDs/GIDs for privilege escalation (`CAP_SETUID`/`CAP_SETGID`)

**Why add back NET_BIND_SERVICE?** The production profile adds it so the application can bind to ports below 1024 if needed. In practice, Juice Shop runs on port 3000 (unprivileged), so even this capability could be omitted. The hardened profile works fine without it.

**Security trade-off:** Dropping all capabilities may break applications that require specific privileges (e.g., `NET_RAW` for ping, `SYS_PTRACE` for debugging). The correct approach is to drop ALL and selectively add back only what the application needs.

#### b) `--security-opt=no-new-privileges`

This flag sets the `PR_SET_NO_NEW_PRIVS` bit on the container process, which:

- Prevents child processes from gaining more privileges than the parent via `execve()`
- Blocks setuid/setgid binaries from elevating privileges
- Prevents exploitation of SUID binaries (e.g., a vulnerable `sudo` or `passwd` binary inside the container)

**Attack prevented:** Without this flag, an attacker who gains shell access inside a container could exploit a SUID-root binary to escalate to root within the container, then potentially escape to the host.

**Downsides:** Some legitimate operations require privilege escalation (e.g., `su`, `cron` running tasks as different users). For most microservice workloads, this flag has no impact since applications run as a single user.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits, a single container can consume **all host memory and CPU**, causing:

- **Memory exhaustion (OOM):** Other containers and the host OS starve, leading to system-wide instability
- **CPU starvation:** A crypto-mining payload or runaway process monopolizes all cores
- **Denial of Service:** An attacker exploiting a memory leak or CPU-intensive endpoint (e.g., regex DoS) can bring down the entire host

**Memory limiting** prevents Resource Exhaustion attacks. With `--memory=512m`, the container is OOM-killed if it exceeds 512 MiB instead of crashing the host.

**`--memory-swap=512m`** (production profile) sets swap equal to memory, meaning **no swap** is available. This prevents the container from using swap space, which would degrade host disk I/O performance.

**Risk of limits too low:** If the memory limit is below the application's working set, the container gets OOM-killed during normal operation. Monitoring actual usage (92 MiB in our test) against the limit (512 MiB) is essential for tuning.

#### d) `--pids-limit=100`

A **fork bomb** is a process that recursively creates copies of itself: `:(){ :|:& };:`. Without PID limits, this exponentially consumes all available PIDs on the host, preventing any new processes from starting — including recovery tools.

**How PID limiting helps:** With `--pids-limit=100`, the kernel refuses `fork()` calls once the container reaches 100 processes. The fork bomb is contained within the container; the host and other containers remain unaffected.

**Determining the right limit:** Monitor the application's peak process count during normal load. Juice Shop (Node.js single-thread with worker threads) typically uses 10-20 processes. A limit of 100 provides 5-10x headroom for request spikes while still preventing fork bombs.

#### e) `--restart=on-failure:3`

This policy automatically restarts the container up to 3 times if it exits with a non-zero exit code:

- **Beneficial:** Recovers from transient failures (OOM kills, crashed processes, failed health checks) without manual intervention. Essential for maintaining uptime in production.
- **Risky when excessive:** An attacker could exploit a restart loop to repeatedly trigger startup-time vulnerabilities or amplify resource consumption. The `:3` limit prevents infinite restart loops.

**`on-failure` vs `always`:**
- `on-failure:3` — restarts only on error exits, with a cap. If the container exits cleanly (code 0), it stays stopped. This is ideal for production services.
- `always` — restarts on any exit, including clean shutdown. This can interfere with intentional stops (maintenance, upgrades) and mask persistent failures.

### 3.5 Critical Thinking Questions

**1. Which profile for DEVELOPMENT? Why?**

The **Default** profile is appropriate for development. Developers need maximum flexibility: debugging tools, unrestricted resource usage for profiling, and no capability restrictions that might mask runtime behavior. Security hardening in development adds friction without reducing real risk (the environment is already trusted and ephemeral).

**2. Which profile for PRODUCTION? Why?**

The **Production** profile. It applies defense-in-depth: all capabilities dropped, no privilege escalation, resource limits to prevent DoS, PID limits against fork bombs, and a restart policy for resilience. The only addition over Hardened is PID limiting, swap restriction, and auto-restart — all critical for production reliability and security.

**3. What real-world problem do resource limits solve?**

Resource limits prevent the **Noisy Neighbor** problem in multi-tenant environments. In Kubernetes clusters or shared Docker hosts, one misbehaving container (memory leak, CPU-intensive vulnerability exploit, crypto-miner) can degrade performance for all co-located services. Resource limits provide isolation guarantees similar to how virtual machines isolate workloads but at the container level.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

In the **Default** profile, an attacker who gains code execution can:
- Escalate to root via SUID binaries
- Open raw network sockets for sniffing traffic (`CAP_NET_RAW`)
- Modify file ownership to access restricted files (`CAP_CHOWN`)
- Fork bomb the host
- Exhaust host memory and CPU
- Perform ARP spoofing on the container network

In the **Production** profile, all of the above are blocked:
- `no-new-privileges` prevents SUID exploitation
- `cap-drop=ALL` removes raw socket, chown, and other dangerous capabilities
- `pids-limit=100` contains fork bombs
- `memory=512m` prevents memory exhaustion
- The attacker is confined to the Node.js process with zero Linux capabilities

**5. What additional hardening would you add?**

1. **Read-only root filesystem** (`--read-only`) with explicit tmpfs mounts for writable paths — prevents an attacker from modifying application binaries or writing webshells.
2. **Custom seccomp profile** restricting syscalls to only what Node.js needs (~50 of ~300+ syscalls).
3. **AppArmor/SELinux profiles** for mandatory access control beyond capabilities.
4. **Network policies** (`--network=custom-bridge` with restricted inter-container communication) instead of the default bridge.
5. **Non-root user enforcement** at the daemon level (`"userns-remap": "default"`).
6. **Health checks** (`HEALTHCHECK --interval=30s CMD curl -f http://localhost:3000 || exit 1`) for automatic unhealthy container replacement.
7. **Image signing** with Docker Content Trust or cosign to verify image provenance.

---

## Appendix: Scan Evidence

### Docker Scout Summary

```
Target:            bkimminich/juice-shop:v19.0.0
Platform:          linux/arm64
Base image:        gcr.io/distroless/nodejs22-debian12:latest
Packages indexed:  1004
Vulnerable pkgs:   49

Vulnerabilities:   11C  64H  31M  5L  7?

Top vulnerable packages:
  vm2 3.9.17           — 4C 0H 1M 0L (sandbox escape, OS command injection)
  node 22.18.0         — 1C 4H 1M 0L (runtime vulnerabilities)
  lodash 2.4.2         — 1C 3H 1M 0L 1? (prototype pollution, command injection)
  jsonwebtoken 0.1.0   — 1C 1H 2M 0L 1? (auth bypass, broken crypto)
  crypto-js 3.3.0      — 1C 1H 0M 0L (broken PBKDF2)
  minimist 0.2.4       — 1C 0H 1M 0L (prototype pollution)
  express 4.21.0       — 0C 4H 0M 0L (resource consumption, request smuggling)
```

### Dockle Results

```
SKIP  - DKL-LI-0001: Avoid empty password (failed to detect etc/shadow)
INFO  - CIS-DI-0005: Enable Content trust for Docker
INFO  - CIS-DI-0006: Add HEALTHCHECK instruction to the container image
INFO  - DKL-LI-0003: Only put necessary files (.DS_Store in node_modules)
```

### Docker Bench for Security Summary

```
Docker Bench for Security v1.6.0
CIS Docker Benchmark 1.6.0

Checks: 86  |  Score: -3

Key WARN findings:
  1.1.1  — No separate container partition
  2.2    — Inter-container traffic unrestricted on default bridge
  2.9    — User namespace support not enabled
  2.12   — No Docker client authorization plugin
  2.13   — No centralized logging configured
  2.14   — Containers not restricted from acquiring new privileges
  2.15   — Live restore not enabled
  2.16   — Userland proxy not disabled
  3.15   — Wrong Docker socket ownership
  3.16   — Wrong Docker socket permissions
  4.5    — Docker Content Trust not enabled
  4.6    — No HEALTHCHECK in 18 images

Key PASS findings:
  1.2.2  — Docker version 29.2.0 is current
  2.3    — Logging level set to info
  2.5    — No insecure registries
  2.6    — AUFS not used
  5.1    — Swarm mode not enabled
```

### Deployment Comparison Output

```
=== Functionality Test ===
Default:    HTTP 200
Hardened:   HTTP 200
Production: HTTP 200

=== Resource Usage ===
NAME               CPU %   MEM USAGE / LIMIT     MEM %
juice-default      2.16%   172.9MiB / 7.65GiB    2.21%
juice-hardened     0.23%   91.72MiB / 512MiB     17.91%
juice-production   1.61%   93.78MiB / 512MiB     18.32%

=== Security Configurations ===
Container: juice-default
  CapDrop: <none>  SecurityOpt: <none>
  Memory: unlimited  CPU: unlimited  PIDs: unlimited  Restart: no

Container: juice-hardened
  CapDrop: [ALL]  SecurityOpt: [no-new-privileges]
  Memory: 512MiB  CPU: 1.0  PIDs: unlimited  Restart: no

Container: juice-production
  CapDrop: [ALL]  SecurityOpt: [no-new-privileges]
  Memory: 512MiB  CPU: 1.0  PIDs: 100  Restart: on-failure:3
```
