# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Top 5 Critical/High Vulnerabilities (Docker Scout)

Target image: `bkimminich/juice-shop:v19.0.0`
Total findings: **118 vulnerabilities** in 48 packages — CRITICAL: 11, HIGH: 65, MEDIUM: 30, LOW: 5, UNSPECIFIED: 7

| # | CVE ID | Package | Severity | CVSS | Impact |
|---|--------|---------|----------|------|--------|
| 1 | CVE-2026-22709 | vm2 ≤3.10.1 | CRITICAL | 9.8 | Protection Mechanism Failure — allows sandbox escape; attacker can execute arbitrary code on the host |
| 2 | CVE-2023-37466 | vm2 ≤3.9.19 | CRITICAL | 9.8 | Code Injection via async generator — full sandbox breakout enabling RCE |
| 3 | CVE-2023-37903 | vm2 ≤3.9.19 | CRITICAL | 9.8 | OS Command Injection via custom inspect function — unauthenticated RCE |
| 4 | CVE-2019-10744 | lodash <4.17.12 | CRITICAL | 9.1 | Prototype Pollution — allows attackers to modify `Object.prototype`, leading to privilege escalation or DoS |
| 5 | CVE-2023-46233 | crypto-js <4.2.0 | CRITICAL | 9.1 | Broken Cryptographic Algorithm — PBKDF2 implementation computes only 1 iteration instead of the configured count, drastically weakening password hashing |

**Additionally notable:** CVE-2023-32314 (vm2 <3.9.18, CRITICAL 9.8) — Sandbox escape via Proxy objects; CVE-2015-9235 (jsonwebtoken <4.2.2, CRITICAL) — JWT algorithm confusion allowing authentication bypass.

### 1.2 Dockle Configuration Findings

Dockle scan results for `bkimminich/juice-shop:v19.0.0`:

| Level | ID | Finding | Security Concern |
|-------|----|---------|-----------------|
| INFO | CIS-DI-0005 | `DOCKER_CONTENT_TRUST` not enabled | Without content trust, Docker does not verify image signatures. A compromised registry or MITM attack could substitute a malicious image silently |
| INFO | CIS-DI-0006 | No `HEALTHCHECK` instruction in Dockerfile | Without a health check, Docker cannot detect application-level failures. A crashed or compromised process continues to receive traffic with no automated recovery |
| INFO | DKL-LI-0003 | Unnecessary `.DS_Store` files in node_modules | macOS metadata files leak directory structure information and inflate image size. Indicates non-reproducible builds with developer machine artifacts |
| SKIP | DKL-LI-0001 | Could not detect `/etc/shadow` | Shadow file is absent or not parseable — dockle cannot verify password policies |

**No FATAL findings** were detected — the image does not expose secrets in ENV vars and does not run an obvious root shell as entrypoint at the Dockerfile level.

### 1.3 Security Posture Assessment

**Does the image run as root?**
Yes. Docker Scout and CIS Benchmark (check 4.1) confirm the container process runs as `root` (UID 0). The Dockerfile does not include a `USER` directive to drop privileges before starting Node.js.

**Recommended security improvements:**

1. **Add a non-root user** — Add `RUN addgroup -S appgroup && adduser -S appuser -G appgroup` and `USER appuser` in the Dockerfile. Running as root means any RCE vulnerability gives the attacker full container root privileges.
2. **Update vm2** — The vm2 package has multiple CRITICAL CVEs with no fix (the project is abandoned). Replace with a maintained sandbox alternative such as `isolated-vm`.
3. **Update lodash** — Upgrade to ≥4.17.21 to patch prototype pollution vulnerabilities.
4. **Update crypto-js** — Upgrade to ≥4.2.0 to fix the broken PBKDF2 implementation.
5. **Add HEALTHCHECK** — Add `HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:3000 || exit 1` to enable automated health monitoring.
6. **Enable content trust** — Set `DOCKER_CONTENT_TRUST=1` in CI/CD pipelines to enforce image signature verification.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 CIS Docker Benchmark Summary

Tool: `docker/docker-bench-security`
Total checks: **105**

| Status | Count |
|--------|-------|
| PASS | 41 |
| WARN | 42 |
| INFO | 79 |
| NOTE | 10 |
| FAIL | 0 |

Score: **16** (out of 112)

### 2.2 Analysis of Key Warnings

| Section | Check | Warning | Security Impact | Remediation |
|---------|-------|---------|-----------------|-------------|
| 1 — Host Config | 1.1 | No separate partition for `/var/lib/docker` | If the Docker data directory fills the root partition, the host OS can crash (DoS). Containers can also escape isolation via filesystem exhaustion | Create a dedicated LVM partition or use `--data-root` pointing to a separate disk |
| 1 — Host Config | 1.5 | Docker daemon not audited with `auditd` | Without audit logging, attacker activity on the Docker daemon (container starts, image pulls, exec commands) leaves no forensic trace | Add `/usr/bin/dockerd` to `/etc/audit/rules.d/docker.rules` |
| 2 — Daemon Config | 2.1 | Inter-container traffic not restricted on default bridge | Containers on the default bridge can communicate freely, allowing lateral movement if one container is compromised | Set `"icc": false` in `/etc/docker/daemon.json` |
| 2 — Daemon Config | 2.8 | User namespace support disabled | All containers share the host's UID namespace; root inside the container maps to root on the host. A container breakout immediately gives host root | Enable `"userns-remap": "default"` in `/etc/docker/daemon.json` |
| 2 — Daemon Config | 2.11 | No authorization plugin enabled | Any user with Docker socket access has unrestricted API access — equivalent to root | Install and configure an authorization plugin (e.g., `opa-docker-authz`) |
| 2 — Daemon Config | 2.18 | Containers not globally restricted from acquiring new privileges | Without `--no-new-privileges`, processes inside containers can use `setuid` binaries to gain elevated capabilities | Set `"no-new-privileges": true` in `daemon.json` |
| 4 — Images | 4.1 | `ml-app` container running as root | Root in container = near-root on host if kernel namespace is escaped | Add `USER` directive to `deployment-app` Dockerfile |
| 5 — Container Runtime | 5.10/5.11 | `ml-app` has no memory/CPU limits | Unbounded resource use enables DoS attacks; a compromised container can exhaust host resources | Add `--memory=1g --cpus=2.0` to `ml-app` startup |
| 5 — Container Runtime | 5.25 | `ml-app` not restricted from acquiring additional privileges | Suid/sgid binaries inside the container can escalate privileges | Start with `--security-opt=no-new-privileges` |

**Overall assessment:** The Docker host has no critical failures (FAIL: 0), but has 42 warnings covering daemon hardening, user namespace isolation, and runtime restrictions. The primary risks are the disabled user namespace support (2.8) and unrestricted inter-container communication (2.1).

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

> Note: `--cap-drop=ALL` alone caused `exec /nodejs/bin/node: operation not permitted` (exit 255) because the default seccomp profile blocked syscalls required for startup. The hardened profile used `seccomp=unconfined` to isolate that variable; the production profile used the default seccomp (without `seccomp=default` file path, which requires a file argument on this Docker version) and added back only minimum necessary capabilities.

| Parameter | juice-default | juice-hardened | juice-production |
|-----------|:-------------:|:--------------:|:----------------:|
| **Port** | 3001 | 3002 | 3003 |
| **CapDrop** | — | ALL | ALL |
| **CapAdd** | (full default set) | CHOWN, DAC_OVERRIDE, FOWNER, NET_BIND_SERVICE, SETGID, SETUID | CHOWN, DAC_OVERRIDE, FOWNER, NET_BIND_SERVICE, SETGID, SETUID |
| **SecurityOpt** | — | `seccomp=unconfined` | — (default seccomp) |
| **no-new-privileges** | No | No | No |
| **Memory limit** | Unlimited | 512 MiB | 512 MiB |
| **Memory swap** | Unlimited | 1024 MiB | 512 MiB (swap disabled) |
| **CPUs** | Unlimited | 1.0 | 1.0 |
| **PIDs limit** | Unlimited | Unlimited | 100 |
| **Restart policy** | no | no | on-failure (max 3) |
| **HTTP response** | 200 OK | 200 OK | 200 OK |
| **Memory usage** | ~101 MiB / 15 GiB (0.6%) | ~92 MiB / 512 MiB (18%) | ~91 MiB / 512 MiB (18%) |

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**
Linux capabilities are fine-grained units of root privilege. Instead of an all-or-nothing root account, the kernel breaks root's power into ~40 individual capabilities (e.g., `CAP_NET_BIND_SERVICE` to bind ports below 1024, `CAP_CHOWN` to change file ownership, `CAP_SYS_PTRACE` to trace processes). A process can hold only the capabilities it needs.

**What attack vector does `--cap-drop=ALL` prevent?**
By default, Docker containers start with a set of ~14 capabilities. If an attacker achieves RCE inside a container, they inherit all of these. Capabilities like `CAP_NET_RAW` allow ARP spoofing and packet sniffing across the host network; `CAP_SYS_ADMIN` can be used to mount filesystems or escape the container namespace. Dropping ALL removes the entire attack surface.

**Why add back `NET_BIND_SERVICE`?**
The Juice Shop application listens on port 3000 (>1024), so `NET_BIND_SERVICE` is not strictly required here. However, in production scenarios where an application needs to bind port 80/443 directly, this capability is required. Without it, the bind syscall returns `EACCES`.

**Security trade-off:**
Dropping all capabilities greatly reduces the blast radius of container compromise but may break applications that rely on capabilities for legitimate operations (e.g., ping requires `CAP_NET_RAW`, setuid binaries need `CAP_SETUID`). Capability requirements must be determined per application.

#### b) `--security-opt=no-new-privileges`

**What does this flag do?**
It sets the `PR_SET_NO_NEW_PRIVS` bit on the container init process, which is inherited by all child processes. This prevents any process from gaining new privileges via `execve()`, even if the executed binary has the setuid or setgid bit set.

**What type of attack does it prevent?**
Privilege escalation via setuid binaries. Without this flag, an attacker who achieves code execution as a low-privileged user inside a container could run a setuid-root binary (e.g., `/usr/bin/sudo`, `/usr/bin/newgrp`) to gain root privileges within the container, and potentially leverage those to escape to the host.

**Downsides:**
Applications that legitimately use setuid binaries will break. In this lab, combining `--cap-drop=ALL` with `--no-new-privileges` caused Juice Shop's startup to fail (`exec /nodejs/bin/node: operation not permitted`) because the image entrypoint changes the effective UID at startup. Diagnosis: the image runs as root and uses a privilege-transition mechanism incompatible with `no-new-privileges` under a fully stripped capability set.

#### c) `--memory=512m` and `--cpus=1.0`

**What happens without resource limits?**
A container without memory limits can consume all available host RAM, causing the OOM killer to terminate other processes — including the Docker daemon or other containers. Without CPU limits, a single container can monopolize all CPU cores.

**What attack does memory limiting prevent?**
Memory exhaustion (DoS) attacks. If an attacker injects a payload that causes unbounded memory allocation (e.g., a billion laughs XML attack, large file upload loops), an unrestricted container crashes the entire host. With a 512 MiB limit, only that container is affected.

**Risk of limits too low:**
If the limit is below the application's working memory footprint, the container is OOM-killed repeatedly, causing service unavailability — a self-inflicted DoS. Limits should be set ~20-30% above the observed peak memory usage under load.

#### d) `--pids-limit=100`

**What is a fork bomb?**
A fork bomb is a program that recursively creates child processes (e.g., `:(){ :|:& };:` in bash) until process table exhaustion causes the host to hang. A single container without a PID limit can fork thousands of processes, starving the kernel's process table.

**How does PID limiting help?**
`--pids-limit=100` caps the total number of processes and threads inside the container. Once the limit is reached, `fork()` returns `EAGAIN`. The attack is contained to 100 processes maximum, leaving the host and other containers functional.

**How to determine the right limit?**
Use `docker stats --format "{{.PIDs}}"` during normal operation under load. Set the limit to 2–3x the observed peak PID count to allow for burst workloads without leaving headroom for a fork bomb.

#### e) `--restart=on-failure:3`

**What does this policy do?**
Docker automatically restarts the container when the main process exits with a non-zero exit code. The `:3` suffix limits automatic restarts to 3 attempts before Docker stops retrying.

**When is auto-restart beneficial? When is it risky?**
- **Beneficial:** Transient failures (OOM kill, temporary network loss, database connection timeout) are recovered automatically without operator intervention. Improves availability SLOs.
- **Risky:** If the container is repeatedly crashing due to a bug or active exploitation, `always` restarts perpetuate the crash loop without investigation. The `:3` limit prevents infinite restart loops. Additionally, if an attacker deliberately crashes the container to trigger a restart with a different environment state, unlimited restarts enable a timing attack.

**`on-failure` vs `always`:**
`always` restarts on *any* exit, including exit code 0 (clean shutdown), and also restarts the container when the Docker daemon starts (survives reboots). `on-failure` only restarts on non-zero exits and does not restart if the process exited cleanly or if Docker was explicitly told to stop the container. For production, `on-failure:3` is safer — it does not restart intentional shutdowns and has an automatic circuit breaker.

### 3.3 Critical Thinking Questions

**1. Which profile for DEVELOPMENT? Why?**
**juice-default** — Development requires maximum flexibility: mounting host directories, using a debugger (`--cap-add=SYS_PTRACE`), running tools that need extra permissions. Security restrictions in development slow down iteration and cause hard-to-diagnose failures (as seen when `--cap-drop=ALL` broke startup). Security hardening should be validated in a staging environment, not during active development.

**2. Which profile for PRODUCTION? Why?**
**juice-production** — It applies the principle of least privilege (minimal capabilities), resource limits (prevents DoS), PID limiting (prevents fork bombs), and a restart policy (improves availability). These measures reduce the blast radius of exploitation: an attacker gaining RCE has fewer capabilities to leverage for host escape and cannot exhaust host resources.

**3. What real-world problem do resource limits solve?**
**Noisy neighbour / resource starvation.** In multi-tenant environments (shared Kubernetes nodes, VPS hosting), one misbehaving or compromised container can consume all CPU and memory, degrading or crashing all other services on the host. Resource limits guarantee each container receives only its allocated share, similar to QoS policies in network routing. This also protects against denial-of-service attacks targeting specific services.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

In `juice-default`, the attacker has the full Docker default capability set and no resource restrictions. In `juice-production`, the following actions are blocked or severely limited:

| Attacker Action | Blocked in Production? | Reason |
|-----------------|:----------------------:|--------|
| ARP spoofing / raw packet injection | ✅ Yes | `CAP_NET_RAW` dropped |
| Mounting host filesystems | ✅ Yes | `CAP_SYS_ADMIN` dropped |
| Modifying network interfaces | ✅ Yes | `CAP_NET_ADMIN` dropped |
| Killing host processes via `CAP_KILL` | ✅ Yes | dropped |
| Fork bomb / process exhaustion | ✅ Yes | `--pids-limit=100` |
| Memory exhaustion of host | ✅ Yes | `--memory=512m` |
| CPU starvation of host | ✅ Yes | `--cpus=1.0` |
| Container runs indefinitely after crash | ✅ Limited | restart capped at 3 |
| Reading arbitrary host files via `CAP_DAC_READ_SEARCH` | ✅ Yes | dropped |

**5. What additional hardening would you add?**

- **Non-root user:** Add `USER node` (or a dedicated app user) in the Dockerfile to eliminate root privilege inside the container entirely.
- **Read-only root filesystem:** Add `--read-only` with specific writable tmpfs mounts for `/tmp` and log directories. Prevents an attacker from writing malware to the container filesystem.
- **Network isolation:** Use a custom bridge network instead of the default; enable `--icc=false` on the daemon to prevent lateral movement between containers.
- **Seccomp profile:** Create a custom seccomp allowlist profile restricting syscalls to only those needed by Node.js (instead of the full default set or `unconfined`).
- **Image signing:** Enable Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) and sign images with `docker trust sign` to prevent supply-chain attacks via tampered images.
- **Distroless or minimal base image:** Rebuild Juice Shop on a distroless Node.js base (e.g., `gcr.io/distroless/nodejs`) to eliminate shell, package manager, and debugging utilities that attackers rely on post-exploitation.
- **Regular dependency updates:** Replace or patch the abandoned `vm2` library. Integrate Docker Scout or Snyk into the CI pipeline with a blocking gate on CRITICAL CVEs.
