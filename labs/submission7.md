# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Top 5 Critical/High Vulnerabilities

The Docker Scout scan of `bkimminich/juice-shop:v19.0.0` found **107 total vulnerabilities** across 54 packages: **12 Critical, 74 High, 41 Medium, 8 Low**.

| # | CVE ID | Package | Severity | CVSS | Impact |
|---|--------|---------|----------|------|--------|
| 1 | CVE-2026-22709 | vm2 3.9.17 | CRITICAL | 9.8 | Protection Mechanism Failure — allows sandbox escape, leading to arbitrary code execution on the host. The vm2 sandbox can be completely bypassed. |
| 2 | CVE-2023-37903 | vm2 3.9.17 | CRITICAL | 9.8 | OS Command Injection — attacker can execute arbitrary system commands through the vm2 sandbox, achieving full remote code execution. No fix available (library deprecated). |
| 3 | CVE-2023-46233 | crypto-js 3.3.0 | CRITICAL | 9.1 | Broken/Risky Cryptographic Algorithm — the PBKDF2 implementation uses MD5 and only one iteration, making password hashing trivially crackable. |
| 4 | CVE-2019-10744 | lodash 2.4.2 | CRITICAL | 9.1 | Prototype Pollution — attacker can inject properties into Object.prototype via `defaultsDeep`, affecting all objects in the application and potentially leading to RCE. |
| 5 | CVE-2026-33937 | handlebars 4.7.7 | CRITICAL | 9.8 | Type Confusion — allows template injection attacks that can lead to remote code execution through crafted Handlebars templates. |

### 1.2 Dockle Configuration Findings

The Dockle scan returned the following findings:

| Level | Check ID | Finding | Security Concern |
|-------|----------|---------|------------------|
| INFO | CIS-DI-0005 | Content trust not enabled | Without Docker Content Trust, images are not verified for integrity and publisher authenticity. A compromised registry could serve tampered images. |
| INFO | CIS-DI-0006 | No HEALTHCHECK instruction | Without a health check, Docker cannot detect if the application has crashed or become unresponsive, potentially leaving a zombie container running. |
| INFO | DKL-LI-0003 | Unnecessary files (.DS_Store) in node_modules | Leaking build environment metadata (macOS artifacts) into production images increases attack surface and indicates sloppy image build hygiene. |
| SKIP | DKL-LI-0001 | Could not detect etc/shadow | Unable to verify if empty passwords exist — this is a positive sign that the image uses a minimal filesystem. |

Notably, the Dockle scan did **not** flag FATAL or WARN issues, indicating that the Juice Shop image follows reasonable Dockerfile best practices (e.g., it does not run as root in the Dockerfile `USER` directive). However, at runtime the container does run as root unless overridden.

### 1.3 Security Posture Assessment

**Does the image run as root?**
Yes. The `bkimminich/juice-shop:v19.0.0` image does not set a non-root `USER` in its Dockerfile. By default, the Node.js process runs as UID 0 (root) inside the container. This means that if an attacker exploits one of the many critical vulnerabilities (e.g., vm2 sandbox escape), they gain root-level access within the container namespace.

**Recommended security improvements:**
1. **Add a non-root USER** — run the Node.js process as an unprivileged user (e.g., `node`) to limit damage from container escape
2. **Update vulnerable dependencies** — vm2 is deprecated and should be replaced; lodash, crypto-js, and handlebars need major version upgrades
3. **Add HEALTHCHECK** — enables orchestrators to detect and restart unresponsive containers
4. **Enable Content Trust** — `export DOCKER_CONTENT_TRUST=1` to verify image signatures
5. **Use multi-stage builds** — reduce the attack surface by excluding build tools and unnecessary files from the final image

### 1.4 Snyk Comparison

Snyk scan was attempted but failed with authentication error (`SNYK-0005`) because no `SNYK_TOKEN` was configured in the environment. The Docker Scout scan above provides comprehensive CVE coverage as the primary scanning tool.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Summary Statistics

The CIS Docker Benchmark (v1.3.4) audit produced the following results:

| Result | Count |
|--------|-------|
| PASS | 27 |
| WARN | 22 |
| INFO | 22 |
| NOTE | 8 |

Total checks: **105**, Score: **16**

### 2.2 Analysis of Key Failures (WARN)

#### Host Configuration (Section 1)

| Check | Finding | Security Impact | Remediation |
|-------|---------|-----------------|-------------|
| 1.1 | No separate partition for containers | Container storage on the root partition means a container filling disk could crash the host OS | Create a dedicated partition (e.g., `/var/lib/docker`) on a separate volume |
| 1.5-1.10 | Auditing not configured for Docker daemon, files, and directories | No audit trail for Docker operations — security incidents cannot be investigated after the fact | Install and configure `auditd` rules for `/usr/bin/dockerd`, `/var/lib/docker`, `/etc/docker`, `docker.service`, and `docker.socket` |

#### Docker Daemon Configuration (Section 2)

| Check | Finding | Security Impact | Remediation |
|-------|---------|-----------------|-------------|
| 2.1 | Inter-container communication not restricted | Containers on the default bridge can freely communicate, enabling lateral movement if one is compromised | Set `"icc": false` in `/etc/docker/daemon.json` |
| 2.8 | User namespaces not enabled | Containers share the host's user namespace — root in container = root on host if a breakout occurs | Enable `userns-remap` in daemon configuration |
| 2.11 | No authorization plugin | Any user with Docker socket access can run any Docker command without fine-grained access control | Deploy an authorization plugin like `authz-broker` |
| 2.14 | Live restore not enabled | Docker daemon restart kills all containers, causing downtime | Set `"live-restore": true` in daemon configuration |
| 2.15 | Userland proxy enabled | The userland proxy is less efficient and exposes more attack surface than hairpin NAT | Set `"userland-proxy": false` in daemon configuration |
| 2.18 | Containers not restricted from acquiring new privileges | Processes inside containers can escalate privileges via setuid binaries or capabilities | Set `"no-new-privileges": true` as daemon default |

#### Container Runtime (Section 5)

| Check | Finding | Security Impact | Remediation |
|-------|---------|-----------------|-------------|
| 5.2 | No SELinux/security options on running containers | No mandatory access control enforcement on containers (registry, ELK stack) | Add `--security-opt` flags to container deployments |
| 5.10 | Containers running without memory limits | Containers can consume all host memory, causing OOM kills of other processes or the host itself | Always set `--memory` and `--memory-swap` limits |
| 5.12 | Root filesystem mounted read-write | A compromised container can modify its own filesystem, persist malware, or tamper with application binaries | Use `--read-only` flag where possible |
| 5.25 | Privilege escalation not restricted | Containers can gain additional privileges through setuid/setgid binaries | Add `--security-opt=no-new-privileges` |
| 5.28 | No PID limits set | Containers can fork-bomb the host, exhausting the PID table and causing a denial of service | Set `--pids-limit` on all containers |

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

Data from `docker inspect` output of the three deployment profiles:

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| **CapDrop** | *(none)* | ALL | ALL |
| **CapAdd** | *(none)* | *(none)* | NET_BIND_SERVICE |
| **SecurityOpt** | *(none)* | no-new-privileges | no-new-privileges |
| **Memory Limit** | 0 (unlimited) | 512 MB | 512 MB |
| **Memory+Swap** | 0 (unlimited) | *(kernel default)* | 512 MB |
| **CPU Quota** | 0 (unlimited) | 0 (limited via --cpus=1.0) | 0 (limited via --cpus=1.0) |
| **PIDs Limit** | *(none)* | *(none)* | 100 |
| **Restart Policy** | no | no | on-failure (max 3) |

**Functionality Test Results** (all profiles returned HTTP 200):
```
Default:    HTTP 200 — fully functional
Hardened:   HTTP 200 — fully functional
Production: HTTP 200 — fully functional
```

**Resource Usage Snapshot:**
```
NAME               CPU %   MEM USAGE / LIMIT   MEM %
juice-default      1.12%   106MiB / 6.991GiB   1.48%
juice-hardened     2.93%   91.62MiB / 512MiB    17.89%
juice-production   1.08%   93.87MiB / 512MiB    18.33%
```

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**Linux capabilities** are a fine-grained decomposition of the traditional UNIX root privilege into distinct units. Instead of an all-or-nothing root model, capabilities break privileges into ~40 individual permissions (e.g., `CAP_NET_RAW` for raw sockets, `CAP_SYS_ADMIN` for mount operations, `CAP_CHOWN` for changing file ownership).

By default, Docker containers receive a subset of ~14 capabilities. **Dropping ALL capabilities** removes every privilege: the process cannot change file ownership, bind to privileged ports, load kernel modules, trace processes, or perform any other privileged operation. This prevents an attacker who gains code execution from escalating their access — even as root inside the container, they cannot perform privileged system calls.

**NET_BIND_SERVICE** is added back because it allows binding to ports below 1024 (e.g., port 80 or 443). Without it, web servers cannot listen on standard HTTP/HTTPS ports. This is the principle of least privilege in action: grant only the single capability the application needs.

**Security trade-off:** Dropping all capabilities significantly hardens the container, but some applications may break if they require specific capabilities. Testing is essential. In this case, Juice Shop runs on port 3000 (unprivileged) so NET_BIND_SERVICE isn't strictly necessary, but it's included to demonstrate the pattern for production services.

#### b) `--security-opt=no-new-privileges`

This flag sets the `no_new_privs` bit on the process, which is a Linux kernel feature (since 3.5) that prevents the process and its children from gaining additional privileges through `execve()`. Specifically, it blocks:

- **setuid/setgid binaries**: Programs like `su`, `sudo`, `ping`, or `passwd` that normally escalate privileges will run with the caller's original privileges instead
- **Capability escalation via file capabilities**: Executables with file-based capability bits are ignored

This prevents a class of **privilege escalation attacks** where an attacker, having gained code execution as an unprivileged user, uses a setuid binary to become root.

**Downsides:** Applications that legitimately need to execute setuid binaries will fail. This is rare in containerized applications but can affect containers running cron jobs or multi-user environments.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits, a container can consume all available host memory and CPU, which creates two attack vectors:

1. **Denial of Service (DoS):** A memory leak, crypto-mining malware, or intentional resource exhaustion attack can starve other containers and the host OS. The Linux OOM killer may kill critical processes.
2. **Noisy neighbor problem:** In multi-tenant environments, one misbehaving container degrades performance for all others.

**Memory limiting** enforces a hard cap. When the container exceeds 512 MB, the kernel's OOM killer terminates processes inside the container rather than affecting the host. The `--memory-swap=512m` setting (equal to memory) disables swap usage entirely, preventing slow performance degradation.

**CPU limiting** (`--cpus=1.0`) restricts the container to at most one CPU core's worth of processing time, preventing CPU starvation of other workloads.

**Risk of setting limits too low:** The application may be OOM-killed during normal operation (e.g., during traffic spikes), causing availability issues. The 512 MB limit here is adequate for Juice Shop, which uses ~95 MB at idle.

#### d) `--pids-limit=100`

A **fork bomb** is a denial-of-service attack where a process recursively creates child processes (e.g., `:(){ :|:& };:` in bash). Each forked process creates more processes exponentially, exhausting the system's PID table within seconds. When no more PIDs can be allocated, no new processes can start on the entire host — including SSH sessions needed for recovery.

**PID limiting** caps the number of processes a container can create. With `--pids-limit=100`, a fork bomb is contained at 100 processes and cannot exhaust the host PID table.

**Determining the right limit:** Monitor the container's typical process count during normal operation and peak load, then set the limit to 2-3x that value. For a single Node.js application like Juice Shop, 100 is generous (it typically runs 1-5 processes). Production workloads running worker pools or thread pools may need higher limits.

#### e) `--restart=on-failure:3`

This policy tells Docker to automatically restart the container if it exits with a non-zero exit code, up to a maximum of 3 attempts.

**When auto-restart is beneficial:**
- Recovering from transient failures (temporary network issues, OOM events)
- Maintaining service availability without external orchestration
- Crash-loop recovery for intermittent bugs

**When auto-restart is risky:**
- A container that crashes due to a security exploit could be restarted, giving the attacker repeated opportunities
- A misconfigured container in a restart loop wastes resources and can fill disk with logs
- Maximum retry limit (3) prevents infinite restart loops

**`on-failure` vs `always`:**
- `on-failure:3` only restarts on error exits (non-zero code) and stops after 3 attempts — ideal for production because it gives up on persistent failures
- `always` restarts unconditionally, even on clean exits (code 0) and after daemon restart — risks masking bugs and wastes resources on irrecoverable failures

### 3.3 Critical Thinking Questions

**1. Which profile for DEVELOPMENT? Why?**

The **Default** profile is appropriate for development. Developers need unrestricted access to debug, inspect, and modify the running application. Capability restrictions and resource limits can interfere with debugging tools (e.g., `strace`, profilers) and cause confusing OOM kills during development. The priority in development is velocity and debuggability, not hardening.

**2. Which profile for PRODUCTION? Why?**

The **Production** profile should be used, with additional hardening. It applies defense-in-depth through multiple layers: capability restrictions prevent privilege escalation, resource limits prevent DoS, PID limits prevent fork bombs, and restart policies ensure availability. Every security control adds a barrier an attacker must bypass. I would additionally recommend `--read-only` filesystem, a non-root user, and network policy restrictions.

**3. What real-world problem do resource limits solve?**

Resource limits prevent the **noisy neighbor** and **resource exhaustion** problems. In 2017, a cryptocurrency mining malware infected Docker containers on exposed APIs, consuming 100% CPU and memory. Without limits, a single compromised container could bring down an entire host running dozens of services. Resource limits contain the blast radius — even if a container is compromised, it can only consume its allocated share.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

In the **Default** profile, an attacker gaining code execution can:
- Escalate to root via setuid binaries (`su`, `sudo`)
- Mount filesystems, load kernel modules (CAP_SYS_ADMIN)
- Capture network traffic (CAP_NET_RAW)
- Change file ownership (CAP_CHOWN)
- Fork bomb the host (unlimited PIDs)
- Exhaust host memory (unlimited memory)
- Bind to any privileged port

In the **Production** profile, ALL of these actions are blocked:
- `--cap-drop=ALL` removes all 14+ default capabilities
- `--security-opt=no-new-privileges` blocks setuid escalation
- `--pids-limit=100` contains fork bombs
- `--memory=512m` prevents memory exhaustion
- The attacker is confined to unprivileged operations within a resource-constrained sandbox

**5. What additional hardening would you add?**

1. **`--read-only`** — mount the root filesystem as read-only to prevent persistent malware and file tampering; use tmpfs for writable directories
2. **`--user 1000:1000`** — run as a non-root user to add another layer of defense against container escape
3. **`--network=custom_bridge`** — use a custom network with inter-container traffic control instead of the default bridge
4. **AppArmor/seccomp profiles** — apply custom profiles to restrict system calls beyond capability dropping
5. **`--tmpfs /tmp:rw,noexec,nosuid`** — prevent execution of uploaded files in temporary directories
6. **Image signing and verification** — enable Docker Content Trust to ensure only verified images are deployed
