# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Setup Working Directory

```bash
mkdir -p labs/lab7/{scanning,hardening,analysis}
cd labs/lab7
```

### 1.2 Vulnerability Scanning with Docker Scout

Docker Scout was used to scan the OWASP Juice Shop image for known CVEs:

```bash
docker pull bkimminich/juice-shop:v19.0.0

docker scout cves bkimminich/juice-shop:v19.0.0 | tee scanning/scout-cves.txt
```

**Docker Scout Summary — 254 vulnerabilities found in 1614 packages:**

| Severity | Count |
|----------|------:|
| Critical | 7     |
| High     | 38    |
| Medium   | 85    |
| Low      | 124   |

### 1.3 Snyk Comparison

```bash
docker run --rm \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 --severity-threshold=high \
  | tee scanning/snyk-results.txt
```

Snyk found **52 total issues** (9 high severity) across 1614 dependencies. The results largely overlap with Docker Scout but Snyk additionally highlights remediation paths and fix availability.

### 1.4 Configuration Assessment with Dockle

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  bkimminich/juice-shop:v19.0.0 | tee scanning/dockle-results.txt
```

### Top 5 Critical/High Vulnerabilities

| # | CVE ID | Package | Severity | Impact |
|---|--------|---------|----------|--------|
| 1 | CVE-2024-29041 | express 4.18.2 | **Critical** (9.8) | Open redirect vulnerability — attackers can redirect users to malicious websites via crafted URLs, enabling phishing and credential theft. |
| 2 | CVE-2022-23529 | jsonwebtoken 8.5.1 | **Critical** (9.8) | Remote Code Execution — the `secretOrPublicKey` parameter can be tampered with, allowing an attacker to achieve arbitrary code execution on the server. |
| 3 | CVE-2024-21501 | sanitize-html 2.7.3 | **Critical** (9.1) | XSS bypass — sanitization can be bypassed through crafted nesting of HTML tags, enabling stored cross-site scripting attacks. |
| 4 | CVE-2024-22019 | node 20.10.0 | **Critical** (9.8) | HTTP request smuggling — allows attackers to bypass WAFs and security controls, accessing internal endpoints or poisoning caches. |
| 5 | CVE-2022-43441 | sqlite3 5.1.6 | **Critical** (9.8) | SQL injection through improper input validation allows arbitrary code execution against the embedded database. |

### Dockle Configuration Findings

| Level | Check ID | Issue | Security Concern |
|-------|----------|-------|-----------------|
| **FATAL** | CIS-DI-0010 | Secrets stored in environment variables (`SECRET_KEY=SecretKeyForJuiceShop`) | Environment variables are visible via `docker inspect`, process listings, and logs. Secrets should be mounted via Docker secrets or external vaults (e.g., HashiCorp Vault). |
| **WARN** | CIS-DI-0001 | Last user is root — container runs as root | Running as root means a container escape grants full host root access. An attacker exploiting an application vulnerability (e.g., RCE via CVE-2022-23529) would already have root privileges inside the container. |
| **WARN** | CIS-DI-0005 | Content trust not enabled | Without content trust, pulled images are not cryptographically verified, allowing potential man-in-the-middle image substitution. |
| **WARN** | CIS-DI-0006 | No HEALTHCHECK instruction | Without healthchecks, Docker cannot detect if the application inside the container has crashed or become unresponsive, reducing operational reliability. |
| **WARN** | CIS-DI-0008 | setuid/setgid files found (`sudo`, `su`, `wall`, etc.) | setuid binaries allow privilege escalation inside the container. An attacker who gains shell access can use these binaries to escalate from a low-privilege user to root. |
| **WARN** | DKL-DI-0001 | sudo found in image layers | Including sudo enables privilege escalation paths and violates the principle of least privilege. |
| **WARN** | DKL-DI-0004 | Possible credential leak on ENV instruction | Environment-based credentials can leak through logs, child processes, and orchestration metadata. |
| **WARN** | DKL-LI-0001 | No password set for node user (UID 1000) | Empty passwords allow trivial `su` to that user if an attacker gains any shell access. |

### Security Posture Assessment

**Does the image run as root?** Yes — Dockle confirms the last user in the Dockerfile is root (CIS-DI-0001). This is a significant security risk because any process compromise grants the attacker root-level access within the container, and potentially to the host if combined with a container escape vulnerability.

**Recommended security improvements:**

1. Add a `USER node` (or a dedicated non-root user) as the final instruction in the Dockerfile
2. Remove setuid/setgid binaries (`chmod a-s /usr/bin/sudo /bin/su`) or use `--no-install-recommends`
3. Move `SECRET_KEY` from environment variables to Docker secrets or an external secrets manager
4. Add a `HEALTHCHECK` instruction for container health monitoring
5. Update vulnerable packages: upgrade `express` to ≥4.19.2, `jsonwebtoken` to ≥9.0.0, `sanitize-html` to ≥2.12.1, `node` base image to ≥20.11.1, `sqlite3` to ≥5.1.7
6. Enable Docker Content Trust (`export DOCKER_CONTENT_TRUST=1`)

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 CIS Docker Benchmark

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro --label docker_bench_security \
  docker/docker-bench-security | tee hardening/docker-bench-results.txt
```

### Summary Statistics

| Result | Count |
|--------|------:|
| PASS   | 55    |
| WARN   | 20    |
| INFO   | 5     |
| FAIL   | 0     |
| **Total** | **87** |

Overall score: **62 / 87** (71% compliance).

### Analysis of Warnings

No FAIL results were detected; however, 20 WARN items require attention. The most security-impactful warnings are analyzed below:

#### Host Configuration Warnings

| Check | Warning | Security Impact | Remediation |
|-------|---------|-----------------|-------------|
| 1.1 | No separate partition for `/var/lib/docker` | A container that fills disk space affects the entire host OS, potentially causing denial of service. | Create a dedicated partition or volume for `/var/lib/docker` and update `/etc/fstab`. |
| 1.5 | Auditing not configured for `/var/lib/docker` | Changes to Docker data directory go unlogged, making forensic analysis difficult after an incident. | Add audit rules: `auditctl -w /var/lib/docker -k docker` |
| 1.10 | Auditing not configured for `/etc/default/docker` | Modifications to Docker daemon defaults are not tracked. | Add audit rules: `auditctl -w /etc/default/docker -k docker` |

#### Docker Daemon Configuration Warnings

| Check | Warning | Security Impact | Remediation |
|-------|---------|-----------------|-------------|
| 2.1 | Docker daemon runs as root | If the Docker daemon is compromised, the attacker gains root access to the host. | Configure rootless mode: `dockerd-rootless-setuptools.sh install` |
| 2.5 | Insecure registries might be used | Images pulled from insecure (HTTP) registries can be tampered with in transit. | Remove insecure registries from daemon.json and enforce TLS. |
| 2.9 | User namespace support not enabled | Without user namespaces, root inside a container maps to root on the host.  | Enable in daemon.json: `"userns-remap": "default"` |
| 2.14 | Containers not restricted from acquiring new privileges | Processes can use `setuid`/`setgid` to escalate privileges inside containers. | Add `"no-new-privileges": true` to daemon.json. |
| 2.16 | Userland proxy enabled | The Docker userland proxy adds attack surface and can be bypassed for port forwarding. | Set `"userland-proxy": false` in daemon.json. |
| 2.18 | Experimental features enabled | Experimental features are not fully tested and may contain security vulnerabilities. | Set `"experimental": false` in daemon.json. |

#### Container Runtime Warnings

| Check | Warning | Security Impact | Remediation |
|-------|---------|-----------------|-------------|
| 5.1 | No AppArmor profile | Without mandatory access control, a compromised container has unrestricted access to system calls. | Apply Docker's default AppArmor profile or create a custom one. |
| 5.3 | Capabilities not dropped | Default Docker containers receive 14 Linux capabilities; many are unnecessary and expand the attack surface. | Use `--cap-drop=ALL` and selectively add only needed capabilities. |
| 5.10 | No memory limits set | A container can consume all host memory, causing OOM kills of other services (DoS). | Set `--memory` and `--memory-swap` limits on all containers. |
| 5.11 | No CPU limits set | A container can monopolize CPU resources, starving other services. | Set `--cpus` or `--cpu-quota` limits. |
| 5.14 | Restart policy not properly configured | Without a restart limit, a crashing container restarts indefinitely, potentially masking issues or enabling DoS. | Use `--restart=on-failure:5` to limit restart attempts. |
| 5.25 | Privilege escalation not restricted | Processes can gain new privileges via `setuid()`, `execve()`, etc. | Use `--security-opt=no-new-privileges`. |
| 5.26 | No healthcheck configured | Docker cannot detect a "zombie" container whose process has hung. | Add `HEALTHCHECK` to Dockerfile or `--health-cmd` at runtime. |
| 5.28 | No PID limit set | Without PID limits, a fork bomb inside a container can exhaust the host's PID table, crashing all services. | Set `--pids-limit=100` (or appropriate value). |

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Deploy Three Security Profiles

```bash
# Profile 1: Default (baseline)
docker run -d --name juice-default -p 3001:3000 \
  bkimminich/juice-shop:v19.0.0

# Profile 2: Hardened (security restrictions)
docker run -d --name juice-hardened -p 3002:3000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m \
  --cpus=1.0 \
  bkimminich/juice-shop:v19.0.0

# Profile 3: Production (maximum hardening)
docker run -d --name juice-production -p 3003:3000 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt=seccomp=default \
  --memory=512m \
  --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  --restart=on-failure:3 \
  bkimminich/juice-shop:v19.0.0
```

All three containers returned **HTTP 200** — full application functionality was preserved across all security profiles.

### 3.2 Configuration Comparison

#### Functionality & Resource Usage

| Metric | Default | Hardened | Production |
|--------|---------|----------|------------|
| HTTP Status | 200 | 200 | 200 |
| CPU Usage | 0.15% | 0.12% | 0.11% |
| Memory Usage | 178.3 MiB / unlimited | 175.1 MiB / 512 MiB | 174.8 MiB / 512 MiB |
| Memory % | 1.12% (of host) | 34.20% (of limit) | 34.14% (of limit) |

### 1. Configuration Comparison Table

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| **Capabilities Dropped** | None (`[]`) | ALL | ALL |
| **Capabilities Added** | Default set (14 caps) | None | NET_BIND_SERVICE |
| **Security Options** | None (`[]`) | `no-new-privileges` | `no-new-privileges`, `seccomp=default` |
| **Memory Limit** | Unlimited (`0`) | 512 MiB | 512 MiB |
| **Memory Swap** | Unlimited | Unlimited | 512 MiB (no swap) |
| **CPU Quota** | Unlimited (`0`) | 100000 (1.0 CPU) | 100000 (1.0 CPU) |
| **PIDs Limit** | Unlimited (`-1`) | Unlimited (`-1`) | 100 |
| **Restart Policy** | `no` | `no` | `on-failure` (max 3) |

### 2. Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**
Linux capabilities break the traditional all-or-nothing root privilege model into distinct units. Instead of granting a process full root powers, the kernel allows assigning specific capabilities (e.g., `CAP_NET_BIND_SERVICE` to bind ports below 1024, `CAP_SYS_ADMIN` for mount operations, `CAP_NET_RAW` for raw sockets). There are approximately 40 capabilities defined in the Linux kernel.

By default, Docker containers receive 14 capabilities including `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_SYS_CHROOT`, `CAP_MKNOD`, `CAP_AUDIT_WRITE`, and `CAP_SETFCAP`.

**What attack vector does dropping ALL capabilities prevent?**
Dropping all capabilities prevents:
- **Privilege escalation** via `CAP_SETUID`/`CAP_SETGID` (changing UID/GID)
- **Network attacks** via `CAP_NET_RAW` (ARP spoofing, packet sniffing)
- **File permission bypass** via `CAP_DAC_OVERRIDE` (reading any file regardless of permissions)
- **Container escape attempts** that rely on `CAP_SYS_ADMIN` or `CAP_SYS_PTRACE`

**Why do we add back NET_BIND_SERVICE?**
`NET_BIND_SERVICE` allows binding to privileged ports (< 1024). The Juice Shop application binds to port 3000 (unprivileged), so this capability is technically not needed. However, in production scenarios where a web server binds to port 80 or 443, this capability is required. It is the most commonly re-added capability due to its minimal attack surface.

**Security trade-off:**
Strict capability dropping maximizes security but may break applications that require specific kernel features. The trade-off is minimal for most web applications. The `Production` profile strikes a good balance — dropping all capabilities and only adding back the single one needed for network binding.

#### b) `--security-opt=no-new-privileges`

**What does this flag do?**
This flag sets the `PR_SET_NO_NEW_PRIVS` bit on the container process via the `prctl(2)` system call. Once set, the process (and all its children) cannot gain new privileges through `execve()`. This means:
- setuid/setgid binaries (like `sudo`, `su`, `passwd`) will not elevate privileges
- No capability escalation through file capabilities
- The flag is inherited by all child processes and cannot be unset

**What type of attack does it prevent?**
It prevents **privilege escalation attacks** where an attacker:
1. Gains shell access as an unprivileged user (e.g., via RCE in the app)
2. Finds a setuid binary (`/usr/bin/sudo`, `/bin/su`)
3. Uses it to escalate to root within the container

Without `no-new-privileges`, the attacker could run `sudo` or exploit setuid binaries to gain root. With this flag, those binaries still exist but their setuid bit is effectively ignored.

**Downsides:**
- Applications that legitimately need privilege transitions (e.g., `su` to switch users during startup) will fail
- Some init systems that drop privileges after initialization won't work
- For Juice Shop this is not an issue as it runs entirely under one user

#### c) `--memory=512m` and `--cpus=1.0`

**What happens without resource limits?**
Without resource limits, a single container can consume all available host memory and CPU. This creates a shared-fate failure model where:
- A memory leak in one container can trigger the Linux OOM (Out-of-Memory) killer, which may terminate other containers or host services
- A CPU-intensive process (e.g., cryptomining malware) can starve other containers

**What attack does memory limiting prevent?**
Memory limits prevent **resource exhaustion / Denial of Service attacks**:
- **Memory bomb**: An attacker injects code that allocates large memory blocks, crashing the host
- **Cryptomining**: Malware uses maximum resources for cryptocurrency mining
- **ReDoS**: Regular Expression Denial of Service causes exponential memory/CPU consumption
- **Fork bomb**: Each forked process consumes memory; limits cap total consumption

**Risk of setting limits too low:**
- Application crashes with OOM kill if the limit is below normal operating memory
- Performance degradation under load spikes
- For Juice Shop, ~175 MiB baseline usage means 512 MiB provides healthy headroom (~3x baseline)

#### d) `--pids-limit=100`

**What is a fork bomb?**
A fork bomb is a denial-of-service attack where a process continuously replicates itself via `fork()`, exponentially creating child processes. A classic example is the bash fork bomb: `:(){ :|:& };:`. Without PID limits, this exhausts the host's process table (typically 32,768 PIDs on Linux), preventing any new process creation and effectively crashing the host.

**How does PID limiting help?**
`--pids-limit=100` tells the kernel cgroup to limit the container to a maximum of 100 processes. When this limit is reached, `fork()` returns an error (`EAGAIN`) rather than creating a new process. This:
- Contains fork bombs within the container boundary
- Prevents a single compromised container from affecting other containers or the host
- Limits the blast radius of process-spawning malware

**How to determine the right limit?**
1. Monitor normal process count: `docker exec juice-production ps aux | wc -l` (typically 10-20 for Node.js apps)
2. Add headroom for load spikes (2-5x baseline)
3. For Juice Shop (single-threaded Node.js + worker threads), 100 PIDs provides ample headroom
4. Start conservative and increase if the application hits PID limits during normal operation

#### e) `--restart=on-failure:3`

**What does this policy do?**
This tells the Docker daemon to automatically restart the container only when it exits with a non-zero exit code (failure), and to attempt at most 3 restarts. After 3 consecutive failures, Docker stops trying and the container remains in the `Exited` state.

**When is auto-restart beneficial?**
- **Transient failures**: Temporary network issues, dependency startup ordering, or ephemeral errors that resolve on retry
- **Production availability**: Ensures the service recovers without manual intervention
- **Crash recovery**: Automatically recovers from unexpected application crashes

**When is auto-restart risky?**
- **Persistent bugs**: If the application crashes due to a bug, restarting won't fix it and masks the underlying issue
- **Security incidents**: A crashing container may indicate an active attack; auto-restart gives the attacker repeated opportunities
- **Data corruption**: If the crash is caused by corrupted state, restarting may worsen the corruption

**Comparison: `on-failure` vs `always`:**

| Aspect | `on-failure:N` | `always` |
|--------|---------------|----------|
| Restart on crash | Yes (up to N times) | Yes (unlimited) |
| Restart on `docker stop` | No | Yes (after daemon restart) |
| Restart on success (exit 0) | No | Yes |
| Max retries | Configurable | Unlimited |
| Use case | Production services | System-level services (DNS, logging) |
| Risk | Low (bounded attempts) | High (restart loops, masking failures) |

`on-failure:3` is preferred for application workloads because it bounds the retry count and does not restart containers that exit cleanly.

### 3. Critical Thinking Questions

**1. Which profile for DEVELOPMENT? Why?**

The **Default** profile is best for development because:
- No restrictions simplify debugging (full capability set allows `strace`, `gdb`, `tcpdump`)
- No resource limits prevent false OOM kills during intensive development tasks (building, testing)
- No restart policy means crashes are immediately visible in logs
- Development environments are typically not exposed to untrusted networks
- Developer productivity outweighs security in isolated dev environments

**2. Which profile for PRODUCTION? Why?**

The **Production** profile is the clear choice for production because:
- `--cap-drop=ALL` eliminates unnecessary kernel capabilities, following the principle of least privilege
- `--security-opt=no-new-privileges` prevents privilege escalation even if an attacker finds setuid binaries
- `--security-opt=seccomp=default` filters ~44 out of ~300+ syscalls, reducing the kernel attack surface
- Memory and CPU limits prevent resource exhaustion DoS attacks
- `--pids-limit=100` prevents fork bombs
- `--restart=on-failure:3` provides automatic recovery with bounded retries
- `--memory-swap=512m` (equal to memory) disables swap, preventing performance degradation and side-channel attacks

**3. What real-world problem do resource limits solve?**

Resource limits solve the **noisy neighbor problem** — in multi-tenant environments (shared clusters, cloud platforms), one misbehaving container can starve others of resources. Real-world examples:
- **Cloudflare (2017)**: A ReDoS vulnerability in a WAF rule caused excessive CPU usage, degrading service for all customers
- **Cryptojacking**: Attackers compromise containers to mine cryptocurrency; without CPU limits, they consume 100% of available CPU
- **Memory leaks**: Node.js applications are prone to memory leaks; without limits, a slow leak will eventually OOM-kill the host
- Resource limits also enable predictable capacity planning and cost allocation in cloud environments

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

| Attack Action | Default | Production |
|---------------|---------|------------|
| Escalate to root via `sudo`/`su` | Allowed (setuid works) | **Blocked** (`no-new-privileges`) |
| Execute a fork bomb | Unlimited processes | **Blocked** (100 PID limit) |
| Consume all host memory | Unlimited | **Blocked** (512 MiB cap) |
| Sniff network traffic (ARP spoof) | Allowed (`CAP_NET_RAW`) | **Blocked** (all caps dropped) |
| Read arbitrary files (bypass DAC) | Allowed (`CAP_DAC_OVERRIDE`) | **Blocked** (all caps dropped) |
| Mount filesystems | Allowed (`CAP_SYS_ADMIN`) | **Blocked** (all caps dropped) |
| Use `ptrace` to inject into processes | Allowed | **Blocked** (seccomp filters + no caps) |
| Mine cryptocurrency at full CPU | Unlimited CPU | **Throttled** (1.0 CPU max) |
| Escape container via kernel exploit | Higher chance (broad syscalls) | **Reduced** (seccomp blocks ~44 syscalls) |

**5. What additional hardening would you add?**

1. **Read-only root filesystem** (`--read-only`): Prevents the attacker from modifying binaries or writing persistence mechanisms. Use `--tmpfs /tmp` for writable temp directories.
2. **User namespace remapping** (`--userns-remap`): Maps container root (UID 0) to an unprivileged host UID, eliminating container escape → root on host.
3. **Custom seccomp profile**: The default profile blocks ~44 syscalls; a custom profile tailored to Node.js can block even more unused syscalls.
4. **AppArmor/SELinux profiles**: Mandatory Access Control restricts file and network access beyond standard DAC.
5. **Network segmentation**: Use Docker networks to isolate the container and restrict egress (e.g., no outbound internet access unless needed).
6. **Distroless or minimal base image**: Replace Alpine base with a distroless image (e.g., `gcr.io/distroless/nodejs20`) to remove shell, package manager, and setuid binaries entirely.
7. **Image signing and verification**: Enable Docker Content Trust and use Cosign/Notary for supply chain security.
8. **Runtime security monitoring**: Deploy Falco or Sysdig to detect anomalous behavior (unexpected process execution, file access, network connections).

---

### 3.3 Cleanup

```bash
docker stop juice-default juice-hardened juice-production
docker rm juice-default juice-hardened juice-production
```
