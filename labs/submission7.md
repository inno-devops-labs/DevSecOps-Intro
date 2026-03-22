# Lab 7 — Container Security: Image Scanning & Deployment Hardening

**Branch:** `feature/lab7`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Setup

```bash
mkdir -p labs/lab7/{scanning,hardening,analysis}
docker pull bkimminich/juice-shop:v19.0.0
```

### 1.2 Docker Scout CVE Scan

```bash
docker scout cves bkimminich/juice-shop:v19.0.0 | tee scanning/scout-cves.txt
```

**Overview results:**

```
Target: bkimminich/juice-shop:v19.0.0
Vulnerabilities: 11C  65H  0M  0L
Packages scanned: 1004
```

Docker Scout found **76 total vulnerabilities** in 33 packages — 11 Critical and 65 High.

### 1.3 Snyk Comparison (Trivy)

Since Snyk requires an account token and timed out during authentication, Trivy was used as the comparison tool (it is a widely-used alternative):

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity HIGH,CRITICAL \
  bkimminich/juice-shop:v19.0.0 | tee scanning/snyk-results.txt
```

**Trivy results summary:**

| Layer | HIGH | CRITICAL |
|-------|------|----------|
| OS packages | 4 | 1 |
| npm packages | 87 | 9 |
| Secrets detected | 1 | 0 |
| **Total** | **92** | **10** |

Trivy found 102 total findings — slightly more than Docker Scout (76) because Trivy also scanned OS-level packages and detected an embedded private key in the source code.

### 1.4 Dockle Configuration Assessment

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0 | tee scanning/dockle-results.txt
```

**Dockle output:**

```
SKIP  DKL-LI-0001: Avoid empty password
      * failed to detect etc/shadow,etc/master.passwd
INFO  CIS-DI-0005: Enable Content trust for Docker
      * export DOCKER_CONTENT_TRUST=1 before docker pull/build
INFO  CIS-DI-0006: Add HEALTHCHECK instruction to the container image
      * not found HEALTHCHECK statement
INFO  DKL-LI-0003: Only put necessary files
      * unnecessary file: juice-shop/node_modules/micromatch/lib/.DS_Store
      * unnecessary file: juice-shop/node_modules/extglob/lib/.DS_Store
```

No FATAL or WARN findings — only INFO level. This means the image follows basic Dockerfile best practices.

---

### Top 5 Critical/High Vulnerabilities

**1. CVE-2026-22709 — vm2 3.9.17 (CRITICAL, CVSS 9.8)**

- **Package:** vm2 (JavaScript sandbox library)
- **Type:** Protection Mechanism Failure
- **Impact:** Remote code execution — an attacker can break out of the vm2 sandbox and run arbitrary code on the host system. This is extremely dangerous in any app that executes user-supplied scripts.
- **Fix:** Upgrade to vm2 3.10.2 or replace with a safer alternative

**2. CVE-2023-37903 — vm2 3.9.17 (CRITICAL, CVSS 9.8)**

- **Package:** vm2
- **Type:** OS Command Injection
- **Impact:** No fix available for this version. An attacker can inject OS commands through the sandbox escape. Since there is no fix, the library itself must be replaced.
- **Fix:** Replace vm2 entirely — the project was abandoned

**3. CVE-2019-10744 — lodash 2.4.2 (CRITICAL, CVSS 9.1)**

- **Package:** lodash (utility library)
- **Type:** Prototype Pollution
- **Impact:** An attacker can modify the prototype of base JavaScript objects, which can lead to unexpected behavior, privilege escalation, or denial of service.
- **Fix:** Upgrade to lodash 4.17.12 or later

**4. CVE-2025-55130 — Node.js 22.18.0 (CRITICAL)**

- **Package:** Node.js runtime
- **Type:** Unspecified vulnerability in Node.js core
- **Impact:** Affects all applications running on this Node.js version.
- **Fix:** Upgrade to Node.js 22.22.0

**5. CVE-2023-37466 — vm2 3.9.17 (CRITICAL, CVSS 9.8)**

- **Package:** vm2
- **Type:** Code Injection
- **Impact:** Allows complete sandbox escape and remote code execution. Same vm2 package — three separate CVEs because the library has multiple independent vulnerabilities.
- **Fix:** Upgrade to vm2 3.10.0+ or replace library

---

### Dockle Configuration Findings

No FATAL or WARN issues were found. The image only had INFO-level findings:

| Finding | ID | Why It Matters |
|---------|-----|----------------|
| Content trust not enabled | CIS-DI-0005 | Without `DOCKER_CONTENT_TRUST=1`, Docker will pull and run images even if they haven't been cryptographically signed. This allows pulling tampered images. |
| No HEALTHCHECK in Dockerfile | CIS-DI-0006 | Without a HEALTHCHECK, Docker can't tell if the app is actually working — only that the process is running. Orchestrators like Kubernetes also use health checks to restart broken containers. |
| .DS_Store files included | DKL-LI-0003 | macOS metadata files were accidentally included in the image. They bloat the image and can leak directory structure info. |

---

### Security Posture Assessment

**Does the image run as root?**

Yes. The docker-bench scan found `juice-shop` containers running as root. Dockle did not explicitly warn about this because the image uses a non-root UID (65532) internally, but the container process is still effectively unrestricted at the Docker level when deployed without `--user` flags.

**Security improvements recommended:**

1. Replace vm2 entirely — it has unfixable CVEs and the project is abandoned
2. Upgrade lodash from 2.4.2 to 4.17.21
3. Upgrade Node.js to 22.22.0
4. Add `HEALTHCHECK` to the Dockerfile
5. Add `USER nonroot` at the end of the Dockerfile to prevent root execution
6. Remove `.DS_Store` and other development artifacts from the final image
7. Enable Docker Content Trust in the CI/CD pipeline

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

| Status | Count |
|--------|-------|
| PASS | 45 |
| WARN | 211 |
| FAIL | 0 |
| INFO | 143 |
| NOTE | 10 |
| **Total** | **409** |

No outright FAIL findings, but 211 WARN findings show significant room for improvement.

### Analysis of Key Warnings

**1.1 — No separate partition for containers**
- **Issue:** Docker stores container data in `/var/lib/docker`, which shares disk with the OS. If containers fill up the disk, the whole host can crash.
- **Fix:** Mount `/var/lib/docker` on a dedicated disk partition

**1.5 – 1.11 — Auditing not configured for Docker files**
- **Issue:** Changes to Docker daemon config, socket files, and directories are not being logged by the system audit daemon (`auditd`). If someone modifies Docker configuration maliciously, there's no trace.
- **Fix:** Add audit rules for `/etc/docker`, `/var/lib/docker`, the Docker socket, and Docker service files

**2.1 — Network traffic not restricted between containers**
- **Issue:** By default, all containers on the same Docker bridge network can talk to each other. This violates least-privilege networking — a compromised container can probe other containers.
- **Fix:** Add `"icc": false` to `/etc/docker/daemon.json`

**2.8 — User namespace support not enabled**
- **Issue:** Without user namespaces, the root user inside a container maps to the real root on the host. If a container breakout happens, the attacker has full host root access.
- **Fix:** Enable user namespace remapping in daemon.json: `"userns-remap": "default"`

**2.11 — No authorization plugin for Docker client commands**
- **Issue:** Anyone who can reach the Docker socket has full control over all containers. There's no audit log of who ran what command.
- **Fix:** Install an authorization plugin (like `authz-broker`) to log and control Docker API access

**2.14 — Live restore not enabled**
- **Issue:** Without live restore, all running containers stop when the Docker daemon restarts (e.g., during a daemon upgrade or crash). This causes downtime.
- **Fix:** Add `"live-restore": true` to daemon.json

**2.15 — Userland proxy not disabled**
- **Issue:** Docker uses a userland proxy process for port forwarding by default. This creates extra processes and is less efficient than using kernel-level iptables.
- **Fix:** Add `"userland-proxy": false` to daemon.json

**2.18 — Containers not restricted from new privileges**
- **Issue:** By default, processes inside containers can gain new privileges through setuid binaries. This could allow privilege escalation inside the container.
- **Fix:** Add `"no-new-privileges": true` to daemon.json to apply this globally

**4.1 — Multiple containers running as root**
- **Issue:** Several containers (including juice-shop and others) are running as the root user. If an attacker exploits a vulnerability inside the container, they immediately have root — and with user namespace not enabled, that's host root too.
- **Fix:** Add `USER nonroot` to Dockerfiles, or use `--user` flag at runtime

**4.5 — Docker Content Trust disabled**
- **Issue:** Without content trust, Docker pulls images without verifying their cryptographic signature. A man-in-the-middle attack or registry compromise could serve malicious images.
- **Fix:** Set `DOCKER_CONTENT_TRUST=1` in the environment

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Deploy Three Security Profiles

```bash
# Profile 1: Default
docker run -d --name juice-default -p 3001:3000 bkimminich/juice-shop:v19.0.0

# Profile 2: Hardened
docker run -d --name juice-hardened -p 3002:3000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m \
  --cpus=1.0 \
  bkimminich/juice-shop:v19.0.0

# Profile 3: Production
docker run -d --name juice-production -p 3003:3000 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt=seccomp=builtin \
  --memory=512m \
  --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  --restart=on-failure:3 \
  bkimminich/juice-shop:v19.0.0
```

### 3.2 Results from deployment-comparison.txt

**Functionality Test:**
```
Default:    HTTP 200
Hardened:   HTTP 200
Production: HTTP 200
```

All three profiles work correctly — security hardening does not break the application.

**Resource Usage:**
```
NAME              CPU %    MEM USAGE / LIMIT     MEM %
juice-default     0.71%    154.9MiB / 14.96GiB   1.01%
juice-hardened    0.68%    92.46MiB / 512MiB     18.06%
juice-production  0.67%    92.02MiB / 512MiB     17.97%
```

**Security Configurations from `docker inspect`:**
```
Container: juice-default
CapDrop: <no value>
SecurityOpt: <no value>
Memory: 0
CPU: 0
PIDs: <no value>
Restart: no

Container: juice-hardened
CapDrop: [ALL]
SecurityOpt: [no-new-privileges]
Memory: 536870912
CPU: 0
PIDs: <no value>
Restart: no

Container: juice-production
CapDrop: [ALL]
SecurityOpt: [no-new-privileges seccomp=builtin]
Memory: 536870912
CPU: 0
PIDs: 100
Restart: on-failure
```

---

### 1. Configuration Comparison Table

| Security Feature | Default | Hardened | Production |
|-----------------|---------|----------|------------|
| **Capabilities dropped** | None | ALL | ALL |
| **Capabilities added back** | All (default) | None | NET_BIND_SERVICE |
| **no-new-privileges** | No | Yes | Yes |
| **seccomp profile** | Default | Default | Builtin (strict) |
| **Memory limit** | None (14.96 GiB host) | 512 MB | 512 MB |
| **Memory swap limit** | Unlimited | Unlimited | 512 MB (no swap) |
| **CPU limit** | None | 1 CPU | 1 CPU |
| **PID limit** | None | None | 100 |
| **Restart policy** | No | No | on-failure:3 |

---

### 2. Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**
Linux capabilities are pieces of root privilege that can be granted or removed individually. Instead of "either root or not root", the kernel splits root power into ~40 separate capabilities: things like `CAP_NET_BIND_SERVICE` (bind to ports below 1024), `CAP_SYS_PTRACE` (debug other processes), `CAP_CHOWN` (change file ownership), etc.

**What attack vector does dropping ALL capabilities prevent?**
By default a container inherits many capabilities that most apps don't need. If an attacker exploits a vulnerability in the app, they can use those capabilities to escalate privileges — for example using `CAP_SYS_PTRACE` to read memory from other processes, or `CAP_NET_RAW` to sniff network traffic. Dropping ALL removes every one of these vectors.

**Why do we need to add back NET_BIND_SERVICE?**
Because the Node.js app needs to listen on port 3000. Normally ports below 1024 require this capability — but actually port 3000 is above 1024, so for juice-shop this capability isn't strictly needed. In a web server binding to port 80 (below 1024), it would be required.

**Security trade-off:**
Dropping all capabilities can break applications that legitimately need them. You have to test carefully to know which ones to add back. It also doesn't help if the app runs as root and has a container escape vulnerability.

#### b) `--security-opt=no-new-privileges`

**What does this flag do?**
It prevents processes inside the container from gaining new privileges through setuid or setgid binaries. Even if someone runs `sudo` or a setuid program inside the container, the process cannot escalate its privileges.

**What type of attack does it prevent?**
Privilege escalation attacks. For example, if an attacker finds a setuid binary in the container (like `ping` or an old `sudo`), without this flag they could use it to become root. With this flag, that escalation path is blocked.

**Downsides:**
Some legitimate programs use setuid internally (for example, `passwd` on Linux uses setuid to write to `/etc/shadow`). If your container needs such programs to work, this flag can break them.

#### c) `--memory=512m` and `--cpus=1.0`

**What happens without resource limits?**
A single container can use all available memory and CPU on the host. If the app has a memory leak or gets overloaded, it can starve other containers and system processes, potentially crashing the whole host.

**What attack does memory limiting prevent?**
Memory exhaustion attacks. An attacker who can trigger memory allocation in the app (e.g., by sending large requests or crafting special payloads) can cause the host to run out of memory. With a 512 MB limit, the container is killed before it affects the rest of the system.

**Risk of setting limits too low:**
If limits are too tight, the app will be killed by the OOM (out of memory) killer even under normal load. This causes unexpected restarts and service outages. You need to profile the app under realistic load before setting limits.

#### d) `--pids-limit=100`

**What is a fork bomb?**
A fork bomb is a program that keeps creating new processes (or threads) in a loop: `:(){ :|:& };:` in bash. Each process creates two more, which creates four, which creates eight... the machine runs out of process slots and freezes.

**How does PID limiting help?**
With `--pids-limit=100`, once the container reaches 100 processes, any attempt to create more fails. This stops a fork bomb from escaping the container and killing the host. The attacker's attack is contained.

**How to determine the right limit?**
Profile the application under normal and peak load. Check how many processes/threads it uses with `docker top <container>` or `ps aux`. Set the limit to 2-3x the normal peak. For juice-shop (a Node.js app), 100 is reasonable since Node is single-threaded.

#### e) `--restart=on-failure:3`

**What does this policy do?**
It tells Docker to automatically restart the container if it exits with a non-zero exit code (i.e., it crashed). The `:3` means it will try at most 3 times before giving up.

**When is auto-restart beneficial?**
When the app crashes due to a transient error (out of memory, network blip, startup race condition). It provides self-healing without operator intervention.

**When is it risky?**
If the app crashes because of a security exploit, restarting it immediately might give the attacker a second chance to exploit it. Also, if the crash happens during a misconfiguration, restarting in a loop (restart loop / crash loop) can hide the real problem.

**`on-failure` vs `always`:**
- `on-failure`: restarts only on crashes (non-zero exit). If you manually stop the container, it stays stopped.
- `always`: restarts no matter what — even if you manually stopped it. This can be annoying during maintenance and may auto-start containers you want to keep stopped after a host reboot.
- For production: `on-failure:3` is better because it handles crashes but respects intentional stops.

---

### 3. Critical Thinking Questions

**1. Which profile for DEVELOPMENT?**

The **Default** profile. During development you need flexibility — debuggers, profilers, and tools often need capabilities or elevated access to work. Strict security settings would constantly block legitimate developer actions and slow down work. Security hardening in dev also doesn't reflect the actual attack surface since the app is not internet-exposed.

**2. Which profile for PRODUCTION?**

The **Production** profile. It provides defense-in-depth:
- ALL capabilities dropped — minimal attack surface if the app is exploited
- no-new-privileges — blocks privilege escalation
- Memory limit — prevents resource exhaustion attacks
- PID limit — prevents fork bombs
- Restart policy — automatic recovery from crashes

All of this adds almost zero performance overhead (the app ran at 0.67% CPU vs 0.71% for Default) while dramatically reducing what an attacker can do.

**3. What real-world problem do resource limits solve?**

Resource limits solve the **noisy neighbor problem** in multi-tenant environments. When you run multiple services on one host (very common in microservices), one misbehaving service — whether due to a bug, memory leak, or attack — can steal resources and crash all other services. Limits create isolation: each container gets a fair share and can't monopolize the host. This is essential for SLA guarantees.

**4. If an attacker exploits Default vs Production, what can they do in Default that's blocked in Production?**

With Default, an attacker who exploits the juice-shop app can:
- Use capabilities like `CAP_NET_RAW` to sniff network traffic from other containers
- Use `CAP_SYS_PTRACE` to read memory from other processes on the host
- Run a fork bomb and freeze the entire host
- Allocate unlimited memory to crash other services
- Use setuid binaries to escalate to root
- Keep the process running indefinitely (no restart limit confusion)

With Production, all of the above is blocked:
- No capabilities → no sniffing, no ptrace, no chown
- `no-new-privileges` → no setuid escalation
- PID limit → fork bomb stops at 100 processes
- Memory limit → container is killed before it affects the host
- Restart policy → controlled recovery

**5. What additional hardening would you add?**

1. **`--read-only`** — Mount the container filesystem as read-only. The app shouldn't be modifying its own files. A read-only root filesystem prevents an attacker from writing malicious scripts or modifying the application.

2. **`--user 1000:1000`** — Run the container as a non-root user explicitly. Even with capabilities dropped, running as root means file ownership issues and potential bypasses.

3. **`--network=none` or a dedicated network** — Isolate the container from the default bridge. Use a custom Docker network where only the containers that need to talk to each other are connected. This prevents lateral movement.

4. **`--tmpfs /tmp`** — Mount `/tmp` as a temporary in-memory filesystem. This gives the app a writable temp directory without allowing writes to the real filesystem, and it's automatically cleaned up.

5. **AppArmor or SELinux profile** — Use `--security-opt apparmor=docker-default` or a custom profile to restrict what system calls the container's process can make at the kernel level, beyond what seccomp provides.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| Image vulnerabilities | 11 Critical, 65 High CVEs (Docker Scout) | Critical |
| vm2 library | 3 separate Critical CVEs, library abandoned | Critical |
| Node.js runtime | Outdated — needs upgrade to 22.22.0 | High |
| Docker host | 211 warnings — no auditing, user namespaces disabled | Medium |
| Default deployment | No limits, all capabilities, no isolation | High |
| Hardened deployment | Good start — caps dropped, no-new-privileges | Medium |
| Production deployment | Strong hardening — adds PID limit, seccomp, restart policy | Low |
