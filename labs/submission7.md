# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout CVE Analysis

The container image `bkimminich/juice-shop:v19.0.0` was scanned using Docker Scout.

**Summary:**
- Critical: 11
- High: 65
- Medium: 30
- Low: 5

This indicates a **highly vulnerable image**, primarily due to outdated dependencies.

#### Top 5 Critical/High Vulnerabilities

| CVE ID | Package | Severity | Potential Impact |
|--------|---------|---------|-----------------|
| CVE-2026-22709 | vm2 3.9.17 | Critical | Protection mechanism failure leading to full compromise |
| CVE-2023-37903 | vm2 3.9.17 | Critical | OS command injection allowing arbitrary command execution |
| CVE-2023-37466 | vm2 3.9.17 | Critical | Code injection leading to remote code execution |
| CVE-2019-10744 | lodash 2.4.2 | Critical | Prototype pollution enabling object manipulation |
| CVE-2023-46233 | crypto-js 3.3.0 | Critical | Use of weak cryptographic algorithms |

#### Observations

- The most critical vulnerabilities are concentrated in Node.js dependencies such as `vm2`, `lodash`, and `crypto-js`.
- Some vulnerabilities have no available fixes in the current versions, increasing risk.
- Many vulnerabilities allow **remote code execution (RCE)** and **injection attacks**, which are critical in production environments.

---

### 1.2 Snyk Scan Analysis

The image was also analyzed using Snyk to compare vulnerability detection results.

**Summary:**
- 6 vulnerabilities in base system dependencies
- 47 vulnerabilities in application dependencies

#### Key Critical/High Findings

| Package | Severity | Issue | Fixed Version |
|---------|---------|-------|---------------|
| vm2@3.9.17 | Critical | Remote Code Execution (RCE) | ≥ 3.10.0 |
| vm2@3.9.17 | Critical | Sandbox Bypass | ≥ 3.9.18 |
| multer@1.4.5-lts.2 | Critical | Uncaught Exception / DoS | ≥ 2.1.1 |
| marsdb@0.6.11 | Critical | Arbitrary Code Injection | Not fixed |
| node@22.18.0 | Critical | Race condition vulnerability | ≥ 22.22.0 |

#### Observations

- Snyk confirms the presence of critical vulnerabilities identified by Docker Scout, especially in `vm2`.
- Additional risks were identified in:
  - `node` runtime (system-level vulnerabilities)
  - `multer`, `jsonwebtoken`, `socket.io`, `qs`, `lodash`
- Some vulnerabilities have **no available patches**, requiring mitigation strategies.

#### Comparison with Docker Scout

- Both tools identified **vm2 as the most critical vulnerable dependency**.
- Docker Scout provides broader CVE coverage across all packages.
- Snyk provides deeper insights into:
  - dependency chains
  - upgrade paths
  - remediation recommendations

---

### 1.3 Dockle Configuration Assessment

Dockle was used to analyze image configuration and best practices.

#### Findings

| Check ID | Level | Finding | Security Impact |
|----------|-------|---------|----------------|
| DKL-LI-0001 | SKIP | Could not verify password configuration | Potential risk if weak credentials exist |
| CIS-DI-0005 | INFO | Docker Content Trust not enabled | Risk of using untrusted or tampered images |
| CIS-DI-0006 | INFO | No HEALTHCHECK instruction | Weak monitoring and failure detection |
| DKL-LI-0003 | INFO | Unnecessary files (.DS_Store) present | Poor build hygiene, potential information leakage |

#### Analysis

- No **FATAL** or **WARN** issues were detected.
- The image follows basic structure guidelines but lacks production-grade hardening.
- Issues are mainly related to:
  - supply chain security
  - observability
  - image cleanliness

---

### 1.4 Security Posture Assessment

The overall security posture of the image is **weak**.

- A large number of **critical and high vulnerabilities** exist in application dependencies.
- The most severe issues include:
  - Remote Code Execution (RCE)
  - Injection vulnerabilities
  - Cryptographic weaknesses
- While configuration issues are not severe (Dockle shows no FATAL findings), the **dependency risk is extremely high**.

#### Does the image run as root?

Based on the Dockerfile behavior, the image uses a non-root user (`UID 65532`), which is a positive security practice.

#### Recommended Improvements

1. **Update dependencies**
   - `vm2` → ≥ 3.10.2  
   - `lodash` → ≥ 4.17.x  
   - `jsonwebtoken` → ≥ 9.0.0  
   - `crypto-js` → ≥ 4.2.0  
   - `multer` → ≥ 2.1.1  

2. **Update base image**
   - Upgrade Node.js from `22.18.0` → `22.22.0`

3. **Handle unpatched vulnerabilities**
   - Replace or isolate risky libraries such as `marsdb`

4. **Improve container configuration**
   - Add `HEALTHCHECK`
   - Enable Docker Content Trust
   - Remove unnecessary files during build

5. **Apply runtime security controls**
   - Drop Linux capabilities
   - Enable `no-new-privileges`
   - Use seccomp profiles
   - Apply memory, CPU, and PID limits

---

Вот более короткий и аккуратный вариант — без лишней воды, но с сохранением смысла и «профессионального» уровня 👇

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 CIS Docker Benchmark Execution

I attempted to run the CIS Docker Benchmark using `docker/docker-bench-security`, but it could not be completed successfully in my environment.

### Environment

- Host OS: macOS (Docker Desktop)
- Architecture: ARM64 (Apple Silicon)

### Issue Encountered

The benchmark failed to start due to a filesystem mount error related to read-only restrictions:

```text
error mounting ".../hostname" to rootfs at "/etc/hostname": read-only file system
```

### Explanation

This issue is caused by a platform limitation rather than an incorrect setup.
Docker Desktop runs containers inside an internal Linux VM, which restricts direct access to host-level resources required by `docker-bench-security`.

As a result:

* host namespaces and filesystem paths are not fully accessible
* some CIS checks cannot be executed
* required bind mounts fail

---



## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Profile       | CapDrop     | CapAdd                | SecurityOpt          | Memory     | MemorySwap | CPUQuota | PIDs | Restart       |
|---------------|------------|----------------------|--------------------|-----------|-----------|----------|------|---------------|
| Default       | <no value> | <no value>           | <no value>         | 0         | 0         | 0        | <no value> | no            |
| Hardened      | ALL        | <no value>           | no-new-privileges  | 512MiB    | 1024MiB   | 0        | <no value> | no            |
| Production    | ALL        | CAP_NET_BIND_SERVICE | no-new-privileges  | 512MiB    | 512MiB    | 0        | 100  | on-failure    |

**Observations:**

- Default has no resource limits or security restrictions.
- Hardened drops all capabilities and enforces `no-new-privileges`, with memory limits.
- Production drops all capabilities, adds only the required NET_BIND_SERVICE, enforces `no-new-privileges`, has memory/CPU/PID limits, and a restart policy.

---

### 3.2 Functionality Test

| Profile       | HTTP Status |
|---------------|-------------|
| Default       | 200         |
| Hardened      | 200         |
| Production    | 200         |

All three profiles respond correctly, showing that security hardening does not break basic application functionality.

---

### 3.3 Resource Usage

| Profile       | Memory Usage / Limit | MEM %  | CPU % |
|---------------|-------------------|-------|-------|
| Default       | 101MiB / 7.654GiB  | 1.29% | 0.53% |
| Hardened      | 95.04MiB / 512MiB  | 18.56%| 0.50% |
| Production    | 94.25MiB / 512MiB  | 18.41%| 0.50% |

- Hardened and Production show memory usage close to the limit, indicating proper enforcement.
- Default has no limits, memory usage is minimal now but could grow unbounded.

---

### 3.4 Security Measure Analysis

#### a. `--cap-drop=ALL` / `--cap-add=NET_BIND_SERVICE`
- Linux capabilities split root privileges into finer-grained actions.
- Dropping all capabilities prevents privilege escalation attacks and reduces risk if the container is compromised.
- NET_BIND_SERVICE is added back to allow binding to low ports (like 3000). This is a least-privilege approach.
- Trade-off: dropping capabilities may break software that needs certain privileges; adding back only the required one balances security and functionality.

#### b. `--security-opt=no-new-privileges`
- Prevents processes from gaining new privileges via setuid/setgid.
- Mitigates privilege escalation attacks.
- Downside: some legitimate tools needing privilege escalation may fail; generally safe for web app containers.

#### c. `--memory=512m` and `--cpus=1.0`
- Limits prevent a container from consuming all host resources.
- Protects against DoS attacks, runaway processes, or memory leaks.
- Risk: too low limits may slow down or crash the application under normal load.

#### d. `--pids-limit=100`
- Caps the number of processes inside a container.
- Protects the host from fork bombs or excessive process creation.
- The value is chosen based on expected workload; 100 is safe for typical web apps.

#### e. `--restart=on-failure:3`
- Automatically restarts the container on failure up to 3 times.
- Useful for transient failures; avoids infinite restart loops that `always` might cause.
- Improves availability in production while limiting risk from persistent misconfigurations.

---

### 3.5 Critical Thinking Questions

1. **Which profile for DEVELOPMENT?**
   - **Hardened**. Balances security checks with usability. Detects potential issues early without strict production restrictions.

2. **Which profile for PRODUCTION?**
   - **Production**. Strongest security measures and resource limits; reduces risk if a container is compromised.

3. **What real-world problem do resource limits solve?**
   - Prevents a single container from crashing or degrading the host due to memory/CPU exhaustion or fork bombs.

4. **If an attacker exploits Default vs Production, what actions are blocked in Production?**
   - Privilege escalation blocked (`no-new-privileges`)
   - Kernel-level attacks prevented (capabilities dropped)
   - Fork bomb / process abuse limited (PID limit)
   - Resource exhaustion mitigated (memory/CPU limits)
   - Persistent crashes handled safely (restart policy)

5. **What additional hardening would you add?**
   - Read-only root filesystem
   - Explicit mounts for writable paths
   - Custom seccomp profiles
   - Rootless Docker
   - Restrict container networking
   - AppArmor / SELinux
   - Signed images and content trust
   - Health checks and runtime monitoring
   - Secrets management instead of env vars
