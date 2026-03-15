# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout Results

The target image `bkimminich/juice-shop:v19.0.0` was scanned with Docker Scout.

#### Vulnerability summary
- Total vulnerabilities: **118**
- Critical: **11**
- High: **64**
- Medium: **31**
- Low: **5**
- Unspecified: **7**

### Top 5 Critical/High Vulnerabilities

| CVE / ID | Package | Severity | Impact |
|---|---|---:|---|
| CVE-2026-22709 | vm2 3.9.17 | Critical | Protection mechanism failure that can lead to full compromise of the sandboxed environment. |
| CVE-2025-55130 | node 22.18.0 | Critical | Race condition in the Node runtime, affecting the base runtime inside the image. |
| CVE-2019-10744 | lodash 2.4.2 | Critical | Prototype pollution vulnerability that can allow object manipulation and application abuse. |
| CVE-2015-9235 | jsonwebtoken 0.4.0 / 0.1.0 | Critical | Improper input validation that can lead to authentication bypass with forged tokens. |
| CVE-2023-46233 | crypto-js 3.3.0 | Critical | Use of a broken or risky cryptographic algorithm, weakening application security controls. |

### Snyk Comparison

The Snyk scan was started with the lab command and produced vulnerability output, but the run ended with:

```text
ERROR   Forbidden (SNYK-CLI-0000)
Status: 403 Forbidden
```

Despite the final 403 error, Snyk still reported meaningful findings before failing, including:
- critical and high vulnerabilities in `node@22.18.0`
- high-severity issues in `qs`, `ip`, `express-jwt`, `multer`, `glob`, `sequelize`, `socket.io`, `tar`, and other dependencies
- multiple upgrade recommendations for remediation

This means the comparison tool produced partial evidence, but the final scan was not fully successful because of account or access restrictions.

### Dockle Configuration Findings

Dockle produced the following findings:

#### INFO findings
- **CIS-DI-0005**: Content Trust is not enabled
  - Recommendation: `export DOCKER_CONTENT_TRUST=1` before `docker pull` or `docker build`
- **CIS-DI-0006**: No `HEALTHCHECK` instruction
  - Security concern: container health is not monitored, so failures may go unnoticed
- **DKL-LI-0003**: Unnecessary files inside the image
  - `juice-shop/node_modules/extglob/lib/.DS_Store`
  - `juice-shop/node_modules/micromatch/lib/.DS_Store`
  - Security concern: unnecessary files increase image noise and can expose accidental development artifacts

#### SKIP finding
- **DKL-LI-0001**: Avoid empty password
  - Dockle could not inspect `/etc/shadow` or `/etc/master.passwd`

### Security Posture Assessment

- The image has a **large number of critical and high vulnerabilities**
- The image contains **outdated dependencies**
- Dockle identified **missing content trust**
- Dockle identified **missing HEALTHCHECK**
- The overall security posture of the image is **weak** and not suitable for production without remediation

### Recommended Improvements

- update vulnerable application dependencies such as `vm2`, `jsonwebtoken`, `lodash`, `multer`, `sequelize`, and `socket.io`
- upgrade the base runtime (`node`)
- enable Docker Content Trust
- add a `HEALTHCHECK` instruction
- remove unnecessary files from the final image
- reduce attack surface by reviewing image contents and dependency tree

---

## Task 2 — Docker Host Security Benchmarking

### Command Execution Result

The CIS Docker Benchmark command from the lab was executed exactly as required, but it failed in the local environment.

Observed error:

```text
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: error mounting "/var/lib/docker/containers/.../hostname" to rootfs at "/etc/hostname": create mountpoint for /etc/hostname mount: create target of file bind-mount: mknod regular file /var/lib/docker/rootfs/overlayfs/.../etc/hostname: read-only file system: unknown
```

### Summary Statistics

PASS/WARN/FAIL/INFO statistics were **not available**, because the benchmark container did not start successfully.

### Analysis of Failure

This failure happened during the Docker Bench Security run on the local macOS Docker Desktop environment.  
The benchmark tool expects Linux host-style access to system paths and host namespaces, but in this environment the required mount operation failed with a **read-only filesystem** error.

### Security Impact

Because the benchmark did not complete, the Docker host configuration could not be audited against the CIS Docker Benchmark in this environment. As a result:
- no PASS/WARN/FAIL control breakdown was produced
- no validated host hardening conclusions can be drawn from this run

### Remediation / Workaround

A practical workaround is to run the same benchmark command on:
- a native Linux host
- a Linux VM
- or a CI runner with Linux Docker Engine

That would provide the expected CIS benchmark output.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Deployment Results

Three deployment profiles were attempted exactly as described in the lab:

- `juice-default`
- `juice-hardened`
- `juice-production`

#### Actual result
- `juice-default` started successfully
- `juice-hardened` started successfully
- `juice-production` failed to start

Observed error for the production profile:

```text
docker: opening seccomp profile (default) failed: open default: no such file or directory
```

### 3.2 Functionality Test Results

| Profile | Result |
|---|---|
| Default | HTTP 200 |
| Hardened | HTTP 200 |
| Production | HTTP 000 |

### 3.3 Configuration Comparison Table

| Setting | Default | Hardened | Production |
|---|---|---|---|
| Capabilities dropped | `<no value>` | `[ALL]` | Failed to start |
| Capabilities added | `<no value>` | none | Failed to start |
| Security options | `<no value>` | `[no-new-privileges]` | Failed to start (`seccomp=default` error) |
| Memory limit | `0` | `536870912` | Failed to start |
| CPU quota | `0` | `0` | Failed to start |
| PIDs limit | `<no value>` | `<no value>` | Failed to start |
| Restart policy | `no` | `no` | Failed to start |

### Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities split root privileges into smaller privileged actions.  
Dropping all capabilities removes unnecessary kernel-level privileges from the container.

**What attack vector does dropping ALL capabilities prevent?**  
It reduces the impact of container compromise by blocking privilege-dependent actions such as network manipulation, raw socket usage, mounting, or other privileged operations.

**Why add back `NET_BIND_SERVICE`?**  
This capability allows binding to low-numbered ports when needed. It is added back only if the application requires that specific privilege.

**Security trade-off:**  
Dropping everything is safer, but adding back only what is needed preserves least privilege.

#### b) `--security-opt=no-new-privileges`

This flag prevents the container and its child processes from gaining extra privileges during execution.

**What type of attack does it prevent?**  
It helps prevent privilege escalation, including abuse of setuid/setgid binaries.

**Downsides:**  
Some applications that rely on gaining extra privileges at runtime may stop working.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits, a container can consume excessive RAM or CPU.

**What attack does memory limiting prevent?**  
It helps reduce denial-of-service risk caused by memory exhaustion.

**Risk of limits being too low:**  
The application may crash, become unstable, or degrade under load.

#### d) `--pids-limit=100`

A fork bomb is a process-creation attack where a program continuously spawns new processes until the system cannot create more.

**How does PID limiting help?**  
It limits the number of processes the container can create, reducing the impact of fork-bomb style abuse.

**How to choose the limit?**  
The limit should be based on normal application behavior plus safe operating headroom.

#### e) `--restart=on-failure:3`

This policy restarts the container only when it exits with failure, up to 3 times.

**When is auto-restart beneficial?**  
It improves resilience against short-lived crashes.

**When is it risky?**  
It can hide repeated failures or create noisy restart loops if misused.

**`on-failure` vs `always`:**
- `on-failure` restarts only failed containers
- `always` restarts the container regardless of why it stopped

### Critical Thinking Questions

#### 1. Which profile is best for DEVELOPMENT? Why?

The **default** profile is the easiest for development because it has fewer restrictions and is less likely to break developer workflows.

#### 2. Which profile is best for PRODUCTION? Why?

The **production** profile is the best design for production because it adds the strongest restrictions:
- dropped capabilities
- `no-new-privileges`
- seccomp
- memory/CPU limits
- PID limit
- restart policy

However, in this environment it failed to start because of a seccomp-related issue.

#### 3. What real-world problem do resource limits solve?

They prevent one container from exhausting host resources and affecting other services, which is important for both accidental overload and denial-of-service scenarios.

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

In the production design, an attacker would face:
- reduced privilege set due to dropped capabilities
- no privilege escalation via `no-new-privileges`
- syscall restrictions through seccomp
- restricted resource abuse due to memory, CPU, and PID limits

#### 5. What additional hardening would you add?

Additional hardening ideas:
- run the container with a non-root user
- use a read-only root filesystem
- drop all writable mounts unless required
- use image signing / content trust
- add a `HEALTHCHECK`
- scan images continuously in CI/CD
- pin image digests instead of floating tags

---

## Final Conclusion

This lab showed three important things:

1. The Juice Shop image contains a large number of critical and high vulnerabilities.
2. Basic deployment hardening measures such as dropped capabilities, `no-new-privileges`, and resource limits improve security.
3. Some security tooling and runtime options may behave differently on macOS Docker Desktop than on a native Linux Docker host.

The hardened deployment profile worked successfully and preserved application functionality, while the production profile failed because of a local seccomp configuration issue. The CIS benchmark step also failed because the Docker host auditing container could not mount required host files in this environment.

Even with these environment limitations, the lab still demonstrated clear security value:
- image scanning exposed serious dependency risk
- Dockle highlighted image hardening gaps
- deployment comparison showed the effect of hardening flags on runtime behavior
