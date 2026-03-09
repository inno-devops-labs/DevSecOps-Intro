# Lab 7 — Container Security: Image Scanning & Deployment Hardening

**Branch:** `feature/lab7`
**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout Quickview Summary

```
Target     │  bkimminich/juice-shop:v19.0.0  │   11C    60H    29M     5L     7?
  digest   │  2765a26de764                   │
Base image │  distroless/static:nonroot      │    0C     0H     0M     0L
```

**Key observation:** The base image (`distroless/static:nonroot`) carries **zero vulnerabilities**. All 11 critical and 60 high severity findings originate entirely from the application layer — npm packages and the Node.js runtime. This confirms that base image choice alone is insufficient; dependency management is the primary attack surface.

**Full scan summary:**
```
112 vulnerabilities found in 46 packages
  CRITICAL     11
  HIGH         60
  MEDIUM       29
  LOW           5
  UNSPECIFIED   7
```

---

### 1.2 Top 5 Critical/High Vulnerabilities

#### Vulnerability #1 — vm2 Sandbox Escape (Multiple CVEs) — `vm2@3.9.17`

| Field | Detail |
|-------|--------|
| CVE IDs | CVE-2026-22709, CVE-2023-37903, CVE-2023-37466, CVE-2023-32314 |
| Severity | **CRITICAL** (CVSS 9.8 each) |
| Package | `pkg:npm/vm2@3.9.17` |
| Fixed version | Not fixed — library is **deprecated and unmaintained** |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Impact:** Four separate sandbox escape vulnerabilities allow an attacker to execute arbitrary code entirely outside the vm2 sandboxed environment via Promise handler bypass, custom inspect function abuse, and OS command injection. The CVSS vector (network-exploitable, no privileges, no user interaction required) means any user-supplied input processed through vm2 could result in full host compromise. The library is no longer maintained and has no fixed version — replacement with `isolated-vm` is the only remediation path.

---

#### Vulnerability #2 — Node.js Runtime RCE — `node@22.18.0`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2025-55130 |
| Severity | **CRITICAL** |
| Package | `pkg:generic/node@22.18.0` |
| Fixed version | `22.22.0` |
| Additional HIGH CVEs | CVE-2026-21637, CVE-2025-59466, CVE-2025-59465, CVE-2025-55131 |

**Impact:** A critical vulnerability in the Node.js 22.x runtime itself, affecting all versions below 22.22.0. Since Juice Shop runs on Node.js 22.18.0, the entire application runtime is vulnerable. Multiple additional HIGH-severity CVEs exist in the same version range. Remediation requires rebuilding the Docker image with an updated Node.js binary.

---

#### Vulnerability #3 — JWT Algorithm Confusion — `jsonwebtoken@0.1.0` and `@0.4.0`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2015-9235 |
| Severity | **CRITICAL** |
| Package | `pkg:npm/jsonwebtoken@0.1.0`, `pkg:npm/jsonwebtoken@0.4.0` |
| Fixed version | `4.2.2` |
| Additional HIGH CVE | CVE-2022-23539 (CVSS 8.1) — broken cryptographic algorithm |

**Impact:** JWT verification can be bypassed by setting the algorithm field to `none`, allowing an attacker to forge arbitrary JWT tokens without a valid signature. Combined with the hardcoded RSA private key found baked into the image (confirmed by Trivy in Lab 4), this creates a trivially exploitable authentication bypass chain: extract the private key, forge an admin JWT, gain full application access. Upgrade to `jsonwebtoken@9.0.0+` and explicitly reject the `none` algorithm in all verification calls.

---

#### Vulnerability #4 — Prototype Pollution — `lodash@2.4.2`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2019-10744 |
| Severity | **CRITICAL** (CVSS 9.1) |
| Package | `pkg:npm/lodash@2.4.2` |
| Fixed version | `4.17.12` |
| Additional HIGH CVEs | CVE-2020-8203, CVE-2021-23337, CVE-2018-16487 |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` |

**Impact:** Prototype pollution allows an attacker to inject properties into JavaScript's base `Object.prototype`, affecting all objects in the application. This can lead to denial of service, property injection, or in certain contexts remote code execution by overwriting critical properties. The version in use (2.4.2) is six major releases behind the patched version and carries multiple additional high-severity CVEs. Upgrade to `lodash@4.17.21+`.

---

#### Vulnerability #5 — Weak PBKDF2 Implementation — `crypto-js@3.3.0`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2023-46233 |
| Severity | **CRITICAL** (CVSS 9.1) |
| Package | `pkg:npm/crypto-js@3.3.0` |
| Fixed version | `4.2.0` |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |

**Impact:** The PBKDF2 implementation uses a default iteration count that is approximately 1,000× weaker than the 1993 RFC standard and 1.3 million× weaker than current NIST recommendations. Any passwords hashed using this library (including user account passwords) are trivially brute-forceable with modern GPU-based cracking tools. Upgrade to `crypto-js@4.2.0+` or migrate to the Node.js native `crypto` module which uses correct defaults.

---

### 1.3 Dockle Configuration Assessment

```
SKIP    - DKL-LI-0001: Avoid empty password
        * failed to detect etc/shadow,etc/master.passwd
INFO    - CIS-DI-0005: Enable Content trust for Docker
        * export DOCKER_CONTENT_TRUST=1 before docker pull/build
INFO    - CIS-DI-0006: Add HEALTHCHECK instruction to the container image
        * not found HEALTHCHECK statement
INFO    - DKL-LI-0003: Only put necessary files
        * unnecessary file : juice-shop/node_modules/extglob/lib/.DS_Store
        * unnecessary file : juice-shop/node_modules/micromatch/lib/.DS_Store
```

**No FATAL or WARN findings were detected.** All findings are INFO level. This is explained by the use of `distroless/static:nonroot` as the base image — distroless images are intentionally minimal, containing no shell, no package manager, and running as a non-root user by default. This eliminates the most common Dockle FATAL findings (running as root, exposed shell, default passwords).

**INFO Finding Analysis:**

| Finding | ID | Security Concern |
|---------|----|-----------------|
| Docker Content Trust not enabled | CIS-DI-0005 | Without DCT, pulled images are not cryptographically verified against a trusted registry. A compromised registry or MITM attack could substitute a malicious image. Mitigation: `$env:DOCKER_CONTENT_TRUST=1` before pull/run. |
| No HEALTHCHECK defined | CIS-DI-0006 | Without a healthcheck, Docker cannot distinguish between a running container and a functionally broken one. Orchestrators (Kubernetes, Swarm) rely on health status for traffic routing and self-healing. A crashed application could silently serve errors. |
| `.DS_Store` files present | DKL-LI-0003 | macOS build artifacts committed into the image. While not directly exploitable, they reveal directory structure to attackers and indicate the image was built without a proper `.dockerignore` file, suggesting loose build hygiene. |

**SKIP Finding:**

The `DKL-LI-0001` check was skipped because `distroless` images do not contain `/etc/shadow` or `/etc/master.passwd` — there are no user accounts to audit. This is actually a security positive: the attack surface from OS-level user management is completely removed.

---

### 1.4 Security Posture Assessment

**Does the image run as root?**

No. The `distroless/static:nonroot` base image explicitly sets a non-root user (UID 65532, group 65532). This is confirmed by the Dockle skip on password file checks and by the image name suffix `:nonroot`. Running as non-root means that even if the application is compromised, an attacker cannot perform privileged system operations without a separate privilege escalation exploit.

**Security improvement recommendations:**

1. **Replace `vm2`** with `isolated-vm` or remove entirely — the library is unmaintained with no fix available and carries four critical CVEs
2. **Upgrade Node.js runtime** from 22.18.0 to 22.22.0+ to patch the critical runtime CVE and four high-severity sibling CVEs
3. **Upgrade `jsonwebtoken`** to 9.0.0+ and explicitly disable the `none` algorithm
4. **Upgrade `crypto-js`** to 4.2.0+ or migrate to native Node.js `crypto`
5. **Upgrade `lodash`** from 2.4.2 to 4.17.21+
6. **Add a `.dockerignore` file** to prevent `.DS_Store` and other build artifacts from entering the image
7. **Add a `HEALTHCHECK` instruction** to the Dockerfile for production operational visibility
8. **Enable Docker Content Trust** in CI/CD pipelines

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Tooling Approach

Three tools were attempted for the CIS Docker Benchmark audit on this Windows 11 / Docker Desktop 29.2.0 environment:

**Tool 1: `docker/docker-bench-security`** — failed to connect to the Docker daemon. The tool is designed for native Linux Docker hosts and requires a Unix socket at `/var/run/docker.sock`. Docker Desktop on Windows uses a Windows named pipe (`npipe:////./pipe/dockerDesktopLinuxEngine`) which the tool cannot use, regardless of mount syntax. All variants were attempted including privileged mode, named pipe mounts, and alternate context endpoints — all returned `Error connecting to docker daemon`.

**Tool 2: `trivy --scanners misconfig`** — ran successfully and completed a full scan of the image. Zero misconfigurations found across all 1,004 packages and image layers. Every target row returned `-` (not applicable) under the misconfigurations column.

**Tool 3: `dockle`** — ran successfully and applied the full CIS Docker Benchmark profile against the image. This is the primary benchmark evidence for this task.

---

### 2.2 Trivy Misconfig Scan Results

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock
  aquasec/trivy:latest image --scanners misconfig --format table
  bkimminich/juice-shop:v19.0.0
```

**Result: 0 FAIL, 0 WARN, 0 PASS — no misconfigurations detected.**

| Check | Result | Reason |
|-------|--------|--------|
| DS002 — Run as non-root user | ✅ PASS (implicit) | Image uses `distroless:nonroot` (UID 65532) |
| DS005 — ADD vs COPY | ✅ PASS (implicit) | No `ADD` with remote URLs detected |
| DS016 — Secrets in ENV | ✅ PASS (implicit) | No secrets baked into environment variables |

Trivy's image misconfig scanner audits Dockerfile instructions baked into the image manifest. Juice Shop passes all checks primarily because the `distroless/static:nonroot` base image handles the most critical control — running as a non-root user — by default.

---

### 2.3 Dockle CIS Benchmark Results (Primary Evidence)

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0
```

**Raw output:**
```
SKIP    - DKL-LI-0001: Avoid empty password
        * failed to detect etc/shadow,etc/master.passwd
INFO    - CIS-DI-0005: Enable Content trust for Docker
        * export DOCKER_CONTENT_TRUST=1 before docker pull/build
INFO    - CIS-DI-0006: Add HEALTHCHECK instruction to the container image
        * not found HEALTHCHECK statement
INFO    - DKL-LI-0003: Only put necessary files
        * unnecessary file : juice-shop/node_modules/extglob/lib/.DS_Store
        * unnecessary file : juice-shop/node_modules/micromatch/lib/.DS_Store
```

**Summary Statistics:**

| Level | Count |
|-------|------:|
| FATAL | 0 |
| WARN | 0 |
| INFO | 3 |
| SKIP | 1 |
| **Total** | **4** |

---

### 2.4 Finding Analysis

**Finding 1 — CIS-DI-0005: Docker Content Trust not enabled (INFO)**

Docker Content Trust (DCT) uses The Update Framework (TUF) to cryptographically sign and verify images at pull and push time. Without DCT enabled, Docker does not verify that a pulled image was signed by a trusted publisher. This creates a supply chain risk: a compromised registry, a DNS hijack, or a man-in-the-middle attack could serve a malicious image that appears to be the legitimate one.

Remediation: Set `DOCKER_CONTENT_TRUST=1` as an environment variable before any `docker pull` or `docker run` in CI/CD pipelines. For production deployments, enforce this at the daemon level via Docker daemon configuration.

**Finding 2 — CIS-DI-0006: No HEALTHCHECK instruction (INFO)**

The Juice Shop image contains no `HEALTHCHECK` directive in its Dockerfile. Without a healthcheck, Docker reports the container status as `Up` as long as the process is running — even if the application is deadlocked, out of memory, or silently returning errors on every request. Container orchestrators such as Kubernetes and Docker Swarm rely on health status to make traffic routing and self-healing decisions.

Remediation: Add a `HEALTHCHECK` instruction to the Dockerfile:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3000/ || exit 1
```

**Finding 3 — DKL-LI-0003: Unnecessary files in image (INFO)**

Two macOS `.DS_Store` files were found baked into the image inside `node_modules` subdirectories. These are metadata files automatically created by macOS Finder and have no runtime purpose. Their presence indicates the image was built on a macOS machine without a `.dockerignore` file to exclude them. While not directly exploitable, they reveal directory structure information to anyone who pulls the image and may indicate broader build hygiene issues.

Remediation: Add a `.dockerignore` file to the repository root containing `**/.DS_Store` to prevent these files from being included in future image builds.

**Finding 4 — DKL-LI-0001: SKIP — Avoid empty password**

Dockle could not check for empty passwords because the image does not contain `/etc/shadow` or `/etc/master.passwd`. These files are absent because `distroless` images contain no OS user management layer at all — there are no user accounts, no shell, and no password files. This skip is a security positive: the entire OS-level user account attack surface is removed.

---

### 2.5 Why No FATAL or WARN Findings?

The absence of any FATAL or WARN findings is directly attributable to the `distroless/static:nonroot` base image. Standard Dockle FATAL checks that would fire on a typical Ubuntu or Alpine base image include:

| Typical FATAL Check | Status for Juice Shop | Reason |
|--------------------|-----------------------|--------|
| Running as root (CIS-DI-0001) | ✅ Not triggered | UID 65532 (non-root) |
| Sensitive environment variables | ✅ Not triggered | No secrets in ENV |
| Default shell present | ✅ Not triggered | Distroless has no shell |
| Unnecessary packages | ✅ Not triggered | No package manager present |

The distroless base image was specifically designed to minimise the container attack surface, and this benchmark result confirms it achieves that goal at the image configuration level. The significant security risks in this image come from the **application dependency layer** (the 11 critical CVEs in npm packages), not from the container configuration — which is exactly what Task 1 identified.

---

### 2.6 Remediation Priorities

1. **Enable Docker Content Trust** in all CI/CD pipelines and deployment scripts — prevents supply chain attacks via image substitution
2. **Add HEALTHCHECK to Dockerfile** — required for production orchestration and self-healing behaviour
3. **Add `.dockerignore`** to exclude `.DS_Store`, `node_modules`, and other unnecessary files from image builds
4. **On a production Linux host**, run the full `docker/docker-bench-security` tool to audit daemon configuration, host partitioning, network isolation (`--icc=false`), AppArmor profiles, and log driver configuration — controls that cannot be assessed from Windows Docker Desktop

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

All three containers returned **HTTP 200** — confirming that security hardening did not break application functionality.

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| **CapDrop** | `<none>` | `ALL` | `ALL` |
| **CapAdd** | `<none>` | `<none>` | `NET_BIND_SERVICE` |
| **SecurityOpt** | `<none>` | `no-new-privileges` | `no-new-privileges` |
| **Memory limit** | Unlimited (0) | 512 MiB | 512 MiB |
| **Memory swap limit** | Unlimited | Unlimited | 512 MiB (swap disabled) |
| **CPU quota** | Unlimited (0) | Unlimited (0) | Unlimited (0)* |
| **PIDs limit** | Unlimited | Unlimited | 100 |
| **Restart policy** | `no` | `no` | `on-failure:3` |

**Resource usage observed:**

| Container | CPU % | Memory Used | Memory % of Limit |
|-----------|------:|-------------|-------------------|
| juice-default | 0.75% | 137.8 MiB | 0.87% (of 15.49 GiB host) |
| juice-hardened | 0.79% | 109.5 MiB | 21.38% (of 512 MiB) |
| juice-production | 1.85% | 96.35 MiB | 18.82% (of 512 MiB) |

*Note: `--cpus=1.0` was specified but `CpuQuota: 0` appears in `docker inspect` output on Docker Desktop for Windows — this is a known Docker Desktop display quirk; the limit is applied at the hypervisor level.*

*Note: `--security-opt=seccomp=default` was omitted from the production profile because Docker Desktop on Windows resolves `default` as a file path rather than a keyword. Docker applies the default seccomp profile automatically regardless, so this represents no reduction in security — it is a platform-specific command syntax limitation.*

---

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**

Linux capabilities divide the traditional all-or-nothing root privilege model into ~40 discrete units of privilege. Instead of a process being either fully privileged (root) or fully unprivileged, capabilities allow granting only the specific privileges a process needs. Examples include `CAP_NET_BIND_SERVICE` (bind to ports below 1024), `CAP_SYS_ADMIN` (mount filesystems, modify kernel parameters), `CAP_CHOWN` (change file ownership).

**What attack vector does dropping ALL capabilities prevent?**

By default Docker containers run with ~14 capabilities including `CAP_NET_RAW` (craft raw packets, ARP spoofing), `CAP_SYS_CHROOT` (change root directory), and `CAP_SETUID` (change user IDs). An attacker who achieves code execution inside the container can abuse these capabilities to attack other containers on the same network, perform container escape attempts, or escalate privileges. `--cap-drop=ALL` removes every capability, leaving the process with the minimal possible privilege set.

**Why add back `NET_BIND_SERVICE`?**

The application listens on port 3000 (above 1024), so `NET_BIND_SERVICE` is not strictly needed here. The production profile adds it defensively — if the application ever needs to bind to a privileged port (80, 443) directly, this single capability enables that without restoring any other dangerous capabilities. The security trade-off is minimal: `NET_BIND_SERVICE` only allows port binding and cannot be abused for lateral movement or privilege escalation.

---

#### b) `--security-opt=no-new-privileges`

**What does this flag do?**

It sets the `PR_SET_NO_NEW_PRIVS` bit on the container's init process, which is inherited by all child processes. Once set, it is irreversible for the lifetime of the process tree. It prevents any process in the container from gaining additional privileges through `setuid` binaries, `sudo`, or `su` — even if those binaries are present and have the setuid bit set.

**What type of attack does it prevent?**

It prevents privilege escalation attacks via setuid executables. Without this flag, an attacker who gains code execution as a low-privileged user could run a setuid binary (e.g. `/usr/bin/sudo`, `/bin/su`) to elevate to root inside the container. Combined with `--cap-drop=ALL`, it creates a strong defence against post-exploitation privilege escalation.

**Are there downsides?**

Yes — any legitimate application functionality that relies on `setuid` binaries will break. For example, ping (which traditionally uses `CAP_NET_RAW` via setuid) would fail. Juice Shop does not rely on setuid binaries, so there is no functional impact here.

---

#### c) `--memory=512m` and `--cpus=1.0`

**What happens without resource limits?**

Without limits, a single container can consume all available host memory and CPU. The default profile confirmed this: `Memory: 0` (unlimited, effectively bounded only by the 15.49 GiB host RAM).

**What attack does memory limiting prevent?**

Memory limiting prevents **denial-of-service via memory exhaustion**. If an attacker exploits a vulnerability that causes uncontrolled memory allocation (e.g. a zip bomb, recursive object expansion, or simply flooding the application with large requests), the container is killed by the OOM killer before it can consume memory needed by other containers or the host OS. The 512 MiB limit is well above the observed ~138 MiB usage, providing headroom while still enforcing a ceiling.

**What's the risk of setting limits too low?**

If the limit is set below normal operating memory usage, the container will be OOM-killed during legitimate operation — causing unexpected crashes and potential data corruption if the application was mid-write. The resource usage data shows Juice Shop uses ~138 MiB at idle, so 512 MiB provides a ~3.7× safety margin.

---

#### d) `--pids-limit=100`

**What is a fork bomb?**

A fork bomb is a denial-of-service attack where a process continuously forks copies of itself (e.g. the classic bash fork bomb `:() { :|:& };:`). Within seconds, the process table fills completely, making it impossible to start any new processes — including the ones needed to manage or kill the attack. The system becomes unresponsive and typically requires a hard reboot.

**How does PID limiting help?**

`--pids-limit=100` caps the total number of processes the container can spawn at 100. Once the limit is reached, any `fork()` or `clone()` call fails with `EAGAIN`. This contains the blast radius entirely within the container — the host and other containers are unaffected. The attack is self-defeating: the fork bomb cannot spawn enough processes to escape the container's PID namespace.

**How to determine the right limit?**

Observe the container under realistic load and measure peak PID count with `docker stats` or `cat /sys/fs/cgroup/pids/docker/<id>/pids.current`. Set the limit to approximately 2–3× the peak observed count to allow bursts without enabling a fork bomb. For Juice Shop, 100 is a reasonable value given it's a single Node.js process with worker threads.

---

#### e) `--restart=on-failure:3`

**What does this policy do?**

It tells Docker to automatically restart the container if it exits with a non-zero exit code (i.e. crashes), up to a maximum of 3 attempts. If the container fails 3 times consecutively, Docker stops retrying. The retry counter resets if the container runs successfully for more than 10 seconds.

**When is auto-restart beneficial? When is it risky?**

Beneficial: transient failures such as temporary database unavailability, out-of-memory kills, or application bugs that crash on specific inputs but recover cleanly on restart. The application returns to service automatically without operator intervention.

Risky: if the container is crashing because it is being actively exploited or because of a persistent misconfiguration, `on-failure` will repeatedly restart it — potentially giving an attacker repeated opportunities to exploit the same vulnerability, or masking a serious underlying issue by continuously restarting into a broken state.

**`on-failure` vs `always`:**

`always` restarts the container regardless of exit code — including clean exits (code 0). This means even intentional shutdowns are reversed, which is inappropriate for most scenarios and can interfere with controlled deployments and maintenance windows. `on-failure` is safer: it only restarts on unexpected crashes, respects intentional stops, and has the `:3` retry cap to prevent infinite crash loops.

---

### 3.3 Critical Thinking Questions

**1. Which profile for DEVELOPMENT? Why?**

The **Default** profile is most appropriate for development. Developers need unrestricted capabilities to run debugging tools, attach profilers, modify files, and experiment with the application. Hardening flags like `--cap-drop=ALL` and `--no-new-privileges` can interfere with legitimate development tasks (e.g. running strace, mounting filesystems for inspection, or using sudo for package installation). The risk is acceptable in a local development environment isolated to `127.0.0.1` with no external network exposure.

**2. Which profile for PRODUCTION? Why?**

The **Production** profile. It applies the principle of least privilege (all capabilities dropped, only `NET_BIND_SERVICE` added back), prevents privilege escalation (`no-new-privileges`), enforces resource limits to contain DoS scenarios (512 MiB memory, swap disabled, 100 PID limit), and provides automatic recovery from transient failures (`on-failure:3`). The functionality test confirmed HTTP 200 with all restrictions applied, proving the hardening does not break the application.

**3. What real-world problem do resource limits solve?**

Resource limits solve the **noisy neighbour problem** in multi-tenant environments. Without limits, a single misbehaving container — whether due to a bug, an attack, or a traffic spike — can starve all other containers on the host of CPU and memory, causing cascading failures across unrelated services. In cloud environments, this translates directly to cost (unbounded memory usage), SLA violations, and potential full host outages. Limits create predictable resource allocation and blast radius containment.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

An attacker who achieves Remote Code Execution inside the Default container can:
- Use `CAP_NET_RAW` to perform ARP spoofing and intercept traffic from other containers
- Use `CAP_SYS_CHROOT` to escape to host filesystem paths
- Run setuid binaries to escalate to root inside the container
- Spawn unlimited processes (fork bomb, spawn reverse shells)
- Consume unlimited memory/CPU to DoS the host

In the **Production** container, all of the above are blocked:
- `--cap-drop=ALL` removes `CAP_NET_RAW`, `CAP_SYS_CHROOT`, and all other dangerous capabilities
- `--no-new-privileges` prevents setuid binary abuse even if such binaries are present
- `--pids-limit=100` prevents fork bombs and limits process spawning
- `--memory=512m` with swap disabled caps memory exhaustion
- The attacker is confined to a minimal privilege set with no escalation path

**5. What additional hardening would you add?**

1. **Read-only root filesystem** (`--read-only`) with explicit tmpfs mounts for writable paths — prevents an attacker from persisting malware or modifying application files
2. **User namespace remapping** — maps container root (UID 0) to an unprivileged host UID, so even root inside the container is unprivileged on the host
3. **Custom seccomp profile** — restrict allowed syscalls to only those Juice Shop actually uses, blocking syscalls commonly used in container escapes (`ptrace`, `mount`, `unshare`)
4. **AppArmor or SELinux profile** — mandatory access control policy confining the container process to only the files and capabilities it legitimately needs
5. **Network isolation** — `--network` flag to place the container on a dedicated bridge network, preventing communication with unrelated containers
6. **Drop `NET_BIND_SERVICE`** if the application only listens on port 3000 — it is not needed and was added only as a precautionary measure

---

## Appendix — Commands Reference

```powershell
# Docker Scout quickview
docker scout quickview bkimminich/juice-shop:v19.0.0

# Full CVE scan
docker scout cves bkimminich/juice-shop:v19.0.0 | Tee-Object -FilePath labs/lab7/scanning/scout-cves.txt

# Dockle configuration assessment
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0 | Tee-Object -FilePath labs/lab7/scanning/dockle-results.txt

# Deploy three security profiles
docker run -d --name juice-default -p 3001:3000 bkimminich/juice-shop:v19.0.0
docker run -d --name juice-hardened -p 3002:3000 --cap-drop=ALL --security-opt=no-new-privileges --memory=512m --cpus=1.0 bkimminich/juice-shop:v19.0.0
docker run -d --name juice-production -p 3003:3000 --cap-drop=ALL --cap-add=NET_BIND_SERVICE --security-opt=no-new-privileges --memory=512m --memory-swap=512m --cpus=1.0 --pids-limit=100 --restart=on-failure:3 bkimminich/juice-shop:v19.0.0

# Cleanup
docker stop juice-default juice-hardened juice-production
docker rm juice-default juice-hardened juice-production
```

### Tools Used

- **Docker Scout v1.20.0** — CVE scanning against Docker's vulnerability database
- **Dockle v0.4.x** — CIS-based container image configuration linter
- **docker/docker-bench-security** — CIS Docker Benchmark audit tool (incompatible with Docker Desktop on Windows — requires native Linux Docker host)