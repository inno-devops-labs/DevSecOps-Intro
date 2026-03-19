# Lab 7 — Container Security: Image Scanning & Deployment Hardening

**Name:** Baha Alimi
**Branch:** `feature/lab7`
**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout — Quickview Summary

```
Target     │  bkimminich/juice-shop:v19.0.0  │   11C    60H    29M     5L     7?
  digest   │  2765a26de764                   │
  platform │  linux/amd64                    │
  size     │  158 MB                         │
  packages │  1004                           │
Base image │  distroless/static:nonroot      │    0C     0H     0M     0L
```

**Key observation:** The base image `distroless/static:nonroot` carries zero vulnerabilities. All 11 critical and 60 high severity findings originate entirely from the application layer — npm packages and the Node.js runtime. This confirms that selecting a secure base image is necessary but not sufficient; application dependency management is the primary attack surface.

**Full scan summary:**

```
112 vulnerabilities found in 46 packages
  CRITICAL     11
  HIGH         60
  MEDIUM       29
  LOW           5
  UNSPECIFIED   7
```

Full output: `labs/lab7/scanning/scout-cves.txt`

---

### 1.2 Top 5 Critical/High Vulnerabilities (Docker Scout)

#### Vulnerability #1 — vm2 Sandbox Escape — `vm2@3.9.17`

| Field | Detail |
|-------|--------|
| CVE IDs | CVE-2026-22709, CVE-2023-37903, CVE-2023-37466, CVE-2023-32314 |
| Severity | **CRITICAL** (CVSS 9.8 each) |
| Package | `pkg:npm/vm2@3.9.17` |
| Fixed version | No fix — library is **deprecated and unmaintained** |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

Four separate sandbox escape vulnerabilities allow an attacker to execute arbitrary code outside the vm2 sandbox via Promise handler bypass, custom inspect function abuse, and OS command injection. The CVSS vector is network-exploitable with no privileges and no user interaction required — any input processed through vm2 could result in full host compromise. As the library is unmaintained with no fixed version, the only remediation is replacement with `isolated-vm`.

---

#### Vulnerability #2 — Node.js Runtime RCE — `node@22.18.0`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2025-55130 |
| Severity | **CRITICAL** |
| Package | `pkg:generic/node@22.18.0` |
| Fixed version | `22.22.0` |
| Additional HIGH CVEs | CVE-2026-21637, CVE-2025-59466, CVE-2025-59465, CVE-2025-55131 |

A critical vulnerability in the Node.js 22.x runtime affecting all versions below 22.22.0. Since Juice Shop runs on Node.js 22.18.0, the entire application runtime is affected. Multiple additional HIGH-severity CVEs exist in the same version range. Remediation requires rebuilding the Docker image with an updated Node.js binary.

---

#### Vulnerability #3 — JWT Algorithm Confusion — `jsonwebtoken@0.1.0` and `@0.4.0`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2015-9235 |
| Severity | **CRITICAL** |
| Package | `pkg:npm/jsonwebtoken@0.1.0`, `pkg:npm/jsonwebtoken@0.4.0` |
| Fixed version | `4.2.2` |
| Additional HIGH CVE | CVE-2022-23539 (CVSS 8.1) |

JWT verification can be bypassed by setting the algorithm field to `none`, allowing forged tokens without a valid signature. Combined with the hardcoded RSA private key baked into the image (found by Trivy in Lab 4 and Snyk in this lab), this creates a trivially exploitable authentication bypass: extract the private key from the image, forge an admin JWT, gain full application access. Upgrade to `jsonwebtoken@9.0.0+` and explicitly reject the `none` algorithm.

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

Prototype pollution allows an attacker to inject properties into JavaScript's base `Object.prototype`, affecting all objects in the application. This can lead to denial of service, property injection, or remote code execution by overwriting critical properties. The version in use (2.4.2) is six major releases behind the patched version. Upgrade to `lodash@4.17.21+`.

---

#### Vulnerability #5 — Weak PBKDF2 — `crypto-js@3.3.0`

| Field | Detail |
|-------|--------|
| CVE ID | CVE-2023-46233 |
| Severity | **CRITICAL** (CVSS 9.1) |
| Package | `pkg:npm/crypto-js@3.3.0` |
| Fixed version | `4.2.0` |
| CVSS Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |

The PBKDF2 implementation uses a default iteration count approximately 1,000x weaker than the 1993 RFC standard and 1.3 million times weaker than current NIST recommendations. Any passwords hashed using this library are trivially brute-forceable with modern GPU cracking tools. Upgrade to `crypto-js@4.2.0+` or migrate to the Node.js native `crypto` module.

---

### 1.3 Snyk Scan Results

Snyk was run as a comparison scan, testing both the OS/runtime layer and the npm dependency layer separately.

**Command:**
```powershell
docker run --rm `
  -e SNYK_TOKEN=<token> `
  -v /var/run/docker.sock:/var/run/docker.sock `
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 `
  --severity-threshold=high
```

Full output: `labs/lab7/scanning/snyk-results.txt`

**Scan summary:**

```
Organization:   3llimi
Tested 2 projects, 2 contained vulnerable paths.
  Project 1 (deb):  10 dependencies tested, 6 issues found
  Project 2 (npm):  975 dependencies tested, 47 issues found
```

**OS/runtime layer findings (6 issues):**

| Package | Description | Severity | Fixed in |
|---------|-------------|----------|----------|
| `node@22.18.0` | Race Condition | **Critical** | `22.22.0` |
| `node@22.18.0` | Symlink Following | High | `22.22.0` |
| `node@22.18.0` | Uncaught Exception (x2) | High | `22.22.0` |
| `node@22.18.0` | Undefined Behavior | High | `22.22.0` |
| `openssl/libssl3@3.0.17` | CVE-2025-69421 | High | `3.0.18-1~deb12u2` |

**Selected npm layer findings (47 issues, key entries):**

| Package | Vulnerability | Severity | Fix Path |
|---------|--------------|----------|----------|
| `multer@1.4.5-lts.2` | Uncaught Exception | **Critical** | Upgrade to `2.1.1` |
| `marsdb@0.6.11` | Arbitrary Code Injection | **Critical** | No fix available |
| `vm2@3.9.17` | Sandbox Bypass / RCE (x3) | **Critical** | Deprecated |
| `sequelize@6.37.7` | SQL Injection | High | `6.37.8` |
| `socket.io@3.1.2` | Denial of Service (x5) | High | `4.7.0` |
| `lodash@2.4.2` | Prototype Pollution (x5) | High | via `sanitize-html@1.7.1` |
| `jsonwebtoken@0.1.0/0.4.0` | Auth Bypass / Forgeable Tokens | High | `5.0.0+` |
| `qs@6.13.0` | Resource Exhaustion (x2) | High | via `express@4.22.0` |
| `ip@2.0.1` | SSRF (x2) | High | via `express-ipfilter@1.4.0` |
| `glob@10.4.5` | Command Injection | High | `12.0.0` |
| `libxmljs2@0.37.0` | Type Confusion (x2) | High | No fix available |
| `crypto-js@3.3.0` | Weak Hash | High | via `pdfkit@0.12.2` |

---

### 1.4 Scout vs Snyk Comparison

| Metric | Docker Scout | Snyk |
|--------|:-----------:|:----:|
| Total vulnerabilities | 112 | 53 |
| Critical | 11 | 5 |
| High | 60 | 48 |
| Packages scanned | 46 flagged | 985 (10 deb + 975 npm) |
| Severity threshold applied | All | High+ only |
| Dependency path shown | No | Yes (full chain) |
| Upgrade guidance | Fixed version | Specific upgrade path |
| No-fix findings labeled | Yes | Yes (explicit) |
| Secrets scanning | No | No |

**Key differences:**

Scout reports more total vulnerabilities (112 vs 53) because it scans all severity levels. Snyk was run with `--severity-threshold=high`, filtering out Medium and Low findings — this accounts for most of the gap, not a difference in detection quality.

Snyk's most significant advantage is showing full dependency chains (e.g. `body-parser > qs > vulnerability`), making findings directly actionable — a developer knows exactly which direct dependency to upgrade to fix a transitive vulnerability. Scout reports the vulnerable package but not the upgrade path through the tree.

Snyk explicitly labels no-fix findings — `marsdb`, `libxmljs2`, and `lodash.set` are flagged as having no available upgrade, which is critical for prioritisation decisions.

Both tools agree on the highest-risk packages: `vm2`, `marsdb`, `jsonwebtoken`, `lodash`, and `node@22.18.0` appear as critical/high in both scans, providing high-confidence validation. Snyk uniquely surfaced `multer@1.4.5-lts.2` as Critical — demonstrating that neither tool's finding set is a strict superset of the other.

**Conclusion:** Scout is better for broad vulnerability enumeration; Snyk is better for developer-facing remediation with dependency path analysis. Running both provides the most complete picture.

---

### 1.5 Dockle Configuration Assessment

**Command:**
```powershell
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0
```

Full output: `labs/lab7/scanning/dockle-results.txt`

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

**Summary statistics:**

| Level | Count |
|-------|------:|
| FATAL | 0 |
| WARN | 0 |
| INFO | 3 |
| SKIP | 1 |

No FATAL or WARN findings were detected. This is directly attributable to the `distroless/static:nonroot` base image — distroless images contain no shell, no package manager, and run as a non-root user by default, eliminating the most common Dockle FATAL findings.

**Finding analysis:**

**CIS-DI-0005 — Docker Content Trust not enabled (INFO)**

Docker Content Trust uses The Update Framework (TUF) to cryptographically sign and verify images at pull and push time. Without it, Docker does not verify that a pulled image was signed by a trusted publisher. A compromised registry, DNS hijack, or man-in-the-middle attack could serve a malicious image that appears legitimate. Remediation: set `DOCKER_CONTENT_TRUST=1` before any `docker pull` or `docker run` in CI/CD pipelines.

**CIS-DI-0006 — No HEALTHCHECK instruction (INFO)**

Without a `HEALTHCHECK` directive, Docker reports the container as `Up` as long as the process is running — even if the application is deadlocked or silently returning errors. Container orchestrators (Kubernetes, Docker Swarm) rely on health status for traffic routing and self-healing decisions.

Remediation:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3000/ || exit 1
```

**DKL-LI-0003 — Unnecessary files in image (INFO)**

Two macOS `.DS_Store` files were baked into the image inside `node_modules` subdirectories. These metadata files have no runtime purpose and indicate the image was built on a macOS machine without a `.dockerignore` file. While not directly exploitable, they reveal directory structure and indicate loose build hygiene.

Remediation: add `**/.DS_Store` to `.dockerignore`.

**DKL-LI-0001 — SKIP**

Dockle could not check for empty passwords because `distroless` images contain no `/etc/shadow` or `/etc/master.passwd`. There are no OS user accounts to audit. This is a security positive — the entire OS-level user account attack surface is removed.

---

### 1.6 Security Posture Assessment

**Does the image run as root?**

No. The `distroless/static:nonroot` base image sets UID 65532 (non-root) by default, confirmed by the Dockle SKIP on password file checks and the `:nonroot` suffix in the base image name. Even if the application is compromised, an attacker cannot perform privileged system operations without a separate privilege escalation exploit.

The security risks in this image come entirely from the application dependency layer — 11 critical CVEs in npm packages — not from the container configuration. The distroless base achieves its goal of minimising the configuration attack surface.

**Security improvement recommendations:**

1. Replace `vm2` with `isolated-vm` — unmaintained with 4 critical CVEs and no fix
2. Upgrade Node.js runtime from `22.18.0` to `22.22.0+`
3. Upgrade `jsonwebtoken` to `9.0.0+` and explicitly disable the `none` algorithm
4. Upgrade `crypto-js` to `4.2.0+` or migrate to Node.js native `crypto`
5. Upgrade `lodash` from `2.4.2` to `4.17.21+`
6. Upgrade `multer` to `2.1.1` — Critical uncaught exception CVE
7. Upgrade `sequelize` to `6.37.8` — confirmed SQL injection
8. Add `.dockerignore` to exclude `.DS_Store` and other build artifacts
9. Add `HEALTHCHECK` instruction to the Dockerfile
10. Enable Docker Content Trust in CI/CD pipelines

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Tooling Approach

Three tools were attempted for the CIS Docker Benchmark audit on this Windows 11 / Docker Desktop 29.2.0 environment.

**Tool 1 — `docker/docker-bench-security` (attempted, incompatible)**

This is the primary tool specified by the lab. It was attempted but failed to connect to the Docker daemon. The tool is designed exclusively for native Linux Docker hosts and requires a Unix socket at `/var/run/docker.sock`. Docker Desktop on Windows uses a Windows named pipe (`npipe:////./pipe/dockerDesktopLinuxEngine`) — the tool cannot connect regardless of mount syntax or Docker context configuration.

Evidence of the attempted run is documented in `labs/lab7/hardening/docker-bench-results.txt`.

What this tool would audit on a native Linux host that cannot be assessed from Windows:
- `--icc=false` (inter-container communication disabled)
- `--userns-remap` (user namespace remapping enabled)
- AppArmor/SELinux profiles loaded per container
- Audit logging on `/var/lib/docker`
- `docker` group membership restrictions
- Daemon configuration file permissions (`/etc/docker/daemon.json`)

**Tool 2 — `trivy --scanners misconfig` (succeeded)**

Ran successfully. Audits Dockerfile instructions and image-level CIS controls baked into the image manifest.

**Tool 3 — `dockle` (succeeded)**

Ran successfully. Applies the CIS Docker Benchmark image profile. This is the primary benchmark evidence for this task.

---

### 2.2 Trivy Misconfig Scan Results

**Command:**
```powershell
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  aquasec/trivy:latest image --scanners misconfig --format table `
  bkimminich/juice-shop:v19.0.0
```

Full output: `labs/lab7/hardening/trivy-misconfig.txt`

**Result: 0 misconfigurations detected across all targets.**

```
Target                                         Type      Misconfigurations
bkimminich/juice-shop:v19.0.0 (debian 12.11)   debian          -
juice-shop/build/package.json                  node-pkg        -
juice-shop/frontend/package.json               node-pkg        -
[all remaining node-pkg targets]                               -
```

Detected environment: Debian 12.11, 1 language-specific file, 0 config files.

| Check | Result | Reason |
|-------|--------|--------|
| DS002 — Run as non-root | Pass | `distroless:nonroot` (UID 65532) |
| DS005 — ADD vs COPY | Pass | No `ADD` with remote URLs |
| DS016 — Secrets in ENV | Pass | No secrets in environment variables |

---

### 2.3 Dockle CIS Benchmark Results

**Command:**
```powershell
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0
```

Full output: `labs/lab7/hardening/docker-bench-results.txt`

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

**Summary statistics:**

| Level | Count |
|-------|------:|
| FATAL | 0 |
| WARN | 0 |
| INFO | 3 |
| SKIP | 1 |

**Analysis:** No failures detected. All findings are INFO level — informational recommendations, not security violations.

**Why no FATAL or WARN findings?**

The `distroless/static:nonroot` base image eliminates the most common Dockle FATAL conditions:

| Typical FATAL Check | Status | Reason |
|--------------------|--------|--------|
| Running as root (CIS-DI-0001) | Not triggered | UID 65532 (non-root) |
| Sensitive ENV variables | Not triggered | No secrets in ENV |
| Shell present in image | Not triggered | Distroless has no shell |
| Package manager present | Not triggered | Distroless has no package manager |

The security risks in this image come from the application dependency layer (11 critical npm CVEs), not from container configuration — consistent with the Task 1 findings.

---

### 2.4 Remediation Priorities

1. Enable Docker Content Trust in all CI/CD pipelines — prevents supply chain attacks via image substitution
2. Add `HEALTHCHECK` to Dockerfile — required for orchestration and self-healing
3. Add `.dockerignore` to exclude `.DS_Store` and other build artifacts from future image builds
4. On a production Linux host, run `docker/docker-bench-security` to audit daemon configuration, network isolation (`--icc=false`), AppArmor profiles, and audit logging — controls outside the scope of image-level scanners

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Deploy Commands

```powershell
# Profile 1: Default (baseline)
docker run -d --name juice-default -p 3001:3000 `
  bkimminich/juice-shop:v19.0.0

# Profile 2: Hardened
docker run -d --name juice-hardened -p 3002:3000 `
  --cap-drop=ALL `
  --security-opt=no-new-privileges `
  --memory=512m `
  --cpus=1.0 `
  bkimminich/juice-shop:v19.0.0

# Profile 3: Production
docker run -d --name juice-production -p 3003:3000 `
  --cap-drop=ALL `
  --cap-add=NET_BIND_SERVICE `
  --security-opt=no-new-privileges `
  --memory=512m `
  --memory-swap=512m `
  --cpus=1.0 `
  --pids-limit=100 `
  --restart=on-failure:3 `
  bkimminich/juice-shop:v19.0.0
```

Full comparison output: `labs/lab7/analysis/deployment-comparison.txt`

---

### 3.2 Functionality Test

```
=== Functionality Test ===
Default:    HTTP 200
Hardened:   HTTP 200
Production: HTTP 200
```

All three profiles returned HTTP 200 — security hardening did not break application functionality.

---

### 3.3 Configuration Comparison Table

From `docker inspect` output:

| Setting | Default | Hardened | Production |
|---------|:-------:|:--------:|:----------:|
| **CapDrop** | `<none>` | `ALL` | `ALL` |
| **CapAdd** | `<none>` | `<none>` | `NET_BIND_SERVICE` |
| **no-new-privileges** | No | Yes | Yes |
| **seccomp** | default (auto) | default (auto) | default (auto)* |
| **Memory limit** | `0` (unlimited) | 512 MiB | 512 MiB |
| **Memory swap limit** | unlimited | unlimited | 512 MiB (disabled) |
| **CPU quota** | unlimited | 1.0 core* | 1.0 core* |
| **PIDs limit** | unlimited | unlimited | 100 |
| **Restart policy** | `no` | `no` | `on-failure:3` |

*`--security-opt=seccomp=default` was omitted from the production run command on Docker Desktop for Windows because the platform resolves `default` as a literal file path rather than a built-in keyword, causing a container startup error. Docker applies the default seccomp profile automatically to all containers regardless — the security posture is identical to explicitly passing the flag. This is a platform-specific syntax limitation with no impact on actual security.

*`CpuQuota: 0` appears in `docker inspect` on Docker Desktop for Windows — a known display quirk. The `--cpus=1.0` limit is applied at the Hyper-V hypervisor level and is not visible through the Linux cgroup interface that `docker inspect` reads.

---

### 3.4 Resource Usage

```
=== Resource Usage ===
NAME               CPU %     MEM USAGE / LIMIT       MEM %
juice-default      0.75%     137.8MiB / 15.49GiB     0.87%
juice-hardened     0.79%     109.5MiB / 512MiB       21.38%
juice-production   1.85%     96.35MiB / 512MiB       18.82%
```

Juice Shop uses approximately 138 MiB at idle. The 512 MiB limit provides a 3.7x safety margin above normal usage while still enforcing a ceiling against memory exhaustion attacks.

---

### 3.5 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**

Linux capabilities divide the traditional all-or-nothing root privilege model into approximately 40 discrete units of privilege. Instead of a process being either fully privileged (root) or fully unprivileged, capabilities allow granting only the specific privileges a process needs. Examples: `CAP_NET_BIND_SERVICE` (bind to ports below 1024), `CAP_SYS_ADMIN` (mount filesystems, modify kernel parameters), `CAP_CHOWN` (change file ownership), `CAP_NET_RAW` (craft raw network packets for ARP spoofing).

**What attack vector does dropping ALL capabilities prevent?**

By default Docker containers run with approximately 14 capabilities including `CAP_NET_RAW` (ARP spoofing, packet crafting), `CAP_SYS_CHROOT` (change root directory), and `CAP_SETUID` (change user IDs). An attacker who achieves code execution inside the container can abuse these to attack other containers on the same network, attempt container escapes, or escalate privileges. `--cap-drop=ALL` removes every capability, leaving the process with the minimal possible privilege set.

**Why add back `NET_BIND_SERVICE`?**

Juice Shop listens on port 3000 (above 1024), so `NET_BIND_SERVICE` is not strictly required here. It is added defensively in the production profile in case the application ever needs to bind to a privileged port (80, 443) directly. The security trade-off is minimal — `NET_BIND_SERVICE` only permits port binding and cannot be abused for lateral movement or privilege escalation.

---

#### b) `--security-opt=no-new-privileges`

**What does this flag do?**

It sets the `PR_SET_NO_NEW_PRIVS` bit on the container's init process, inherited by all child processes. Once set it is irreversible for the lifetime of the process tree. It prevents any process in the container from gaining additional privileges through `setuid` binaries, `sudo`, or `su` — even if those binaries are present in the image with the setuid bit set on the filesystem.

**What type of attack does it prevent?**

It prevents privilege escalation via setuid executables. Without this flag, an attacker who gains code execution as a low-privileged user could run a setuid binary (e.g. `/usr/bin/sudo`) to elevate to root inside the container. Combined with `--cap-drop=ALL`, this creates a strong barrier against post-exploitation privilege escalation.

**Are there downsides?**

Yes — any legitimate functionality relying on setuid binaries breaks. For example, `ping` traditionally requires `CAP_NET_RAW` via a setuid binary. Juice Shop has no such dependencies so there is no functional impact in this case.

---

#### c) `--memory=512m` and `--cpus=1.0`

**What happens without resource limits?**

Without limits a single container can consume all available host memory and CPU. This is confirmed by the default profile `docker inspect` output: `Memory: 0` — unlimited, bounded only by the 15.49 GiB host RAM.

**What attack does memory limiting prevent?**

Memory limiting prevents denial-of-service via memory exhaustion. If an attacker exploits a vulnerability causing uncontrolled memory allocation (zip bomb, recursive object expansion, request flooding), the container is killed by the OOM killer before consuming memory needed by other containers or the host OS. The 512 MiB limit is well above the observed ~138 MiB idle usage, providing real headroom while enforcing a ceiling.

**What is the risk of setting limits too low?**

If the limit falls below normal operating memory, the container is OOM-killed during legitimate operation, causing unexpected crashes and potential data corruption if a write was in progress. The 3.7x safety margin above idle usage avoids this scenario.

---

#### d) `--pids-limit=100`

**What is a fork bomb?**

A fork bomb is a denial-of-service attack where a process continuously forks copies of itself (the classic bash example: `:() { :|:& };:`). Within seconds the process table fills completely, making it impossible to start any new processes — including those needed to manage or kill the attack. The system becomes unresponsive and typically requires a hard reboot.

**How does PID limiting help?**

`--pids-limit=100` caps the total number of processes the container can spawn. Once the limit is reached, any `fork()` or `clone()` call fails with `EAGAIN`. This contains the blast radius entirely within the container's PID namespace — the host and other containers are completely unaffected. The attack becomes self-defeating: the fork bomb cannot spawn enough processes to escape its namespace.

**How to determine the right limit?**

Observe the container under realistic load and measure peak PID count with `docker stats` or `/sys/fs/cgroup/pids/docker/<id>/pids.current`. Set the limit to approximately 2-3x the peak observed count to allow bursts without enabling a fork bomb. For Juice Shop, 100 is a reasonable value given it runs as a single Node.js process with worker threads.

---

#### e) `--restart=on-failure:3`

**What does this policy do?**

It tells Docker to automatically restart the container if it exits with a non-zero exit code (i.e. crashes), up to a maximum of 3 consecutive attempts. The retry counter resets if the container runs successfully for more than 10 seconds. After 3 consecutive failures, Docker stops retrying.

**When is auto-restart beneficial? When is it risky?**

Beneficial for transient failures such as temporary database unavailability, OOM kills on traffic spikes, or application bugs that crash on specific inputs but recover cleanly. The application returns to service automatically without operator intervention.

Risky if the container is crashing because it is being actively exploited or due to a persistent misconfiguration. In those cases `on-failure` will repeatedly restart it — potentially giving an attacker repeated opportunities to exploit the same vulnerability, or masking a serious issue by continuously restarting into a broken state.

**`on-failure` vs `always`:**

`always` restarts the container regardless of exit code, including intentional clean shutdowns (exit code 0). This reverses controlled deployments and maintenance windows. `on-failure` is safer: it only restarts on unexpected crashes, respects intentional stops, and the `:3` cap prevents infinite crash loops.

---

### 3.6 Critical Thinking Questions

**1. Which profile for development? Why?**

The **Default** profile is most appropriate for development. Developers need unrestricted capabilities to run debugging tools (`strace`, `gdb`), attach profilers, modify files, and experiment freely. Hardening flags like `--cap-drop=ALL` and `--no-new-privileges` can interfere with legitimate tasks. The risk is acceptable in a local environment isolated to `127.0.0.1` with no external network exposure.

**2. Which profile for production? Why?**

The **Production** profile. It applies the principle of least privilege (all capabilities dropped, only `NET_BIND_SERVICE` added back), prevents privilege escalation (`no-new-privileges`), enforces resource limits to contain DoS scenarios (512 MiB memory, swap disabled, 100 PID limit), and provides automatic recovery from transient failures (`on-failure:3`). The functionality test confirmed HTTP 200 with all restrictions applied — the hardening does not break the application.

**3. What real-world problem do resource limits solve?**

Resource limits solve the noisy neighbour problem in multi-tenant environments. Without limits, a single misbehaving container — due to a bug, an attack, or a traffic spike — can starve all other containers on the host of CPU and memory, causing cascading failures across unrelated services. In cloud environments this translates directly to unplanned cost (unbounded memory billing), SLA violations, and potential full host outages. Limits create predictable resource allocation and blast radius containment.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

An attacker with RCE inside the **Default** container can:
- Use `CAP_NET_RAW` to perform ARP spoofing and intercept traffic from other containers on the same network
- Use `CAP_SYS_CHROOT` to escape to host filesystem paths
- Run setuid binaries to escalate to root inside the container
- Spawn unlimited processes (fork bomb, multiple concurrent reverse shells)
- Consume unlimited memory and CPU to DoS the entire host

In the **Production** container, all of the above are blocked:
- `--cap-drop=ALL` removes `CAP_NET_RAW`, `CAP_SYS_CHROOT`, and all other dangerous capabilities
- `--no-new-privileges` prevents setuid binary abuse regardless of what binaries are in the image
- `--pids-limit=100` prevents fork bombs and limits concurrent process spawning
- `--memory=512m` with swap disabled caps memory exhaustion
- The attacker is confined to a minimal privilege set with no viable escalation path

**5. What additional hardening would you add?**

1. **Read-only root filesystem** (`--read-only`) with explicit `tmpfs` mounts for writable paths — prevents an attacker from persisting malware or modifying application files on disk
2. **User namespace remapping** — maps container UID 0 to an unprivileged host UID, so even root inside the container is unprivileged on the host
3. **Custom seccomp profile** — restrict allowed syscalls to only those Juice Shop actually uses, blocking syscalls commonly used in container escapes (`ptrace`, `mount`, `unshare`, `keyctl`)
4. **AppArmor or SELinux profile** — mandatory access control policy confining the container process to only the files and capabilities it legitimately needs
5. **Network isolation** — `--network` flag to place the container on a dedicated bridge network, preventing communication with unrelated containers
6. **Remove `NET_BIND_SERVICE`** — Juice Shop only listens on port 3000 (above 1024) so this capability is not needed; it was added only as a defensive precaution

---

## Appendix — Commands Reference

```powershell
# Set UTF-8 encoding (required on Windows before all commands)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Docker Scout full CVE scan
docker scout cves bkimminich/juice-shop:v19.0.0 | `
  ForEach-Object { $_ -replace '\x1B\[[0-9;]*[mK]', '' } | `
  Set-Content -Path labs/lab7/scanning/scout-cves.txt

# Snyk scan (high severity and above)
docker run --rm `
  -e SNYK_TOKEN=<token> `
  -v /var/run/docker.sock:/var/run/docker.sock `
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 `
  --severity-threshold=high 2>&1 | `
  ForEach-Object { $_ -replace '\x1B\[[0-9;]*[mK]', '' } | `
  Set-Content -Path labs/lab7/scanning/snyk-results.txt

# Dockle configuration assessment
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0 | `
  ForEach-Object { $_ -replace '\x1B\[[0-9;]*[mK]', '' } | `
  Set-Content -Path labs/lab7/scanning/dockle-results.txt

# Trivy misconfig scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock `
  aquasec/trivy:latest image --scanners misconfig --format table `
  bkimminich/juice-shop:v19.0.0 | `
  ForEach-Object { $_ -replace '\x1B\[[0-9;]*[mK]', '' } | `
  Set-Content -Path labs/lab7/hardening/trivy-misconfig.txt

# Deploy three security profiles
docker run -d --name juice-default -p 3001:3000 bkimminich/juice-shop:v19.0.0

docker run -d --name juice-hardened -p 3002:3000 `
  --cap-drop=ALL --security-opt=no-new-privileges `
  --memory=512m --cpus=1.0 `
  bkimminich/juice-shop:v19.0.0

docker run -d --name juice-production -p 3003:3000 `
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE `
  --security-opt=no-new-privileges `
  --memory=512m --memory-swap=512m --cpus=1.0 `
  --pids-limit=100 --restart=on-failure:3 `
  bkimminich/juice-shop:v19.0.0

# Cleanup
docker stop juice-default juice-hardened juice-production
docker rm juice-default juice-hardened juice-production
```

---

## Evidence Files

```
labs/lab7/
├── scanning/
│   ├── scout-cves.txt            # Docker Scout CVE output (112 vulns, 46 packages)
│   ├── snyk-results.txt          # Snyk scan output (2 projects, 53 issues)
│   └── dockle-results.txt        # Dockle configuration assessment
├── hardening/
│   ├── docker-bench-results.txt  # docker-bench attempt — failed (Windows incompatible), see section 2.1
│   └── trivy-misconfig.txt       # Trivy misconfig scan (0 misconfigurations)
└── analysis/
    └── deployment-comparison.txt # Functionality test + resource usage + security configs
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Docker Scout v1.20.0 | CVE scanning — Docker advisory database |
| Snyk | CVE scanning — Snyk proprietary + NVD, full dependency path analysis |
| Dockle v0.4.x | CIS Docker Benchmark image configuration linting |
| Trivy | Misconfig scanning — Dockerfile and image-level CIS controls |
| docker/docker-bench-security | CIS Docker Benchmark host audit (incompatible with Docker Desktop on Windows — requires native Linux Docker host) |