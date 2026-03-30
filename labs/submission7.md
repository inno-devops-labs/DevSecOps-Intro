# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

## Task 1: Image Vulnerability & Configuration Analysis

### 1.1 Vulnerability Summary (Docker Scout)

**Image:** `bkimminich/juice-shop:v19.0.0`  
**Total:** 118 vulnerabilities in 48 packages

| Severity | Count |
|---|---|
| CRITICAL | 11 |
| HIGH | 65 |
| MEDIUM | 30 |
| LOW | 5 |
| UNSPECIFIED | 7 |

### Top 5 Critical/High Vulnerabilities

1. **CVE-2023-37466** — `vm2` package
   - **Severity:** CRITICAL (CVSS 9.8)
   - **Impact:** OS Command Injection — allows arbitrary code execution via sandbox escape
   - **Description:** Improper Control of Code Generation in vm2 ≤3.9.19

2. **CVE-2023-37903** — `vm2` package
   - **Severity:** CRITICAL (CVSS 9.8)
   - **Impact:** OS Command Injection, full sandbox bypass with RCE
   - **Description:** Improper Neutralization of OS Command elements in vm2 ≤3.9.19

3. **CVE-2019-10744** — `lodash` package
   - **Severity:** CRITICAL (CVSS 9.1)
   - **Impact:** Prototype Pollution — can corrupt Object prototype, potentially leading to DoS or RCE
   - **Description:** Improper modification of Object prototype attributes in lodash <4.17.12

4. **CVE-2015-9235** — `jsonwebtoken` package
   - **Severity:** CRITICAL
   - **Impact:** Auth bypass — `alg: "none"` JWT accepted as valid, no signature verification
   - **Description:** Improper Input Validation in jsonwebtoken <4.2.2

5. **CVE-2023-46233** — `crypto-js` package
   - **Severity:** CRITICAL
   - **Impact:** Weak cryptographic algorithm — PBKDF2 implementation vulnerable to brute-force
   - **Description:** Use of Broken Cryptographic Algorithm in crypto-js <4.2.0

### 1.2 Snyk Comparison

**Scan:** `snyk container test bkimminich/juice-shop:v19.0.0 --severity-threshold=high`  
**Organization:** aidarsarvartdinov2004  
**Result:** Tested 2 projects — both contained vulnerable paths

| Package | Severity | Vulnerability |
|---|---|---|
| `node@22.18.0` | **CRITICAL** | Race Condition — CVE via SNYK-UPSTREAM-NODE-14928492 |
| `node@22.18.0` | HIGH | Symlink Following — SNYK-UPSTREAM-NODE-14928586 |
| `node@22.18.0` | HIGH | Uncaught Exception — SNYK-UPSTREAM-NODE-14929624 |
| `node@22.18.0` | HIGH | Undefined Behavior — SNYK-UPSTREAM-NODE-14975915 |
| `node@22.18.0` | HIGH | Uncaught Exception — SNYK-UPSTREAM-NODE-14982196 |
| `openssl/libssl3` | HIGH | CVE-2025-69421 — introduced via 3.0.17-1~deb12u2, fixed in 3.0.18 |

**Scout vs Snyk comparison:** Scout found significantly more application-level CVEs (118 total including npm deps like `vm2`, `lodash`, `jsonwebtoken`). Snyk scanned at the OS-layer depth, focusing on base image packages (`openssl`, `node` runtime). Both tools complement each other — Scout is better for npm dep analysis, Snyk excels at OS-layer and provides guided remediation paths.


### 1.3 Dockle Configuration Findings

**Scan command:** `dockle --input juice-shop.tar`

| Level | Code | Description |
|---|---|---|
| SKIP | DKL-LI-0001 | Could not detect `/etc/shadow` or `/etc/master.passwd` (non-critical in container context) |
| INFO | CIS-DI-0005 | Content trust not enabled — `DOCKER_CONTENT_TRUST=1` should be set before pull/build |
| INFO | CIS-DI-0006 | No `HEALTHCHECK` instruction in Dockerfile — container has no built-in health monitoring |
| INFO | DKL-LI-0003 | Unnecessary `.DS_Store` files found in `node_modules` (macOS metadata files committed accidentally) |

**Notable result:** No **FATAL** or **WARN** level findings — the image does not run as root in the Dockle tests, and no secrets were detected in environment variables.

**Security Assessment:**
- The image passed all critical Dockle checks (no exposed secrets, no insecure sudo, no sensitive file permission issues)
- Missing `HEALTHCHECK` is a best-practice gap — without it, Docker cannot detect if the app crashes silently inside a running container
- Content trust should be enforced at the pipeline level to ensure image integrity

---

## Task 2: Docker Host Security Benchmarking

### CIS Docker Benchmark Results

**Summary:** 72 checks — 24 PASS, 32 WARN, 0 FAIL, 16 INFO

| Section | PASS | WARN | INFO |
|---|---|---|---|
| 1. Host Configuration | 1 | 8 | 2 |
| 2. Docker Daemon Config | 7 | 11 | 0 |
| 3. Docker Daemon Files | 8 | 0 | 2 |
| 4. Container Images | 1 | 5 | 1 |
| 5. Container Runtime | 5 | 8 | 0 |
| 6. Security Operations | 0 | 0 | 2 |
| 7. Swarm Configuration | 3 | 0 | 0 |

### Analysis of Key Warnings

- **4.1 Running as root:** `juice-default` container runs as root — any container escape grants full host access.
- **4.6 No HEALTHCHECK:** `bkimminich/juice-shop:v19.0.0` has no HEALTHCHECK — Docker cannot detect if the app crashes silently.
- **5.10 Memory not limited:** `juice-default` has no memory cap — allows DoS via resource exhaustion.
- **5.11 CPU not limited:** `juice-default` has no CPU restriction — noisy neighbor risk.
- **5.25 Can acquire new privileges:** `juice-default` allows privilege escalation via SUID binaries.
- **5.28 PID limit not set:** `juice-default` has no PID limit — vulnerable to fork bombs.
- **2.14 Containers not restricted from acquiring new privileges:** Daemon-wide setting not enforced.
- **1.1.1 No separate partition for containers:** All containers share the host filesystem partition.

---

## Task 3: Deployment Security Configuration Analysis

### Configuration Comparison Table (from `docker inspect`)

| Configuration | Default | Hardened | Production |
|---|---|---|---|
| **CapDrop** | None | ALL | ALL |
| **CapAdd** | Default set | None | NET_BIND_SERVICE |
| **SecurityOpt** | None | no-new-privileges | no-new-privileges |
| **Memory Limit** | Unlimited | 512 MiB | 512 MiB |
| **Memory Swap** | Unlimited | Unlimited | 512 MiB (no swap) |
| **CPU** | Unlimited | 1.0 cores | 1.0 cores |
| **PID Limit** | Unlimited | Unlimited | 100 |
| **Restart Policy** | no | no | on-failure:3 |

### Actual Resource Usage (from `docker stats`)

| Container | CPU | Memory Used | Limit |
|---|---|---|---|
| juice-default | 1.50% | 136.3 MiB | Unlimited |
| juice-hardened | 1.49% | 115 MiB | 512 MiB |
| juice-production | 0.54% | 96.45 MiB | 512 MiB |

All three profiles responded: **HTTP 200** — functionality preserved.

### Security Measure Analysis

**a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`**

Linux capabilities are fine-grained permissions that allow non-root processes to perform privileged operations (e.g., `CAP_NET_BIND_SERVICE` = bind to port <1024). Dropping ALL capabilities prevents a compromised container from: changing ownership of files, binding raw sockets (used for network sniffing), loading kernel modules, or bypassing file permissions. `NET_BIND_SERVICE` is added back so the app can bind port 3000 (>1024, so actually unnecessary here, but documents intent). Trade-off: applications requiring specific capabilities must explicitly whitelist them.

**b) `--security-opt=no-new-privileges`**

Prevents the container process from acquiring new capabilities via `setuid`/`setgid` executables (SUID binaries). Without this, a process could execute `su` or other SUID tools to escalate to root. Downside: breaks applications that deliberately use SUID for privilege escalation as a feature.

**c) `--memory=512m` and `--cpus=1.0`**

Without limits, a single compromised or buggy container can consume all host memory/CPU, causing a Denial of Service affecting all other containers — "noisy neighbor" problem. Memory limiting also prevents memory-based exhaustion attacks. Too-low limits may cause OOM kills and application instability.

**d) `--pids-limit=100`**

A fork bomb (`:(){ :|:& };:`) creates processes exponentially until the system freezes. Limiting PIDs to 100 caps the blast radius. Determining the right value: measure normal process count with `docker exec juice-production ps aux | wc -l` and add a 50% buffer.

**e) `--restart=on-failure:3`**

Automatically restarts the container if it exits with a non-zero code, up to 3 times. Beneficial for transient failures (OOM, crashes). Risk: if an attacker can repeatedly crash the container (e.g., via exploit), auto-restart may extend the attack window. `always` would restart even on manual stop — dangerous in incident response.

### Critical Thinking Questions

1. **Development profile:** Default — simpler debugging, no capability restrictions that might break tools.

2. **Production profile:** Production — full hardening (cap drop, PID limits, memory caps, restart policy) provides defense-in-depth without breaking functionality (all showed HTTP 200).

3. **Real-world problem solved by resource limits:** Prevents a single misbehaving or compromised container from starving other containers on a multi-tenant host — critical in Kubernetes shared cluster environments.

4. **Attacker constrained in Production vs Default:**
   - Cannot bind raw sockets (network sniffing blocked by cap-drop)
   - Cannot escalate via SUID executables (no-new-privileges)
   - Cannot fork bomb the host (PID limit 100)
   - Cannot exhaust host memory (512 MiB cap)
   - Cannot run indefinitely after crash (on-failure:3 limits restart loops)

5. **Additional hardening recommendations:**
   - `--read-only` filesystem with tmpfs for writable dirs
   - `--user=1001` to run as non-root
   - Custom seccomp profile restricting syscalls (e.g., block `ptrace`, `mount`)
   - Network policies to restrict container egress
   - Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) for image signing
