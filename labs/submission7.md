# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Environment and evidence scope

- Host environment used for this lab: **Windows + Docker Desktop**.
- Target image: **`bkimminich/juice-shop:v19.0.0`**.
- Evidence used in this submission comes from the saved outputs in:
  - `labs/lab7/scanning/`
  - `labs/lab7/hardening/`
  - `labs/lab7/analysis/`

Two execution notes matter for interpreting the results:

1. The captured `docker scout` output is **not a valid CVE report**. The command line was accidentally concatenated, so the saved file contains Scout help text and an argument error instead of vulnerability results.
2. The Snyk run produced usable vulnerability output, but it ended with **`403 Forbidden`** after printing the findings. I therefore use the printed Snyk results as evidence for the vulnerability analysis and explicitly note the Docker Scout limitation instead of inventing missing data.

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Top 5 Critical/High Vulnerabilities

Because the captured Docker Scout report is invalid, the table below is based on the successful portion of the **Snyk** output.

| ID | Package | Severity | Why it matters / potential impact |
|---|---|---:|---|
| `SNYK-UPSTREAM-NODE-14928492` | `node@22.18.0` | Critical | Race-condition bugs in the runtime can break isolation assumptions and may let a malicious request or crafted workload trigger unsafe behavior in the Node.js process. |
| `SNYK-JS-MARSDB-480405` | `marsdb@0.6.11` | Critical | Arbitrary code injection means attacker-controlled input may get executed as application code. In a web application container, this can become full application compromise. |
| `SNYK-JS-VM2-5772823` | `vm2@3.9.17` | Critical | Remote code execution in a sandboxing library is especially dangerous because it defeats the purpose of isolation and can let untrusted code escape the intended sandbox. |
| `SNYK-JS-MULTER-10299078` | `multer@1.4.5-lts.2` | Critical | A critical exception/resource-handling issue in upload processing can be exploited for denial of service or unstable behavior during file upload handling. |
| `CVE-2025-69421` | `openssl/libssl3@3.0.17-1~deb12u2` | High | The OS layer still contains a high-severity OpenSSL issue. Crypto-library flaws are high value because they affect transport security and any TLS-dependent communication. |

### 1.2 Additional notable findings from Snyk

Snyk reported two distinct layers of risk:

1. **OS/package-layer findings**: 6 known issues were reported in 10 OS-level dependencies, including one OpenSSL issue and multiple high/critical Node runtime issues.
2. **Application dependency findings**: 47 issues were reported across 975 npm dependencies. The most important themes were:
   - **RCE / sandbox escape** in `vm2`
   - **Arbitrary code injection** in `marsdb`
   - **High-risk JWT / signature validation issues** in old auth dependencies (`express-jwt`, `jsonwebtoken`, `jws`)
   - **Prototype pollution** in legacy lodash-related dependencies
   - **DoS / resource-exhaustion** issues in `qs`, `socket.io`, `multer`, and `minimatch`

This tells me the image is not only affected by base-image risk; the application dependency graph is also deeply outdated and contains several vulnerabilities with direct exploitability.

### 1.3 Docker Scout comparison

The lab asked for a Docker Scout vs Snyk comparison. In this run, that comparison is limited:

- **Snyk produced actionable vulnerability findings**, including package names, severities, and fixed versions.
- **Docker Scout did not complete successfully** in the captured run, so there is no trustworthy Scout CVE list to compare against.

Because of that, I cannot honestly claim a one-to-one tool comparison from the saved evidence. The correct conclusion is that the Snyk findings are usable, while the Docker Scout command should be rerun before using Scout data in a final tool-comparison discussion.

### 1.4 Dockle Configuration Findings

**FATAL findings:** none reported.

**WARN findings:** none reported.

Even though Dockle did not emit FATAL/WARN in this run, it still reported several meaningful **INFO** findings:

1. **Content trust is not enabled**
   - Why it matters: without content trust, image authenticity is not being verified during pull/build operations. That weakens supply-chain integrity.

2. **No `HEALTHCHECK` instruction**
   - Why it matters: orchestrators and runtime platforms have less reliable information about application health. A broken process may keep running without being detected quickly.

3. **Unnecessary files are present** (`.DS_Store` artifacts)
   - Why it matters: extra files increase image clutter, bloat the image, and indicate weak image hygiene. This is low severity compared with code-execution flaws, but it still reflects weaker build discipline.

4. **`SKIP` on password-file detection**
   - Dockle could not inspect `/etc/shadow` or `/etc/master.passwd`, which is unsurprising for a minimal/distroless-style image and does not by itself prove a password weakness.

### 1.5 Security Posture Assessment

**Does the image run as root?**

From the saved evidence alone, I cannot prove that conclusively. None of the captured outputs includes `Config.User`, and Dockle did not emit a root-user warning in this run. So the honest answer is: **the run does not provide enough evidence to assert root vs non-root execution with certainty**.

**Overall posture**

The image is functionally deployable, but its security posture is weak for production use because:

- Snyk reported multiple **critical** dependency issues.
- The dependency tree is clearly outdated.
- Content trust is disabled.
- The image lacks a health check.
- Build hygiene is imperfect.

**Recommended improvements**

1. Rebuild the image on a fully patched base and update Node.js to a fixed version.
2. Upgrade or replace vulnerable packages such as `vm2`, `multer`, `express-jwt`, `jsonwebtoken`, `socket.io`, and `sequelize`.
3. Remove obsolete dependencies that have no patch path, especially those tied to critical findings.
4. Add a `HEALTHCHECK` instruction.
5. Enable signed image verification / content trust in the build and release pipeline.
6. Explicitly run the container as a non-root user and verify it through image metadata and runtime inspection.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Summary Statistics

From the saved Docker Bench output:

- **PASS:** 19
- **WARN:** 28 warning lines were reported in the output, with the most important actionable warnings concentrated in daemon/network/auth/auditing settings.
- **FAIL:** 0
- **INFO:** many informational lines were emitted, including environment-specific notes such as missing `docker.service`, `daemon.json`, and certificate files.
- **Benchmark summary:** **74 checks**, **score 4**.

A practical interpretation is more useful than raw counts here:

- There were **no explicit FAIL results**.
- There were **many WARN findings**, which means the Docker host/backend is functional but not hardened to CIS-style recommendations.
- Because this lab was run on **Windows + Docker Desktop**, some missing Linux files and service-unit paths are environmental rather than evidence of a broken native Linux host setup.

### 2.2 Most important warnings and their impact

Since there were no `[FAIL]` entries, I analyze the most security-relevant `[WARN]` entries.

#### 1. `1.5` / `1.6` — auditing not configured for Docker daemon and Docker directories

**Why this matters:**
Without auditing, suspicious configuration changes, daemon abuse, or unauthorized access attempts are harder to detect and investigate. This weakens forensic visibility.

**Remediation:**
- Enable OS-level auditing for Docker binaries, configuration files, and storage directories.
- Forward audit events into centralized logging/SIEM.

#### 2. `2.1` — network traffic is not restricted between containers on the default bridge

**Why this matters:**
If an attacker compromises one container, unrestricted east-west traffic makes lateral movement easier.

**Remediation:**
- Avoid the default bridge for sensitive workloads.
- Use user-defined networks, segmentation, and explicit firewall/network-policy controls.

#### 3. `2.6` — Docker daemon listening on TCP without TLS

**Why this matters:**
An unauthenticated or weakly protected Docker API over TCP is extremely dangerous. Docker daemon access is effectively root-equivalent over the container platform.

**Remediation:**
- Disable TCP exposure if it is unnecessary.
- If remote API access is required, enforce mutual TLS authentication and restrict reachable interfaces.

#### 4. `2.8` — user namespace support is not enabled

**Why this matters:**
User namespaces reduce the blast radius of container escapes by remapping container-root to an unprivileged host UID range.

**Remediation:**
- Enable userns remapping where supported by the platform.
- Test compatibility with mounted volumes and existing workflows before rollout.

#### 5. `2.11` — authorization for Docker client commands is not enabled

**Why this matters:**
If any user who reaches the Docker API can issue sensitive commands, the control plane is too permissive.

**Remediation:**
- Restrict Docker group membership.
- Add authorization plugins or tighter access control around the daemon.

#### 6. `2.12` — centralized/remote logging is not configured

**Why this matters:**
Only local logs means easier log loss, weaker incident response, and lower visibility across hosts.

**Remediation:**
- Forward logs to a central logging backend.
- Retain logs with proper rotation and retention policy.

#### 7. `2.14` — live restore is not enabled

**Why this matters:**
Daemon restarts may unnecessarily interrupt running containers.

**Remediation:**
- Enable live restore if the environment supports it and if operational testing confirms safe behavior.

#### 8. `2.15` — userland proxy is not disabled

**Why this matters:**
The userland proxy is not usually the biggest risk, but disabling it can reduce attack surface and simplify packet handling.

**Remediation:**
- Disable userland proxy unless specifically needed.

#### 9. `2.18` — containers are not globally restricted from acquiring new privileges

**Why this matters:**
If workloads do not opt in to `no-new-privileges`, privilege escalation chains become easier after compromise.

**Remediation:**
- Enforce `no-new-privileges` by policy for production containers.
- Reject deployments that omit it when possible.

#### 10. `3.15` — Docker socket ownership is not `root:docker`

**Why this matters:**
The Docker socket is one of the most sensitive objects on the host. Weak ownership or overexposure makes daemon abuse easier.

**Remediation:**
- Correct ownership/permissions on the socket.
- Never mount the socket into ordinary application containers unless absolutely necessary.

#### 11. `4.5` — Content trust disabled

**Why this matters:**
Unsigned image pulls weaken supply-chain integrity.

**Remediation:**
- Enable content trust / artifact signing verification in CI/CD.

#### 12. `4.6` — no health checks in images

**Why this matters:**
Operationally unhealthy containers may remain “running” even when they are no longer serving requests correctly.

**Remediation:**
- Add health checks to images and integrate them with orchestration health policies.

### 2.3 Overall host assessment

The benchmark result is not catastrophic because there are no explicit FAIL entries, but it is also not production-grade hardened. The system is best described as:

- **usable for development / learning**,
- **not fully aligned with CIS-style hardening**,
- **partly influenced by Docker Desktop environment constraints**.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Profile | Capabilities | Security options | Memory | CPU | PIDs | Restart policy |
|---|---|---|---:|---:|---:|---|
| Default | No explicit drops/adds | None | Unlimited (`0`) | Unlimited (`0`) | Not set | `no` |
| Hardened | `CapDrop=["ALL"]`, no added caps | `no-new-privileges` | `512 MiB` | `1 CPU` | Not set | `no` |
| Production | `CapDrop=["ALL"]`, `CapAdd=["CAP_NET_BIND_SERVICE"]` | `no-new-privileges` | `512 MiB` | `1 CPU` | `100` | `on-failure` |

### 3.2 Functionality and resource observations

All three profiles returned **HTTP 200**, so hardening did **not** break the application’s basic functionality.

Resource observations:

- **Default** used about **107.5 MiB** but had effectively **no memory ceiling** from Docker’s point of view.
- **Hardened** used about **91.97 MiB / 512 MiB**.
- **Production** used about **98.36 MiB / 512 MiB**.

This is exactly what I want from hardening: keep the app functional while constraining the damage a compromised container can do.

### 3.3 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**What are Linux capabilities?**
They split the old all-or-nothing root privilege model into smaller privilege units. Instead of giving a process unlimited root power, Linux can grant only specific privileged abilities.

**What does dropping all capabilities do?**
It removes the container’s extra kernel-level privileges beyond normal process behavior. This blocks many post-compromise actions such as reconfiguring networking, loading kernel-related features, or using privileged system operations.

**Why add back `NET_BIND_SERVICE`?**
That capability allows binding to low-numbered ports (<1024). In general, if an app truly needs such a port, this is safer than restoring a broader privilege set.

**Security trade-off**
- Benefit: much smaller privilege surface.
- Cost: some software may fail if it expects capabilities that are no longer present.

#### b) `--security-opt=no-new-privileges`

**What does it do?**
It prevents a process and its children from gaining more privileges than they started with, even through setuid/setgid binaries or similar mechanisms.

**What attack does it help prevent?**
It blocks privilege-escalation chains inside the container after initial code execution.

**Downside**
Some software that relies on privilege escalation helpers may break. In normal web services, that is usually an acceptable trade-off.

#### c) `--memory=512m` and `--cpus=1.0`

**What happens without limits?**
A buggy process, memory leak, or malicious request stream can consume excessive CPU or memory and starve neighboring workloads.

**What attack does memory limiting help prevent?**
Primarily denial of service through memory exhaustion.

**Risk of limits being too low**
The application may become unstable under normal load, be OOM-killed, or throttle too aggressively and degrade user experience.

#### d) `--pids-limit=100`

**What is a fork bomb?**
A fork bomb is a process that rapidly spawns more processes until the system runs out of PIDs or scheduler capacity.

**How does PID limiting help?**
It caps the number of processes the container may create, which limits damage from fork bombs or runaway worker creation.

**How to choose the limit**
Measure normal process count during startup, steady-state load, and peak load, then add reasonable headroom instead of guessing blindly.

#### e) `--restart=on-failure:3`

**What does it do?**
It restarts the container automatically only when it exits with failure, and only up to three times.

**When is it beneficial?**
For transient crashes or short-lived startup failures.

**When is it risky?**
If a service is persistently broken, infinite restart loops can hide the real issue and create operational noise.

**`on-failure` vs `always`**
- `on-failure` is more controlled and safer for debugging repeated crashes.
- `always` is more aggressive and can be useful for essential services, but it may keep restarting unhealthy workloads indefinitely.

### 3.4 Critical Thinking Questions

#### 1. Which profile for DEVELOPMENT? Why?

I would choose **Hardened** for development.

Why?
- It keeps the application working (`HTTP 200`).
- It already enforces the most valuable baseline controls: dropped capabilities, `no-new-privileges`, and resource limits.
- It is less operationally restrictive than the full production profile, so debugging is simpler.

Default is convenient, but it teaches bad habits and hides real production constraints.

#### 2. Which profile for PRODUCTION? Why?

I would choose **Production**.

Why?
- It preserves functionality.
- It has the strongest privilege reduction.
- It adds PID limits and a controlled restart policy.
- It constrains both abuse and accidental overload better than the other two profiles.

#### 3. What real-world problem do resource limits solve?

They prevent one container from degrading the entire host or cluster. In real systems, this matters for:

- memory leaks,
- runaway workers,
- malicious high-load requests,
- noisy-neighbor effects in shared infrastructure.

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

Compared with Default, Production makes several post-exploitation actions harder:

- less ability to abuse Linux capabilities,
- no easy path to gain new privileges,
- limited ability to spawn unbounded processes,
- reduced ability to consume unlimited CPU and memory,
- reduced persistence through controlled restart behavior.

Production does **not** magically prevent application compromise, but it significantly reduces blast radius.

#### 5. What additional hardening would you add?

I would add:

1. Explicit **non-root** user enforcement and verification.
2. A **read-only root filesystem** where possible.
3. `tmpfs` mounts for writable runtime paths only.
4. Removal of Docker socket mounts from non-admin workloads.
5. A custom seccomp/AppArmor profile if platform support allows it.
6. Image signing / verification in CI.
7. Dependency update policy and regular rebuilds.
8. Runtime monitoring, centralized logs, and alerting.
9. Secret injection through a secret manager instead of environment variables or baked-in files.
10. Network segmentation and ingress restrictions.

---

## Final Conclusion

This lab shows three different security layers that all matter:

1. **Image security** — the Juice Shop image contains serious dependency risk, including multiple critical findings from Snyk.
2. **Host security** — the Docker backend is usable but not hardened to CIS-style best practice, with many warnings around auditing, daemon exposure, logging, and privilege controls.
3. **Deployment security** — runtime hardening materially improves safety without breaking the app, and the production profile provides the best balance for a real deployment.

My main conclusion is that container security is not one control but a chain:

- patch the image,
- harden the Docker host/backend,
- constrain the runtime.

If any one of these three is weak, the overall deployment remains exposed.
