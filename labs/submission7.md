# Lab 7 Submission — Container Security Analysis

**Student:** Maria Nikolashina  
**Date:** March 15, 2026

**Evidence used:** `labs/lab7/scanning/scout-cves.txt`, `labs/lab7/scanning/snyk-results.txt`, `labs/lab7/scanning/dockle-results.txt`, `labs/lab7/hardening/docker-bench-results.txt`, and `labs/lab7/analysis/deployment-comparison.txt`.

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Scanner Summary

**Docker Scout**

- Image: `bkimminich/juice-shop:v19.0.0`
- Platform: `linux/arm64`
- Packages analyzed: `1004`
- Vulnerabilities: `11 Critical`, `64 High`, `31 Medium`, `5 Low`, `7 unspecified`
- Total reported: `118 vulnerabilities in 49 packages`

**Snyk**

- OS package scan: `6 issues` across `10` dependencies
- Application dependency scan: `46 issues` across `975` dependencies
- High/critical issues were concentrated in `node`, `vm2`, `lodash`, `jsonwebtoken`, `multer`, `sequelize`, `tar`, and related transitive packages

**Comparison**

- **Docker Scout** gave the clearest package-by-package CVE inventory and severity totals.
- **Snyk** added stronger remediation guidance, grouped findings by upgrade path, and separated OS-level issues from JavaScript dependency issues.
- The two tools broadly agreed that the image has a serious dependency risk profile and should not be treated as production-ready without rebuilds and upgrades.

### 1.2 Top 5 Critical/High Vulnerabilities

| CVE ID | Package | Severity | Why it matters |
|--------|---------|----------|----------------|
| **CVE-2026-22709** | `vm2@3.9.17` | Critical | Sandbox protection failure. A breakout from `vm2` can become remote code execution in the application context. |
| **CVE-2025-55130** | `node@22.18.0` | Critical | Core runtime race condition in Node.js. A runtime-level bug is high impact because it affects the main process rather than a narrow optional feature. |
| **CVE-2019-10744** | `lodash@2.4.2` | Critical | Prototype pollution. Attackers can tamper with object behavior and sometimes pivot into application logic abuse or code execution chains. |
| **CVE-2015-9235** | `jsonwebtoken@0.1.0` / `0.4.0` | Critical | Improper JWT validation. This class of issue can allow forged tokens or authentication bypass. |
| **CVE-2023-46233** | `crypto-js@3.3.0` | Critical | Broken or risky cryptographic behavior. Weak crypto libraries undermine token integrity and data protection guarantees. |

**Other high-signal findings**

- `sequelize@6.37.7` high-severity SQL injection issue
- `ip@2.0.1` high-severity SSRF issue
- `glob`, `tar`, `minimatch`, and `multer` high-severity command injection, path traversal, ReDoS, and resource exhaustion issues

### 1.3 Dockle Configuration Findings

Dockle did **not** report any `FATAL` or `WARN` findings in this run. It reported:

- `CIS-DI-0005` `INFO` — Docker Content Trust is not enabled
- `CIS-DI-0006` `INFO` — the image has no `HEALTHCHECK`
- `DKL-LI-0003` `INFO` — unnecessary files were found, including `.DS_Store` files in dependencies
- `DKL-LI-0001` `SKIP` — empty password check could not inspect `/etc/shadow` or `/etc/master.passwd`

**Why these findings matter**

- **Content Trust disabled:** image origin and integrity are not cryptographically verified during pull or deployment.
- **No HEALTHCHECK:** orchestrators and operators have less visibility into application liveness. A broken process can stay “running” while serving bad responses.
- **Unnecessary files in the image:** extra files increase image size, can leak development metadata, and widen the attack surface slightly.
- **Skipped password-file check:** this is expected on minimal or distroless-style images and is not automatically a security problem.

### 1.4 Security Posture Assessment

**Does the image run as root?**

No. Local image metadata shows `Config.User = "65532"`, so the container runs as a non-root user by default. That is a positive baseline control.

**Other posture observations**

- Exposes port `3000/tcp`
- No `HEALTHCHECK` defined
- Snyk identifies the target OS as `Distroless`, which reduces package surface but does not remove application dependency risk
- The dominant risk is **outdated application dependencies**, not root execution

**Recommended improvements**

1. Rebuild on a patched Node.js version (`22.22.0` or later according to scanner output).
2. Upgrade or replace critical libraries such as `vm2`, `jsonwebtoken`, `lodash`, `crypto-js`, `sequelize`, `multer`, and `tar`.
3. Add a `HEALTHCHECK` to support reliable runtime monitoring.
4. Remove unnecessary files from the image during build.
5. Sign and verify images in CI/CD using Docker Content Trust, Cosign, or equivalent signing controls.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 CIS Docker Benchmark Summary

From `labs/lab7/hardening/docker-bench-results.txt`:

| Result | Count |
|--------|------:|
| **PASS** | 23 |
| **WARN** | 102 |
| **FAIL** | 0 |
| **INFO** | 165 |
| **NOTE** | 7 |

**Interpretation**

- There were **no explicit FAIL results** in this run.
- The output is still security-relevant because it contains a large number of **WARN** findings.
- This benchmark was executed on a macOS Docker/OrbStack-style environment, so some checks are noisy or Linux-host-specific. That matters when interpreting systemd-, auditd-, or daemon-path-related messages.

### 2.2 Highest-Impact Warnings

**1. Docker auditing not configured**

- Examples: checks `1.5`, `1.6`, `1.7`, `1.11`
- **Impact:** actions against the Docker daemon and key Docker paths may not be captured for incident response or forensic review.
- **Remediation:** enable audit rules for the Docker daemon, `/var/lib/docker`, `/etc/docker`, and `daemon.json`.

**2. Docker daemon TLS not configured**

- Example: check `2.6`
- **Impact:** if the daemon is reachable over TCP without strong authentication, an attacker could control containers remotely.
- **Remediation:** disable unauthenticated TCP listeners or require mutual TLS for daemon access.

**3. User namespaces not enabled**

- Example: check `2.8`
- **Impact:** container root maps more directly to host privileges, increasing the impact of a container breakout.
- **Remediation:** enable `userns-remap` where compatible with the workload.

**4. No authorization plugin / no centralized logging / live restore disabled**

- Examples: checks `2.11`, `2.12`, `2.14`
- **Impact:** weaker access control for Docker API actions, weaker operational visibility, and more fragile daemon restarts.
- **Remediation:** configure an authorization plugin, use a central logging backend, and enable `"live-restore": true` where supported.

**5. Userland proxy and privilege defaults**

- Examples: checks `2.15`, `2.18`
- **Impact:** broader network exposure and weaker default runtime hardening.
- **Remediation:** disable the userland proxy if not needed and enforce `no-new-privileges` by default in runtime policy.

**6. Docker socket ownership warning**

- Example: check `3.15`
- **Impact:** incorrect ownership or overly broad access to `docker.sock` can effectively grant root-equivalent control over the host.
- **Remediation:** restrict socket ownership and access to trusted administrators only.

**7. Content trust and healthcheck warnings**

- Examples: checks `4.5`, `4.6`
- **Impact:** unsigned images are easier to tamper with, and missing healthchecks reduce runtime resilience.
- **Remediation:** require signed images and add `HEALTHCHECK` to maintained images.

### 2.3 Overall Assessment

The benchmark does not show a catastrophic misconfiguration, but it does show that the host is not hardened to a strong CIS-aligned baseline. The most important gaps are around **auditability**, **daemon exposure**, **namespace isolation**, **authorization**, and **secure operational defaults**.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Functional Comparison

All three deployment profiles remained functional:

| Profile | HTTP Result | Memory Usage |
|---------|-------------|--------------|
| **Default** | `200` | `97.72 MiB / 5.126 GiB` |
| **Hardened** | `200` | `81.56 MiB / 512 MiB` |
| **Production** | `200` | `84.55 MiB / 512 MiB` |

This shows that the added hardening did **not** break the application in this lab.

### 3.2 Configuration Comparison Table

The table below combines the saved inspect output in `deployment-comparison.txt` with the launch flags used in the lab commands. This is necessary because the saved inspect snippet did not print every field needed for comparison.

| Control | Default | Hardened | Production |
|---------|---------|----------|------------|
| **Capabilities dropped** | None shown | `ALL` | `ALL` |
| **Capabilities added** | None | None | `NET_BIND_SERVICE` configured |
| **Security options** | None shown | `no-new-privileges` | `no-new-privileges:true` |
| **Memory limit** | None | `512 MiB` | `512 MiB` |
| **Memory swap limit** | None | None | `512 MiB` |
| **CPU limit** | None | `--cpus=1.0` configured | `--cpus=1.0` configured |
| **PID limit** | None | None | `100` |
| **Restart policy** | `no` | `no` | `on-failure:3` |

**Note on CPU output**

The saved inspect output showed `CPU: 0` because the template printed `CpuQuota`, which did not reflect the `--cpus=1.0` flag in this environment. The launch commands still show that CPU limits were intended for Hardened and Production.

### 3.3 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities break root privileges into smaller units. Dropping all capabilities removes broad privileged actions such as raw socket access, kernel module operations, and privileged network controls.

**Security value**

- Reduces the blast radius after code execution inside the container
- Blocks many post-exploitation actions that rely on ambient Linux capabilities

**Why add back `NET_BIND_SERVICE`?**

- This capability is only needed to bind to privileged ports below `1024`
- In this lab, Juice Shop listens on port `3000`, so `NET_BIND_SERVICE` is not actually required

**Trade-off**

- `cap-drop=ALL` is a strong default
- adding back only what is truly needed is the least-privilege model
- in this specific case, keeping `NET_BIND_SERVICE` is slightly more permissive than necessary

#### b) `--security-opt=no-new-privileges`

This flag prevents the process and its children from gaining more privileges than they started with, even if a setuid binary or similar mechanism is present.

**Security value**

- Helps block privilege escalation after initial compromise
- Limits abuse of setuid/setgid binaries inside the container

**Downside**

- Some legacy software that depends on privilege elevation may stop working
- For modern application containers, that is usually an acceptable trade-off

#### c) `--memory=512m` and `--cpus=1.0`

Without limits, a container can consume excessive RAM or CPU and starve neighboring workloads or the host itself.

**Security value**

- Mitigates resource exhaustion and some denial-of-service scenarios
- Improves multi-tenant stability by containing “noisy neighbor” behavior

**Risk of limits that are too low**

- Legitimate traffic spikes can cause slow responses, OOM kills, or restarts
- Limits must be based on measured workload behavior, not guesswork alone

#### d) `--pids-limit=100`

A fork bomb is a malicious or buggy process pattern that rapidly spawns child processes until the system runs out of PIDs or scheduler capacity.

**Security value**

- Prevents a compromised container from creating unbounded processes
- Reduces the impact of process-based denial-of-service attacks

**How to choose a limit**

- Measure normal process count during startup and peak load
- Leave a safe buffer for worker processes and diagnostics
- Keep the cap low enough to block abuse, but high enough to avoid false kills

#### e) `--restart=on-failure:3`

This policy restarts the container automatically when it exits with failure, but only up to three times.

**When it helps**

- transient crashes
- temporary dependency issues
- short-lived operational failures

**When it becomes risky**

- repeated crashes can hide root causes if operators only notice the restart loop
- an exploited container may repeatedly relaunch if the underlying issue is not fixed

**`on-failure` vs `always`**

- `on-failure` is safer for controlled recovery because it does not restart clean manual stops indefinitely
- `always` improves availability, but it can also make bad states persist longer and complicate debugging

### 3.4 Critical Thinking Answers

**1. Which profile for development? Why?**

I would use **Hardened** for development. It keeps the application functional while introducing least-privilege and resource-control habits early. Default is easier, but it normalizes insecure behavior and hides issues that only appear under realistic runtime limits.

**2. Which profile for production? Why?**

I would use **Production**, but I would remove the unnecessary `NET_BIND_SERVICE` capability because Juice Shop listens on port `3000`. Production is the best fit because it combines least privilege, resource limits, PID limits, and restart behavior.

**3. What real-world problem do resource limits solve?**

They prevent one compromised or buggy container from exhausting CPU, RAM, or process slots and degrading the whole host. In real environments this protects service availability during traffic spikes, memory leaks, fork bombs, and abusive requests.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**

Production blocks or constrains several common post-exploitation moves:

- gaining extra privileges through setuid-style escalation
- abusing ambient Linux capabilities
- exhausting memory or CPU without bounds
- spawning unlimited child processes
- remaining down indefinitely after a transient crash because restart policy provides limited recovery

It does **not** make the application safe by itself. A code execution bug inside the app is still serious, but the surrounding container is harder to abuse.

**5. What additional hardening would you add?**

- Read-only root filesystem
- Explicit seccomp profile
- AppArmor/SELinux profile where supported
- `--tmpfs` for writable temp paths
- non-default network segmentation
- image signing and admission policy
- vulnerability gating in CI before deployment

---

## Conclusion

Lab 7 shows that container security is layered:

- The Juice Shop image already avoids one major problem by running as a non-root user.
- That is not enough, because both Docker Scout and Snyk still show a large set of critical and high-risk dependencies.
- Host-level CIS benchmarking shows operational hardening gaps around auditing, daemon exposure, isolation, and logging.
- Runtime hardening flags materially improve containment without breaking application availability in this lab.

The strongest overall approach is: **patch the image**, **sign and verify it**, **harden the Docker host**, and **run the container with least privilege plus resource controls**.

---

## Acceptance Criteria Check

**Satisfied in the current workspace**

- [x] Branch `feature/lab7` exists
- [x] Vulnerability scanning completed with Docker Scout
- [x] CIS Docker Benchmark audit completed
- [x] Deployment security comparison completed
- [x] All scan outputs exist under `labs/lab7/`
- [x] `labs/submission7.md` now contains required analysis for Tasks 1-3

**Not yet satisfied from current git state**

- [ ] Lab 7 files are committed
- [ ] PR from `feature/lab7` to the course repo main branch is open
- [ ] PR link submitted via Moodle
