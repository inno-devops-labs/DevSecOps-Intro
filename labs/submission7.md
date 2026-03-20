## Lab 7 — Container Security: Image Scanning & Deployment Hardening



## Task 1 — Image Vulnerability & Configuration Analysis

### 1.2 Vulnerability scanning (Docker Scout)

**Docker Scout summary (from `labs/lab7/scanning/scout-cves.txt`):**
- Total vulnerabilities: **11 Critical**, **65 High**, **30 Medium**, **5 Low** (plus additional “?” category)

#### Top 5 Critical/High vulnerabilities (from Docker Scout)

1. **CVE-2026-22709**  
   - **Affected package/version**: `vm2@3.9.17`  
   - **Severity**: Critical (CVSS **9.8**)  
   - **Impact (Scout description)**: Protection Mechanism Failure  
   - **Affected range**: `<=3.10.1`  
   - **Fixed version**: `3.10.2`  

2. **CVE-2023-37903**  
   - **Affected package/version**: `vm2@3.9.17`  
   - **Severity**: Critical (CVSS **9.8**)  
   - **Impact (Scout description)**: Improper Neutralization of Special Elements used in an OS Command (`OS Command Injection`)  
   - **Affected range**: `<=3.9.19`  
   - **Fixed version**: **not fixed** (as reported by Scout)  

3. **CVE-2023-37466**  
   - **Affected package/version**: `vm2@3.9.17`  
   - **Severity**: Critical (CVSS **9.8**)  
   - **Impact (Scout description)**: Improper Control of Generation of Code (`Code Injection`)  
   - **Affected range**: `<=3.9.19`  
   - **Fixed version**: `3.10.0`  

4. **CVE-2023-32314**  
   - **Affected package/version**: `vm2@3.9.17`  
   - **Severity**: Critical (CVSS **9.8**)  
   - **Impact (Scout description)**: Improper Neutralization of Special Elements in Output Used by a Downstream Component (`Injection`)  
   - **Affected range**: `<3.9.18`  
   - **Fixed version**: `3.9.18`  

5. **CVE-2019-10744**  
   - **Affected package/version**: `lodash@2.4.2`  
   - **Severity**: Critical (CVSS **9.1**)  
   - **Impact (Scout description)**: Prototype Pollution (Improperly Controlled Modification of Object Prototype Attributes)  
   - **Affected range**: `<4.17.12`  
   - **Fixed version**: `4.17.12`  

---

### 1.3 Snyk comparison (from `labs/lab7/scanning/snyk-results.txt`)

Snyk reported multiple **high severity** issues and at least one **critical severity** issue while scanning `bkimminich/juice-shop:v19.0.0`.

Notable results:
- **High**: `openssl/libssl3` — **CVE-2025-69421** (fixed in `3.0.18-1~deb12u2`)  
- **Critical** (Snyk): `node@22.18.0` — **Race Condition** (`SNYK-UPSTREAM-NODE-14928492`, fixed in `22.22.0`)  
- Multiple additional **high** upstream issues in `node@22.18.0` (including symlink-following, uncaught exceptions, and undefined behavior)  
- Snyk also produced a **403 Forbidden** error at the end of the run (`SNYK-CLI-0000`), but the vulnerability findings above were still printed and are usable for the lab’s “top vulnerabilities / impact” discussion.

---

### 1.4 Configuration assessment (Dockle) (from `labs/lab7/scanning/dockle-results.txt`)

**FATAL issues (running as root):**
- **None detected** in `dockle-results.txt`

**WARN issues:**
- **None detected** in `dockle-results.txt`

Dockle output mainly contained `SKIP`/`INFO` findings:
- **SKIP (DKL-LI-0001: Avoid empty password)**  
  - Dockle could not detect `/etc/shadow` and `/etc/master.passwd` (`failed to detect etc/shadow,etc/master.passwd`).  
  - **Why this matters**: Dockle could not verify password-related hardening, so the “running as root / empty password” security posture cannot be fully confirmed from this run.
- **INFO (CIS-DI-0006: Add HEALTHCHECK instruction to the container image)**  
  - Result: `not found HEALTHCHECK statement`

- So no FATAL/WARN issues were identified
---

### 1.5 Security posture assessment

**Does the image run as root?**
- Dockle did **not** report any `FATAL`/`WARN` issues related to root execution in this run, so there is **no direct evidence** of a root-related misconfiguration from `dockle-results.txt`.
- However, Dockle also **skipped** checks that rely on traditional password database files (`/etc/shadow`, `/etc/master.passwd`). Because those checks could not run, confirmation of root/non-root execution from Dockle alone is **not definitive**.

**Recommended security improvements**
1. **Run containers as a non-root user** (verify via Dockerfile `USER` and/or `docker inspect` in a real pipeline).
2. **Enable image provenance / content trust** (Dockle suggests `DOCKER_CONTENT_TRUST=1`).
3. **Add a `HEALTHCHECK`** to improve operational security (and detect failing/compromised containers faster).
4. **Reduce attack surface** by removing unnecessary files (e.g., `.DS_Store` artifacts) and updating dependencies/packages flagged by Docker Scout and Snyk.

---

## Task 2 — Docker Host Security Benchmarking (CIS Docker Benchmark)

### 2.1 CIS Docker Benchmark results (from `labs/lab7/hardening/docker-bench-results.txt`)

**Summary statistics:**
- **PASS**: 19
- **WARN**: 24
- **FAIL**: 0
- **INFO**: 90

The benchmark also reported:
- **Checks**: 74
- **Score**: 5

### 2.2 Analysis of failures

There were **no `[FAIL]`** entries in benchmark output. The main areas of concern are the **`[WARN]`** items, which indicate potential hardening gaps.

#### Key WARN findings (and remediation)

1. **Host Configuration**
   - `1.1 Ensure a separate partition for containers has been created` (**WARN**)  
   - **Security impact**: Without separation, container filesystem/bloat or compromise can more easily affect the host.
   - **Remediation**: Use dedicated partitions/LVM for container storage and follow your organization’s standard host hardening baseline.

2. **Docker daemon security**
   - `2.6 Ensure TLS authentication for Docker daemon is configured` (**WARN**)  
   - **Security impact**: Docker daemon control plane on TCP without proper TLS increases attack surface for unauthorized access.
   - **Remediation**: Configure Docker daemon to require TLS/mTLS for remote connections and disable unauthenticated TCP exposure.

3. **Authorization & logging**
   - `2.11 Ensure that authorization for Docker client commands is enabled` (**WARN**)  
   - **Security impact**: Without authorization, authenticated users may have excessive control over Docker resources.
   - **Remediation**: Enable authorization plugins / centralized access control (e.g., authorization layer integrated with IAM).
   - `2.12 Ensure centralized and remote logging is configured` (**WARN**)  
   - **Security impact**: Weak logging reduces detection and incident response capability.
   - **Remediation**: Configure log shipping to a central system (SIEM) with retention and integrity controls.

4. **Networking / privileges**
   - `2.1 Ensure network traffic is restricted between containers on the default bridge` (**WARN**)  
   - **Security impact**: Lateral movement becomes easier if containers can talk freely.
   - **Remediation**: Use user-defined networks and network policies / firewall rules to restrict east-west traffic.
   - `2.18 Ensure containers are restricted from acquiring new privileges` (**WARN**)  
   - **Security impact**: Containers may be able to gain additional privileges if security controls are not enforced.
   - **Remediation**: Enforce `no-new-privileges`, drop capabilities, and consider a custom seccomp/AppArmor profile strategy.

5. **Socket and image hardening**
   - `3.15 Ensure that Docker socket file ownership is set to root:docker` (**WARN**)  
   - **Security impact**: Incorrect socket permissions can allow broader access to the Docker daemon (effectively root).
   - **Remediation**: Fix ownership/permissions on `/var/run/docker.sock` according to the CIS requirement.
   - `4.5 Ensure Content trust for Docker is Enabled` (**WARN**)  
   - **Remediation**: Require content trust in CI/CD and block unsigned/unverified images.
   - `4.6 Ensure HEALTHCHECK instructions have been added` (**WARN**)  
   - **Remediation**: Add explicit health checks in Dockerfiles so orchestrators and monitoring can detect unhealthy behavior.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration comparison table (from `labs/lab7/analysis/deployment-comparison.txt`)

| Profile | Functionality test | Capabilities (drop/add) | Security options | Resource limits (memory/CPU) | PIDs | Restart policy |
|---|---|---|---|---|---|---|
| `juice-default` | HTTP **200** | CapDrop: `<no value>` | `<no value>` | Memory: `15.6GiB`; CPU: `1.37%` | `<no value>` | `no` |
| `juice-hardened` | HTTP **200** | CapDrop: `[ALL]` | `[no-new-privileges]` | Memory: `512MiB`; CPU: `0.59%` | `<no value>` | `no` |
| `juice-production` | HTTP **200** | CapDrop: `[ALL]` | `[no-new-privileges]` | Memory: `512MiB`; CPU: `1.86%` | `100` | `on-failure:3` |


### 3.2 Security measure analysis (explain EACH security flag)

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
Linux capabilities split “root privileges” into smaller privilege subsets that can be granted to processes without giving full root rights.  

- **`--cap-drop=ALL`**: drops all Linux capabilities from the container processes.  
  - **Prevents**: many common escalation steps that rely on privileged kernel features (for example, raw networking, loading kernel modules, altering system time, or performing privileged operations that are restricted to specific capabilities).  
  - **Security goal**: reduce the impact of a container compromise by limiting what system-level actions the attacker can perform from inside the container.
- **`--cap-add=NET_BIND_SERVICE`**: re-adds only the ability to bind to privileged ports (ports < 1024).  
  - **Why it is added**: if the application needs to listen on a low-numbered port, dropping all capabilities can break binding. Adding back only `NET_BIND_SERVICE` keeps the privilege scope minimal.
  - **Trade-off**: preserves application functionality while still reducing the rest of the privilege surface compared to full `CAP_*` sets.

#### b) `--security-opt=no-new-privileges`
`no-new-privileges` prevents processes in the container from gaining additional privileges even if they execute files with setuid/setgid permissions or file capabilities.  

- **Attack type mitigated**: privilege escalation inside the container (e.g., taking advantage of a privileged binary or malicious payload designed to obtain elevated permissions).
- **Downside**: if an application legitimately depends on privilege escalation mechanisms, it may fail. For typical application containers, it is usually a safe hardening default.

#### c) `--memory=512m` and `--cpus=1.0`
Resource limits prevent a compromised container (or a runaway bug) from consuming excessive host resources.

- **If no limits exist**, an attacker can trigger denial-of-service by exhausting memory/CPU:
  - Memory exhaustion can lead to OOM conditions and instability.
  - CPU exhaustion can degrade performance for other workloads.
- **Security benefit**: reduces blast radius (limiting how much resource a single container can consume).
- **Risk**: limits set too low can cause the app to crash or become unstable (availability impact). The correct limit should be sized based on load testing and metrics.

#### d) `--pids-limit=100`
`pids-limit` restricts the number of processes/threads a container can create.

- **Fork bomb**: a fork bomb is a denial-of-service technique that repeatedly spawns new processes until resources are exhausted.
- **How PID limiting helps**: even if an attacker gains code execution, they cannot create unlimited processes/threads, which mitigates fork bombs and similar resource exhaustion attacks.
- **How to pick a number**: measure the maximum number of threads/processes used under peak load and set a conservative upper bound with headroom.

#### e) `--restart=on-failure:3`
`on-failure:3` restarts the container when it exits with a non-zero status, up to three restart attempts.

- **When it helps**: recovery from transient failures (e.g., brief dependency issues) without manual intervention.
- **When it can be risky**: if an attacker intentionally triggers repeated crashes, the restart policy can create restart loops and amplify operational impact (especially if combined with missing health checks).
- **Compare to `always`**:
  - `always` restarts regardless of exit reason, including deliberate/manual stops.
  - `on-failure` is narrower and generally safer for security-focused deployments.

### 3.3 Critical thinking questions

1. **Which profile for DEVELOPMENT? Why?**  
   Use `juice-hardened` for most development testing. It keeps meaningful security controls (capabilities dropped, `no-new-privileges`, memory limit) while still working reliably (HTTP 200 in tests).

2. **Which profile for PRODUCTION? Why?**  
   Use `juice-production`. It adds additional containment and reliability controls: `--pids-limit=100` and `--restart=on-failure:3` on top of the least-privilege settings from `juice-hardened`.

3. **What real-world problem do resource limits solve?**  
   They limit the blast radius of bugs or attacks that cause denial-of-service by consuming CPU, memory, or creating too many processes (e.g., fork bombs).

4. **If an attacker exploits Default vs Production, what actions are blocked in Production?**  
   In `juice-production`, the attacker’s actions are more constrained because:
   - capabilities are dropped (`CapDrop=[ALL]`), reducing privileged kernel actions;
   - `no-new-privileges` blocks certain privilege escalation paths;
   - PID limiting (`PIDs=100`) reduces the ability to spawn process floods;
   - memory limits reduce the ability to exhaust memory and crash the host/workload.

5. **What additional hardening would you add?**  
   Examples:
   - run the container explicitly as a non-root user (`USER` in the Dockerfile);
   - add a custom `seccomp`/AppArmor profile and enforce it consistently in production;
   - ensure `HEALTHCHECK` exists (CIS benchmark warns it is missing);
   - pin and update dependencies to remediate the high/critical CVEs found by Docker Scout and Snyk.

