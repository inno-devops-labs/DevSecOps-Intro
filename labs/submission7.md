# Lab 7 - Container Security: Image Scanning & Deployment Hardening

## Task 1 - Image Vulnerability and Configuration Analysis

### 1.1 Top 5 Critical/High Vulnerabilities

| CVE ID | Package | Severity | Impact |
|--------|----------|-----------|--------|
| CVE-2023-37903 | vm2@3.9.17 | **Critical (9.8)** | Remote code execution via OS command injection in sandboxed environments; attackers could execute arbitrary system commands. |
| CVE-2019-10744 | lodash@2.4.2 | **Critical (9.1)** | Prototype pollution vulnerability that allows modification of object prototypes, enabling arbitrary code injection. |
| CVE-2015-9235 | jsonwebtoken@0.4.0 | **Critical (9.1)** | Improper input validation allows attackers to forge JWT tokens and bypass authentication. |
| CVE-2023-46233 | crypto-js@3.3.0 | **Critical (9.1)** | Usage of insecure cryptographic algorithm potentially exposing encrypted data to decryption or manipulation. |
| CVE-2021-44906 | minimist@0.2.4 | **Critical (9.8)** | Argument injection vulnerability allowing remote code execution when parsing user input. |

**Summary:**  
Most critical vulnerabilities are found in Node.js libraries (`vm2`, `lodash`, `jsonwebtoken`, `crypto-js`, `minimist`).  
They enable **remote code execution**, **authentication bypass**, and **data leakage** - the most dangerous classes of attacks.  
The image includes multiple outdated packages that have not been patched upstream.

---

### 1.2 Dockle Configuration Findings

**Observed results (Dockle output contains INFO/SKIP, no FATAL/WARN):**

- **[SKIP] DKL-LI-0001: Avoid empty password**  
  → Dockle could not detect expected password files (`/etc/shadow`, `/etc/master.passwd`) in this image layout. This is not a direct vulnerability, but it reduces confidence in account-related checks.

- **[INFO] CIS-DI-0005: Enable Content trust for Docker**  
  → `DOCKER_CONTENT_TRUST=1` is not enabled. Without signature verification, image provenance and integrity checks are weaker (supply-chain risk).

- **[INFO] CIS-DI-0006: Add HEALTHCHECK instruction**  
  → No `HEALTHCHECK` is defined. Runtime platforms cannot reliably detect degraded application state.

- **[INFO] DKL-LI-0003: Only put necessary files**  
  → Unnecessary `.DS_Store` files exist in `node_modules`, indicating image hygiene issues and avoidable bloat.

**Why this matters:**  
Even INFO-level findings indicate hardening gaps. Missing content trust and health checks do not immediately break functionality, but they reduce security assurance and operational resilience.

---

### 1.3 Security Posture Assessment

- **Does the image run as root?**  
  No. The image is configured with non-root user `UID 65532` (`docker image inspect ... .Config.User`). This is a positive least-privilege control and reduces post-exploitation impact.

- **Security Recommendations:**
  1. Keep running as non-root and enforce it in deployment policy (`runAsNonRoot` / equivalent controls).  
  2. Add `HEALTHCHECK` instruction to monitor container liveness.  
  3. Enable Docker Content Trust (`export DOCKER_CONTENT_TRUST=1`) to verify image integrity.  
  4. Rebuild image frequently and update vulnerable npm dependencies.  
  5. Consider additional runtime controls: `--read-only`, seccomp profile, and mandatory resource limits.


Overall, the image has significant dependency risk (multiple Critical/High CVEs).  
Despite a good non-root default, it is **not production-ready** without dependency remediation and stronger runtime hardening.


## 🧱 Task 2 - Docker Host Security Benchmarking

### 2.1 Summary Statistics


| Result Type | Count | Description |
|--------------|--------|-------------|
| PASS | 36 | Security controls properly configured |
| WARN | 52 | Potential misconfigurations requiring review |
| FAIL | 0 | No critical failed controls detected |
| INFO | 95 | Informational checks (not actionable) |



### 2.2 Analysis of Warnings and suggestions


- **No FAIL results** were reported - only Warnings, mostly related to hardening gaps (TLS, user namespaces, resource limits).  
- Overall configuration is functional but lacks production-grade isolation and monitoring settings.


Below are the key **WARN** findings with their security implications and recommended remediations.

1. **1.1 - Ensure a separate partition for containers has been created**  
   *Impact:* Without isolation, container data shares the root filesystem, risking disk exhaustion and privilege escalation.  
   *Remediation:* Mount `/var/lib/docker` on a dedicated partition with restricted mount options (`nodev`, `nosuid`, `noexec`).

2. **1.5 - Ensure auditing is configured for the Docker daemon**  
   *Impact:* Lack of audit logs makes it impossible to trace unauthorized or suspicious Docker operations.  
   *Remediation:* Configure Linux auditing for `/usr/bin/dockerd` and related binaries using `auditctl` or rules in `/etc/audit/rules.d/`.

3. **2.1 - Restrict network traffic between containers on the default bridge**  
   *Impact:* Containers can communicate freely across the bridge, potentially allowing lateral movement if one is compromised.  
   *Remediation:* Edit `daemon.json` and set `"icc": false` and `"iptables": true` to isolate containers by default.

4. **2.6 - Ensure TLS authentication for Docker daemon is configured**  
   *Impact:* The daemon listens over TCP without TLS, allowing possible man-in-the-middle or unauthorized access.  
   *Remediation:* Generate TLS certificates and set `"tlsverify": true`, `"tlscacert"`, `"tlscert"`, and `"tlskey"` in `/etc/docker/daemon.json`.

5. **2.8 - Enable user namespace support**  
   *Impact:* Containers currently share host UID/GID mapping, risking privilege escalation to host-level root.  
   *Remediation:* Add `"userns-remap": "default"` to `daemon.json` and restart Docker.

6. **2.11 - Enable authorization for Docker client commands**  
   *Impact:* Any user with Docker CLI access can control the daemon without access checks.  
   *Remediation:* Deploy Docker authorization plugins (e.g., `docker-authz`) to enforce command-level permissions.

7. **2.12 - Ensure centralized and remote logging is configured**  
   *Impact:* Local-only logs risk loss on host failure and hinder incident response.  
   *Remediation:* Configure `log-driver` as `syslog`, `fluentd`, or `gelf` and forward logs to a remote log collector.

8. **2.14 - Enable live restore**  
   *Impact:* Containers stop when the Docker daemon restarts, reducing availability.  
   *Remediation:* Add `"live-restore": true` in `daemon.json`.

9. **3.15 - Ensure Docker socket file ownership is set to root:docker**  
   *Impact:* Wrong ownership on `/var/run/docker.sock` may let non-Docker users access the API.  
   *Remediation:* Run `chown root:docker /var/run/docker.sock` and ensure only trusted users are in the `docker` group.

10. **4.5 - Enable Docker Content Trust**  
    *Impact:* Images may be pulled from unverified sources, exposing the system to supply-chain attacks.  
    *Remediation:* Enable Docker Content Trust globally: `export DOCKER_CONTENT_TRUST=1`.

11. **4.6 - Add HEALTHCHECK instructions to container images**  
    *Impact:* Without health checks, orchestrators cannot automatically detect unhealthy containers.  
    *Remediation:* Update Dockerfiles to include `HEALTHCHECK CMD curl -f http://localhost:3000 || exit 1`.

12. **5.1 / 5.2 - Missing AppArmor/SELinux security options**  
    *Impact:* Containers lack mandatory access control enforcement, making privilege escalation easier.  
    *Remediation:* Apply AppArmor or SELinux profiles via `--security-opt apparmor=<profile>` or `--security-opt label:type:<type>`.

13. **5.10 / 5.11 - No memory or CPU limits configured**  
    *Impact:* Containers may consume excessive host resources, leading to denial of service.  
    *Remediation:* Start containers with `--memory=<limit>` and `--cpus=<limit>` flags.

14. **5.12 - Container root filesystem not read-only**  
    *Impact:* Writable root FS allows runtime tampering or persistence of malicious changes.  
    *Remediation:* Use `--read-only` flag in `docker run` to enforce immutable filesystem.

15. **5.13 - Ports bound to wildcard interface 0.0.0.0**  
    *Impact:* Services become accessible from all network interfaces, increasing exposure.  
    *Remediation:* Bind services to specific host IPs using `-p <IP>:<hostPort>:<containerPort>`.

16. **5.25 - Privilege escalation not restricted**  
    *Impact:* Containers can gain new privileges during runtime.  
    *Remediation:* Add `--security-opt no-new-privileges:true` when running containers.

17. **5.28 - No PIDs cgroup limit configured**  
    *Impact:* Unbounded process creation (fork bomb) may crash the host.  
    *Remediation:* Use `--pids-limit=100` or appropriate value based on application needs.
##  Task 3 - Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Setting | Default | Hardened | Production |
|----------|----------|-----------|-------------|
| **Capabilities (Drop/Add)** | None / None | ALL / None | ALL / NET_BIND_SERVICE* |
| **Security Options** | None | no-new-privileges | no-new-privileges + seccomp=default* |
| **Memory Limit** | Unlimited | 512 MB | 512 MB |
| **CPU Limit** | Unlimited | Unlimited* | Unlimited* |
| **PIDs Limit** | Unlimited | None | 100 |
| **Restart Policy** | None | None | on-failure:3 |
| **HTTP Status (Test)** | 200 OK | 200 OK | 200 OK |
| **Memory Usage** | 105.4 MiB / 7.6 GiB (1.35%) | 95.24 MiB / 512 MiB (18.6%) | 93.58 MiB / 512 MiB (18.28%) |
| **CPU Usage** | 0.60% | 2.92% | 0.65% |

**\*** `CapAdd` and seccomp are part of the run command for the production profile.  
**\*** On macOS Docker Desktop, CPU quota values can appear as `0` in `docker inspect` because enforcement happens inside the Linux VM layer.
 
All profiles function correctly (HTTP 200), but the Hardened and Production versions apply strict security and resource controls that isolate the container and reduce its ability to impact the host system.  


---

### 3.2 Security Measure Analysis

#### a) --cap-drop=ALL and --cap-add=NET_BIND_SERVICE

**What are Linux capabilities:**  
Linux capabilities are fine-grained privileges that split the all-powerful root permissions into smaller sets (e.g., networking, mounting, process control).  
This lets a process run with only the privileges it truly needs instead of full root access.

**What dropping all capabilities prevents:**  
Dropping `ALL` removes every privileged operation (like changing network interfaces, loading kernel modules, or mounting filesystems).  
It prevents attackers inside the container from performing host-level actions if they exploit the app.

**Why add NET_BIND_SERVICE back:**  
Binding to ports below 1024 (for example, 80/443) requires this capability.  
For Juice Shop on port 3000, it is not strictly required. In real deployments, it is useful when the process must bind directly to privileged ports while still keeping all other capabilities dropped.

**Trade-off:**  
Maximum safety, but debugging or advanced operations (e.g., packet capture) will no longer work inside the container.

---

#### b) --security-opt=no-new-privileges

**Meaning:**  
This flag ensures that processes in the container cannot gain more privileges (e.g., via `setuid` binaries or privilege escalation exploits).

**Prevents:**  
Privilege escalation attacks - for example, if a compromised process tries to become root or execute privileged code.

**Downsides:**  
Almost none in normal workloads. Some legacy apps that depend on `setuid` might not work, but modern applications like Juice Shop run fine.

---

#### c) --memory=512m and --cpus=1.0

**Meaning:**  
These set hard limits on the amount of memory (512 MB) and CPU (1 core) a container can use.

**Without limits:**  
A container could consume all host resources (CPU/memory), crash the host, or cause a denial of service.

**What attack it prevents:**  
Prevents resource exhaustion attacks - for example, if a process creates a memory leak or infinite loop.

**Risk of too low limits:**  
If limits are too strict, the container may crash under normal load (e.g., out-of-memory errors or throttling).

---

#### d) --pids-limit=100

**Meaning:**  
This restricts the number of processes the container can spawn.

**What is a fork bomb:**  
A malicious or buggy program that endlessly spawns new processes until the system runs out of PIDs and becomes unresponsive.

**How PID limit helps:**  
If an attacker tries to create thousands of processes, Docker kills new ones once the limit (100) is reached, protecting the host.

**How to choose a value:**  
Estimate normal process count ×2 for overhead. Web apps usually need fewer than 50 processes.

---

#### e) --restart=on-failure:3

**Meaning:**  
Automatically restarts the container if it crashes (up to 3 times).

**When useful:**  
For production reliability - helps recover from temporary errors.

**When risky:**  
If the container crashes due to a persistent bug, it will restart repeatedly, masking the issue and wasting resources.

**on-failure vs always:**  
`on-failure` restarts only on crashes; `always` restarts even when manually stopped - riskier for debugging or controlled downtime.

---

### 3.3 Critical Thinking Questions

1. **Which profile for DEVELOPMENT?**  
   Default - easier to debug, no resource restrictions, and faster iteration for developers.

2. **Which profile for PRODUCTION?**  
   Production - includes privilege reduction, resource limits, and restart policy, ensuring stable and secure long-term deployment.

3. **What real-world problem do resource limits solve?**  
   They prevent runaway containers from consuming all system resources, protecting the host from denial-of-service or crash loops.

4. **If an attacker exploits Default vs Production, what actions are blocked in Production?**  
   In Production, they cannot gain extra privileges, cannot spawn unlimited processes, cannot fill up system memory, and cannot modify host resources.

5. **What additional hardening would you add?**  
   - Mount filesystem as read-only (`--read-only`)  
   - Use dedicated AppArmor/SELinux profile  
   - Enable Docker Content Trust  
   - Use non-root user (`USER node`) in Dockerfile  
   - Add logging driver for centralized monitoring

