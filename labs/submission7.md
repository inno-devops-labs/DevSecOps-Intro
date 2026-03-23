## Lab 7 — Container Security: Image Scanning & Deployment Hardening

###  Image Vulnerability and Configuration Review
#### Top 5 Critical and High Vulnerabilities

| CVE ID         | Package  | Severity | Impact Summary                                                                                 |
| -------------- | -------- | -------- | ---------------------------------------------------------------------------------------------- |
| CVE-2023-37903 | vm2      | Critical | Allows RCE inside sandbox environments which means an attacker could run system-level commands |
| CVE-2026-31802 | tar      | High     | Path traversal in archive leading to  files compromise                                         |
| CVE-2021-44906 | minimist | Critical | Argument  injection vulnerability leading to RCE<br>                                           |
| CVE-2024-37890 | ws       | High     | NPD leading to potential DoS from crafted malicious websocket input                            |
| CVE-2019-10744 | lodash   | Critical | Prototype Pollution leading to LPE/DoS                                                         |

Total findins: **118** in 48 packages
- Critical: **11**
- High: **65**
- Medium: **30**
- Low: **5**
- Unspecified: **7**

Most of the serious issues come from outdated Node.js libraries which brings risks like RCE, LPE, and data exposure
The image clearly needs dependency updates and a rebuild to remove the vulnerable versions

#### Dockle Configuration Findings

`Dockle` didn’t show any FATAL or WARN messages, but the INFO and SKIP entries still highlight small gaps:
1. [SKIP] Avoid empty password check:
	- `Dockle` couldn’t find the usual password files so it just skipped this check
2. [INFO] Missing `HEALTHCHECK` instruction:
	- Without a `HEALTHCHECK` Docker can’t detect when the app becomes unhealthy
3. [INFO] Unnecessary files included
	- Some `.DS_Store` files were found which means the image has small hygiene issues and extra weight

Even minor findings show areas for improvement in resilience and image cleanliness

#### Security Posture Summary
Does the container run as root?
- *No, the image uses a non-root user with UID 65532 which is a good security practice*


**Recommended improvements**:
- Keep enforcing non-root execution
- Add a proper `HEALTHCHECK` instruction
- Turn on Docker Content Trust for signature verification
- Update npm dependencies and rebuild the image regularly

This image is not ready for production because of the dependency risks even though the user permissions are configured safely
#### Snyk report
- `Snyk` ran successfully after passing a valid token and reported **47 issues** in **975 dependencies** 
- `Docker Scout` ran successfully after Docker Hub auth and reported `87` total vulnerabilities (`11 Critical`, `65 High`, `30 Medium`, `5 Low`, `7 Unspecified`)
### Docker Host Security Benchmark
#### Summary Table
- `PASS`: 36
- `WARN`: 77
- `INFO`: 104
- `NOTE`: 10
- `FAIL`: 0 in this run

#### Important Benchmark Warnings
- **1.1 — Use a dedicated partition for Docker data**  
    _Impact:_ Storing containers on the root filesystem can lead to disk issues or make privilege escalation easier  
    _Fix:_ Move `/var/lib/docker` to its own partition and apply secure mount settings like `nodev`, `nosuid`, and `noexec`
- **1.5 — Set up auditing for the Docker daemon**  
    _Impact:_ Without audit logs it’s hard to track suspicious Docker actions  
    _Fix:_ Add audit rules for `/usr/bin/dockerd` through `auditctl` or by adding rules under `/etc/audit/rules.d/`
- **2.1 — Limit traffic between containers on the default bridge**  
    _Impact:_ Containers can talk to each other freely which gives attackers room for lateral movement  
    _Fix:_ In `daemon.json`, set `"icc": false` and `"iptables": true` to restrict internal communication
- **2.6 — Enable TLS for Docker daemon communications**  
    _Impact:_ The daemon accepts TCP traffic without encryption which allows spoofing or unauthorized access  
    _Fix:_ Create TLS certificates and set `"tlsverify"`, `"tlscacert"`, `"tlscert"`, and `"tlskey"` in `/etc/docker/daemon.json`
- **2.8 — Turn on user namespaces**  
    _Impact:_ The container shares host UID/GID ranges which can lead to host-level privilege escalation  
    _Fix:_ Add `"userns-remap": "default"` in `daemon.json` and restart Docker
- **2.11 — Enable authorization checks for Docker commands**  
    _Impact:_ Anyone with Docker CLI access can run any command on the daemon  
    _Fix:_ Use an authorization plugin such as `docker-authz` to enforce permission rules
- **2.12 — Configure centralized or remote logging**  
    _Impact:_ Logs stored only locally may be lost or inaccessible during incidents  
    _Fix:_ Use logging drivers like `syslog`, `fluentd`, or `gelf` and forward logs to a remote system
- **2.14 — Enable live restore**  
    _Impact:_ Containers shut down whenever the daemon restarts  
    _Fix:_ Add `"live-restore": true` inside `daemon.json`
- **3.15 — Docker socket should be owned by root:docker**  
    _Impact:_ Incorrect permissions on `/var/run/docker.sock` can let unauthorized users control the Docker API  
    _Fix:_ Run `chown root:docker /var/run/docker.sock` and keep only trusted users in the `docker` group
- **4.5 — Turn on Docker Content Trust**  
    _Impact:_ Images might come from unverified sources which increases supply-chain threats  
    _Fix:_ Enable globally with `export DOCKER_CONTENT_TRUST=1`
- **4.6 — Add HEALTHCHECK instructions**  
    _Impact:_ Without health checks orchestrators cannot automatically detect broken containers  
    _Fix:_ Insert a HEALTHCHECK command into the Dockerfile, for example `curl -f http://localhost:3000 || exit 1`
- **5.1 / 5.2 — AppArmor or SELinux profiles not enabled**  
    _Impact:_ Mandatory access control is not applied which weakens container isolation  
    _Fix:_ Use `--security-opt apparmor=<profile>` or SELinux labels such as `--security-opt label:type:<type>`
- **5.10 / 5.11 — Missing memory and CPU restrictions**  
    _Impact:_ Containers can consume unlimited resources and potentially DOS the host  
    _Fix:_ Run containers with `--memory=<limit>` and `--cpus=<limit>`
- **5.12 — Writable root filesystem**  
    _Impact:_ Attackers or misbehaving processes can modify files inside the container  
    _Fix:_ Run with a read-only root filesystem using the `--read-only` flag
- **5.13 — Ports exposed on 0.0.0.0**  
    _Impact:_ Services become reachable from all interfaces, increasing attack surface  
    _Fix:_ Bind ports to a specific IP using `-p <IP>:<hostPort>:<containerPort>`
- **5.25 — Privilege escalation allowed**  
    _Impact:_ Containers may be able to gain higher privileges at runtime  
    _Fix:_ Use `--security-opt no-new-privileges:true`
- **5.28 — No PIDs limit**  
    _Impact:_ Unlimited process creation could lead to a fork bomb that crashes the host  
    _Fix:_ Apply a PIDs limit such as `--pids-limit=100` depending on workload requirements

### Deployment Security Configuration Analysis

## Collected Evidence

The comparison data for the three deployment setups was saved in:  
`labs/lab7/analysis/deployment-comparison.txt`

**Functional checks:**
- Default: returns HTTP 200
- Hardened: returns HTTP 200
- Production: returns HTTP 200

All setups work correctly from a functional standpoint

| Parameter      | Default (juice-default) | Hardened (juice-hardened) | Production (juice-production) |
| -------------- | ----------------------- | ------------------------- | ----------------------------- |
| CapDrop        | none                    | ALL                       | ALL                           |
| CapAdd         | none                    | none                      | NET_BIND_SERVICE              |
| SecurityOpt    | none                    | no-new-privileges         | no-new-privileges             |
| Memory         | unlimited               | 512m                      | 512m                          |
| Memory Swap    | unlimited               | host default (~1GiB)      | 512m                          |
| CPU            | unlimited               | 1.0                       | 1.0                           |
| PIDs Limit     | none                    | none                      | 100                           |
| Restart Policy | no                      | no                        | on-failure:3                  |

The Hardened and Production profiles introduce strict limits and privilege reductions compared to the Default setup


### Security Measure Analysis

`--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

- Linux capabilities break root access into smaller permission units
- Dropping all capabilities reduces what an attacker can do if the container is compromised
- NET_BIND_SERVICE is added only when the app has to bind to ports below 1024
- The trade-off is tighter security but less flexibility for applications that depend on extra kernel features

`--security-opt=no-new-privileges`

- Ensures that a process inside the container cannot elevate its privileges using setuid/setgid binaries
- Blocks several common escalation paths after initial exploitation
- Software requiring privilege elevation may not work correctly under this setting

`--memory=512m` and `--cpus=1.0`

- Without limits, a single container could exhaust system resources and impact other workloads
- Memory caps reduce the impact of leaks or intentionally heavy workloads
- If limits are too aggressive, the app might hit OOM events or behave inconsistently under load

`--pids-limit=100`

- Protects the host from fork bombs or rapid process spawning that could overwhelm PID availability
- A fixed PID budget keeps each container isolated from system-wide process limits
- The right value depends on normal peak usage with some extra room included

`--restart=on-failure:3`

- Automatically restarts a container up to three times when it exits with a failure code
- Helps stabilize deployments by handling temporary crashes
- Can hide persistent issues if the container loops through repeated crashes
- `on-failure` only retries after errors, while `always` restarts no matter why it exited

### Critical Thinking Answers

**Which profile fits development best and why**

- _Hardened_ is a good balance because it stays close to production while keeping the environment easier to debug

**Which profile should be used in production and why**

- _Production_ because it applies strict least-privilege rules, adds resource limits, PID control, and restart policies for reliability

**What real-world issue do resource limits address**

- They prevent one container from overwhelming the system and creating noisy-neighbor or denial-of-service situations

**If an attacker gains control of a container, what does Production block compared to Default**

- Privilege escalation is restricted by no-new-privileges
- Kernel permission exposure is reduced thanks to dropped capabilities
- Memory, CPU, and PID limits reduce DoS potential
- Restart behavior is controlled by the on-failure policy

**Additional hardening that could be applied**

- Use a read-only root filesystem wherever possible
- Remove all writable mounts unless the app absolutely needs them
- Run as a non-root user and use rootless mode when feasible
- Apply a custom seccomp or AppArmor profile
- Enable image signing policies and enforce signature verification
- Add runtime monitoring and restrict outbound network traffic