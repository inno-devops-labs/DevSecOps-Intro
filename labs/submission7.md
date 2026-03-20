# Lab 7 - Container Security Analysis

## Scope
- Target image: `bkimminich/juice-shop:v19.0.0`
- Image/configuration tools attempted: `Docker Scout`, `Snyk`, `Dockle`
- Host/deployment tools: `docker-bench-security`, `docker inspect`, `docker stats`

## Task 1 - Image Vulnerability and Configuration Analysis

### Generated Artifacts
- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/snyk-results.txt`
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/scanning/trivy-fallback.json`
- `labs/lab7/scanning/trivy-fallback.txt`
- `labs/lab7/scanning/task1-prereq-notes.txt`
- `labs/lab7/scanning/vuln-reference.txt`

### Tool Availability Notes
- `Docker Scout` ran successfully after Docker Hub authentication and reported `87` total vulnerabilities (`11 Critical`, `65 High`, `30 Medium`, `5 Low`, `7 Unspecified`).
- `Snyk` ran successfully after passing a valid token and reported `53` issues across two projects (`6` issues in the OS/base-image layer and `47` issues in application/npm dependencies).
- On this `arm64` host, `snyk/snyk:docker` also had to run via `linux/amd64` emulation.

### Top 5 Critical/High Vulnerabilities
Primary evidence below comes from `labs/lab7/scanning/scout-cves.txt`. I kept the local Trivy fallback artifacts as supplemental reference only.

| Vulnerability | Package | Severity | Impact |
|---|---|---|---|
| `CVE-2026-22709` | `vm2` | Critical | Sandbox escape/protection failure in a JavaScript VM package can enable remote code execution through crafted input. |
| `CVE-2023-37903` | `vm2` | Critical | OS command injection in the sandbox package allows attacker-controlled commands to escape intended isolation. |
| `CVE-2023-37466` | `vm2` | Critical | Code injection issue in `vm2` weakens sandbox guarantees and can lead to arbitrary code execution. |
| `CVE-2025-55130` | `node` | Critical | Vulnerable Node.js runtime in the base image means even rebuilt app dependencies would still inherit a critical platform issue until the base image is updated. |
| `CVE-2019-10744` | `lodash` | Critical | Prototype pollution in an old `lodash` version can enable logic manipulation and unsafe property injection in affected code paths. |

### Docker Scout vs Snyk Comparison
- `Docker Scout` produced broader package-level CVE coverage for this image: `87` vulnerabilities across `48` vulnerable packages.
- `Snyk` split the result into:
  - OS/base image scan: `6` issues found in `10` dependencies
  - Application/npm scan: `47` issues found in `975` dependencies
- `Snyk` emphasized upgrade paths and grouped findings by dependency tree, for example:
  - `vm2@3.9.17` remote code execution / sandbox bypass
  - `marsdb@0.6.11` arbitrary code injection
  - `multer@1.4.5-lts.2` critical uncaught-exception issue
  - `express-jwt@0.1.3` authorization bypass
  - `sequelize@6.37.7` SQL injection
- Practical takeaway:
  - `Docker Scout` is stronger for quick image-level visibility and base-image/package provenance.
  - `Snyk` is stronger for remediation guidance because it ties issues directly to upgrade targets in the dependency graph.

### Dockle Configuration Findings
Observed output in `labs/lab7/scanning/dockle-results.txt`:
- `WARN/FATAL`: none in this run
- `INFO`:
  - Content trust not enabled (`CIS-DI-0005`)
  - Missing `HEALTHCHECK` (`CIS-DI-0006`)
  - Unnecessary files in the image (`DKL-LI-0003`)

Why these matter:
- No content trust means weaker image provenance assurance.
- No health check reduces detection of unhealthy containers in orchestration/runtime.
- Unnecessary files enlarge attack surface and image noise.

### Security Posture Assessment
- The image does **not** run as root. `docker image inspect` reports `User="65532"`.
- The base image choice is relatively strong (`distroless`), but application/runtime dependencies still contain many critical and high vulnerabilities.
- The image is missing a `HEALTHCHECK`.
- Recommended improvements:
  - add a `HEALTHCHECK`,
  - update the base image/runtime to a patched Node.js release,
  - upgrade or remove high-risk vulnerable packages such as `vm2`, `lodash`, and legacy `jsonwebtoken`,
  - enable signed-image verification/content trust in CI,
  - regularly rebuild against patched dependencies,
  - remove unnecessary leftover files from dependency trees.

## Task 2 - Docker Host Security Benchmarking

### Generated Artifacts
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/hardening/docker-bench-summary.txt`

### Summary Statistics
- `PASS`: 36
- `WARN`: 77
- `INFO`: 104
- `NOTE`: 10
- `FAIL`: 0 in this run

### Important Benchmark Warnings
Representative warnings from `labs/lab7/hardening/docker-bench-results.txt`:
- `1.1` separate partition for containers not created
- `2.6` Docker daemon listening on TCP without TLS
- `2.8` user namespace support not enabled
- `2.12` centralized/remote logging not configured
- `3.15` Docker socket ownership not `root:docker`
- `5.10` default container has no memory limit
- `5.25` default container not restricted with `no-new-privileges`
- `5.26` no runtime health checks on the Juice Shop containers
- `5.28` PIDs limit missing on default and hardened profiles

### Security Impact and Remediation
- TCP Docker API without TLS:
  - Impact: remote daemon control risk if exposed.
  - Fix: disable TCP listener or require mutual TLS.
- No user namespaces:
  - Impact: weaker isolation between container and host identities.
  - Fix: enable user namespace remapping or rootless Docker where possible.
- Missing centralized logging:
  - Impact: poorer incident response and forensic retention.
  - Fix: forward logs to centralized backend.
- Default containers without runtime limits:
  - Impact: easier resource-exhaustion and noisy-neighbor abuse.
  - Fix: set memory, CPU, and PID limits by default.

### Environment Note
- The lab’s original benchmark command mounted all of `/etc` read-only, which failed on this Docker Desktop environment because it conflicted with container-managed `/etc/hostname`.
- I adjusted the benchmark run to mount the specific paths the tool actually needs (`/etc/docker`, `/etc/default`, `/etc/systemd/system`, `/usr/lib/systemd/system`, `/etc/audit`) and the benchmark completed successfully.

## Task 3 - Deployment Security Configuration Analysis

### Generated Artifact
- `labs/lab7/analysis/deployment-comparison.txt`

### Functional Result
All three profiles responded successfully:
- Default: `HTTP 200`
- Hardened: `HTTP 200`
- Production: `HTTP 200`

### Configuration Comparison Table
| Profile | Capabilities | Security options | Memory | CPU | PIDs | Restart |
|---|---|---|---|---|---:|---|
| Default | none dropped, none added | none | unlimited | unlimited | unset | `no` |
| Hardened | `CapDrop=[ALL]` | `no-new-privileges` | `512MiB` | `1.0 CPU` (`NanoCpus=1000000000`) | unset | `no` |
| Production | `CapDrop=[ALL]`, `CapAdd=[CAP_NET_BIND_SERVICE]` | `no-new-privileges` | `512MiB`, no extra swap (`MemorySwap=512MiB`) | `1.0 CPU` (`NanoCpus=1000000000`) | `100` | `on-failure:3` |

### Security Measure Analysis
`--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
- Linux capabilities split root privileges into smaller units.
- Dropping all capabilities removes many kernel-level actions an exploited process could otherwise perform.
- `NET_BIND_SERVICE` is only needed for binding privileged ports below `1024`.
- For Juice Shop specifically, the app listens on `3000`, so adding `NET_BIND_SERVICE` is not actually necessary here.
- Trade-off: least privilege is better; adding back capabilities should be justified by the app’s real needs.

`--security-opt=no-new-privileges`
- Prevents processes from gaining more privileges via setuid/setgid binaries or file capabilities.
- It helps block privilege-escalation chains after an application compromise.
- Downside: workloads that rely on privileged helper binaries may break.

`--memory=512m` and `--cpus=1.0`
- Without limits, one compromised or buggy container can consume disproportionate host resources.
- Memory limits help contain memory exhaustion and denial-of-service conditions.
- CPU limits reduce host starvation from runaway processes.
- If limits are too low, the app can be throttled or OOM-killed under normal load.

`--pids-limit=100`
- A fork bomb is a process explosion that rapidly consumes PID space and host resources.
- PID limiting constrains how many processes a container may create.
- The right limit depends on observing normal workload behavior plus a safety margin.

`--restart=on-failure:3`
- Restarts the container only when it exits with a failure, up to 3 attempts.
- Good for transient crashes and short-lived failures.
- Risk: repeated restarts can hide the root cause and create noisy crash loops.
- `on-failure` is safer than `always` for avoiding endless restart behavior after intentional stops or persistent bad states.

### Critical Thinking Answers
1. Development profile:
`Default` or `Hardened`, depending on debugging needs. For local debugging, `Default` is simpler. For shared dev/staging, `Hardened` is better because it adds meaningful restrictions without making the app fail.

2. Production profile:
`Production`, but with one change: remove unnecessary `CAP_NET_BIND_SERVICE`. It has the strongest practical hardening in this lab while remaining functional.

3. Real-world problem solved by resource limits:
They prevent single-container resource exhaustion from degrading the whole host or cluster.

4. If an attacker exploits Default vs Production:
Production blocks or limits several follow-on actions:
- no broad Linux capabilities,
- no privilege escalation via `no-new-privileges`,
- restricted process count,
- bounded memory/CPU use,
- limited automatic restart behavior.

5. Additional hardening to add:
- make root filesystem read-only,
- bind ports to `127.0.0.1` or front with a reverse proxy,
- add a health check,
- apply custom seccomp/AppArmor profiles,
- use user-namespace remapping/rootless Docker where possible,
- manage secrets outside environment/build artifacts.

## Conclusion
- Tasks 2 and 3 were completed fully with real outputs.
- Task 1 is now completed with real `Docker Scout`, `Snyk`, and `Dockle` outputs.
- The retained `Trivy` fallback artifacts are supplemental only and were not needed once authenticated scans succeeded.
