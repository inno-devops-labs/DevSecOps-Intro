# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Target Application

- Image: `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### Docker Scout Vulnerability Analysis

Docker Scout was used to scan the OWASP Juice Shop container image for known package vulnerabilities.

Scan summary:
- Critical: **11**
- High: **65**
- Medium: **30**
- Low: **5**
- Unspecified: **7**

The scan detected **48 vulnerable packages** with a total of **118 vulnerabilities**. This indicates a significant supply-chain risk due to outdated and vulnerable dependencies inside the image.

### Top 5 Critical/High Vulnerabilities

| CVE | Package | Severity | Impact |
|-----|---------|----------|--------|
| CVE-2026-22709 | `vm2` 3.9.17 | Critical | Protection mechanism failure with very high impact; may enable sandbox escape / remote code execution scenarios |
| CVE-2023-37903 | `vm2` 3.9.17 | Critical | OS command injection vulnerability |
| CVE-2023-37466 | `vm2` 3.9.17 | Critical | Code injection vulnerability |
| CVE-2025-55130 | `node` 22.18.0 | Critical | Vulnerable Node.js runtime affecting the application platform itself |
| CVE-2019-10744 | `lodash` 2.4.2 | Critical | Prototype pollution vulnerability that can impact application integrity |

Additional notable high-risk packages included:
- `tar`
- `multer`
- `jsonwebtoken`
- `crypto-js`
- `sequelize`
- `ip`

### Snyk Comparison

Snyk was used as an additional scanner to compare results with Docker Scout.  
It identified multiple high and critical vulnerabilities in both OS-level and npm dependencies, including issues in `node`, `vm2`, `multer`, `sequelize`, and `express-jwt`.

Snyk also provided actionable remediation suggestions, such as upgrading:
- `node` to `22.22.0`
- `multer` to `2.1.1`
- `sequelize` to `6.37.8`
- `express-jwt` to `6.0.0`

In general:
- **Docker Scout** is strongly integrated into Docker workflows and is convenient for image and SBOM-oriented vulnerability analysis.
- **Snyk** is useful for broader security platform workflows and policy-driven reporting.
- Both tools are valuable, but Docker Scout already provided enough detailed CVE evidence for this lab.

### Dockle Configuration Findings

Dockle did not report any **FATAL** or **WARN** findings for this image, but it reported several informational issues:

- Docker content trust is not enabled
- No `HEALTHCHECK` instruction is present
- Unnecessary files exist in the image (for example `.DS_Store` files)

These findings still matter because:
- missing **HEALTHCHECK** reduces runtime observability and recovery quality
- missing **content trust** weakens supply-chain assurance
- unnecessary files increase image noise and slightly increase attack surface / maintenance burden

### Security Posture Assessment

The image has a weak security posture from a vulnerability management perspective because it includes many outdated and vulnerable packages.

Assessment:
- The image contains numerous critical/high vulnerabilities
- Dockle did not flag major runtime misconfigurations, but best practices are still missing
- The image would benefit from dependency cleanup and stronger image hardening

Recommended improvements:
- update vulnerable npm and runtime dependencies
- rebuild the image regularly with patched base/runtime layers
- add a `HEALTHCHECK`
- enable content trust / signed image workflows
- remove unnecessary files from build output
- run the container as a non-root user if possible
- minimize package footprint and attack surface

---

## Task 2 — Docker Host Security Benchmarking

### CIS Docker Benchmark Summary

Docker Bench Security results:

- PASS: **40**
- WARN: **82**
- FAIL: **0**
- INFO: **88**

The benchmark completed successfully. No direct `FAIL` findings were reported, but the large number of `WARN` entries shows that the Docker host and running environment still have many hardening gaps.

### Analysis of Warnings

Key warning areas included:

- no separate partition for containers
- auditing not configured for Docker daemon/files
- network traffic on the default bridge not sufficiently restricted
- user namespace support not enabled
- authorization for Docker client commands not enabled
- centralized/remote logging not configured
- live restore not enabled
- userland proxy not disabled
- containers not restricted from acquiring new privileges
- Docker socket ownership issue
- many images missing `HEALTHCHECK`
- some containers running without CPU restrictions
- some containers using writable root filesystems
- wildcard host bindings (`0.0.0.0`)
- no PID limits on several containers
- Docker socket mounted into at least one container

### Security Impact

These warnings matter because they increase the blast radius of compromise and weaken defense in depth. For example:

- missing auditing reduces incident visibility
- lack of user namespaces weakens isolation
- unrestricted host bindings expose services too broadly
- writable root filesystems help persistence after compromise
- missing PID / CPU limits increases denial-of-service risk
- mounting the Docker socket can enable container breakout or host control

### Recommended Remediation Steps

Recommended remediations:
- configure auditing for Docker daemon and critical Docker paths
- enable user namespace remapping
- restrict bridge/container networking more tightly
- enable centralized logging
- enable content trust and healthchecks where possible
- use `no-new-privileges`
- apply CPU, memory, and PID limits consistently
- avoid mounting Docker socket into containers
- bind services to specific interfaces instead of `0.0.0.0`
- consider read-only root filesystems for suitable containers

---

## Task 3 — Deployment Security Configuration Analysis

### Functionality Results

All three profiles were tested for availability:

- Default: **HTTP 200**
- Hardened: **HTTP 200**
- Production: **HTTP 200**

This shows that the hardened runtime settings did not break the application in this environment.

### Resource Usage Summary

Observed memory usage:

- Default: **99.86 MiB / 5.786 GiB**
- Hardened: **92.77 MiB / 512 MiB**
- Production: **91.29 MiB / 512 MiB**

The hardened and production profiles successfully enforced memory limits, while the default profile used the host default limit.

### Configuration Comparison Table

| Profile | Capabilities | Security Options | Memory | CPU | PIDs | Restart Policy |
|--------|--------------|------------------|--------|-----|------|----------------|
| Default | Docker defaults | none | unlimited / host default | none | none | no |
| Hardened | `--cap-drop=ALL` | `no-new-privileges` | 512 MiB | set via `--cpus=1.0` | none | no |
| Production | `--cap-drop=ALL`, `--cap-add=NET_BIND_SERVICE` | `no-new-privileges` | 512 MiB | set via `--cpus=1.0` | 100 | `on-failure` |

### Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities split root privileges into smaller privilege units.  
Dropping all capabilities removes a large set of privileged operations that a compromised process could otherwise abuse.

Security benefit:
- reduces privilege escalation opportunities
- limits post-exploitation actions
- follows least-privilege design

`NET_BIND_SERVICE` is added back only when low-port binding is needed. This is a much safer model than keeping default capabilities.

#### b) `--security-opt=no-new-privileges`

This prevents processes from gaining additional privileges after container start, for example through setuid/setgid binaries.

Security benefit:
- helps stop privilege escalation inside the container
- limits abuse after code execution compromise

Downside:
- some applications that rely on privilege transitions may not work correctly

#### c) `--memory=512m` and `--cpus=1.0`

Without limits, a container can consume excessive host resources and affect availability of other workloads.

Security benefit:
- reduces denial-of-service impact
- contains runaway memory/CPU consumption
- protects multi-container hosts from noisy-neighbor effects

Risk if limits are too low:
- application instability
- restarts
- degraded performance

#### d) `--pids-limit=100`

A fork bomb is an attack or failure mode where processes recursively create more processes until the system becomes unusable.

Security benefit:
- limits process explosion
- reduces host resource exhaustion risk

The correct PID limit depends on the application’s process model and expected concurrency.

#### e) `--restart=on-failure:3`

This restart policy restarts the container only after failure, and only up to a limited number of times.

Security benefit:
- improves resilience during transient failures
- avoids endless restart loops better than `always`

Comparison:
- `on-failure` is safer for crash analysis and controlled recovery
- `always` may hide recurring faults and create restart loops

### Critical Thinking

**Which profile is best for development? Why?**  
The **default** or **hardened** profile is more suitable for development. Default is easiest for debugging, while hardened adds useful protections without too much operational complexity. In practice, hardened is the better security-aware development baseline.

**Which profile is best for production? Why?**  
The **production** profile is the best choice because it applies least privilege, memory limits, PID limits, and restart control. It provides stronger containment if the application is exploited.

**What real-world problem do resource limits solve?**  
They reduce the impact of denial-of-service conditions, runaway processes, memory exhaustion, and unfair resource consumption on shared hosts.

**If an attacker exploits Default vs Production, what actions are blocked in Production?**  
Production better restricts:
- privilege-related operations due to dropped capabilities
- privilege escalation due to `no-new-privileges`
- process explosion due to PID limit
- resource abuse due to memory/CPU constraints
- uncontrolled restart behavior due to limited restart policy

**What additional hardening would you add?**  
Additional recommended hardening:
- run as non-root
- use read-only root filesystem where possible
- add explicit seccomp profile support
- restrict networking further
- add healthchecks
- use signed images / attestations
- reduce package footprint
- mount only required volumes with minimal permissions

### Note on seccomp

The intended production profile originally included an explicit `seccomp=default` setting. In this environment, Docker rejected that literal option and treated it as a missing file path. To complete the deployment comparison successfully, the production profile was re-run without the explicit seccomp flag.

The recommendation remains the same: in a real production environment, Docker’s default seccomp profile or a custom hardened seccomp profile should be enabled.

---

## Conclusion

This lab showed that container security depends on both **image security** and **runtime hardening**.

Key conclusions:
- the Juice Shop image contains a large number of critical/high vulnerabilities
- Docker Bench revealed many host/container hardening warnings even without direct FAIL findings
- runtime hardening flags significantly improve containment without breaking application functionality
- the production-style profile offers the best balance for real deployment security

A secure container deployment should combine:
- regular vulnerability scanning
- host hardening
- strict runtime controls
- least privilege
- resource limits
- secure supply-chain practices
