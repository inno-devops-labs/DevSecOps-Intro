# Container Security: Image Scanning & Deployment Hardening

## Image Vulnerability & Configuration Analysis

### Docker Scout and Snyk Comparison

The OWASP Juice Shop image `bkimminich/juice-shop:v19.0.0` was scanned with Docker Scout and Snyk. Docker Scout reported a broad vulnerability picture across the full image, while Snyk split findings between OS packages and application dependencies.

| Tool | Scope | Summary |
|------|-------|---------|
| Docker Scout | Full image, package inventory, base image lineage | **11 Critical**, **65 High**, **30 Medium**, **5 Low**, **7 unspecified** across **1004 packages** |
| Snyk | OS and application dependency analysis | **6 issues** in OS packages (`deb`) and **47 issues** in application dependencies (`npm`) |

**Observations:**
- **Docker Scout** provides the best high-level image overview. It clearly identified the most exposed packages (`vm2`, `node`, `lodash`, `jsonwebtoken`, `crypto-js`) and showed fix versions where available.
- **Snyk** added value by separating OS-level and application-level findings. It also confirmed that the Node.js dependency tree inside the application remains highly vulnerable.

### Top 5 Critical / High Vulnerabilities

The table below lists the most important vulnerabilities identified from the Scout and Snyk outputs.

| # | Package | CVE | Severity | Impact | Fix / Recommendation |
|---|---------|-----|----------|--------|----------------------|
| 1 | `vm2@3.9.17` | `CVE-2026-22709` | Critical | Sandbox escape / protection mechanism failure with remote code execution potential | Upgrade to `vm2 >= 3.10.2` or replace `vm2` entirely if possible |
| 2 | `vm2@3.9.17` | `CVE-2023-37903` | Critical | OS command injection in the sandbox library; especially dangerous because Juice Shop includes a chat bot using `vm2` | No fixed version listed in Scout for this CVE; remove the vulnerable usage path or replace the library |
| 3 | `node@22.18.0` | `CVE-2025-55130` | Critical | Core runtime vulnerability affecting the whole application process | Rebuild on Node `22.22.0` or newer base image |
| 4 | `lodash@2.4.2` | `CVE-2019-10744` | Critical | Prototype pollution leading to integrity compromise in server-side JavaScript execution paths | Upgrade to `lodash >= 4.17.12`, preferably `4.17.21` |
| 5 | `crypto-js@3.3.0` | `CVE-2023-46233` | Critical | Use of a broken or risky cryptographic algorithm | Upgrade to `crypto-js >= 4.2.0` |

**Additional high-risk findings:**
- `jsonwebtoken@0.1.0` and `jsonwebtoken@0.4.0` are both affected by `CVE-2015-9235` and `CVE-2022-23539`, which can lead to token validation weaknesses and risky cryptographic behaviour.
- Snyk additionally reported a **high-severity OpenSSL issue** in `libssl3` (`CVE-2025-69421`) and multiple **high-severity Node.js issues** fixed in `22.22.0`.

### Dockle Configuration Findings

Dockle did not report any `FATAL` or `WARN` findings for this image. The scan produced only `INFO` items and one `SKIP` line.

| Level | Rule | Finding | Security Concern | Remediation |
|------|------|---------|------------------|-------------|
| INFO | `CIS-DI-0005` | Docker Content Trust not enabled | Unsigned images can be pulled or reused without integrity verification | Enable image signing / trust in CI and release workflows |
| INFO | `CIS-DI-0006` | No `HEALTHCHECK` instruction | Orchestrators and operators cannot detect unhealthy-but-running containers reliably | Add a `HEALTHCHECK` probing application readiness |
| INFO | `DKL-LI-0003` | Unnecessary files found (`.DS_Store`) | Unnecessary files increase image noise and may leak build artefacts | Clean build context and exclude irrelevant files |
| SKIP | `DKL-LI-0001` | Could not inspect password files | Expected for distroless-style images without a full traditional filesystem layout | No direct remediation needed |

### Security Posture Assessment

The image **does not run as root**. `docker image inspect` shows `User="65532"`, which is a non-root runtime user and a positive hardening decision.

**Overall assessment:**
- **Runtime user posture is good** because the container is configured to run as a non-root UID.
- **Dependency posture is weak** because the image contains many outdated and vulnerable runtime dependencies, including multiple critical vulnerabilities in `vm2`, `node`, `lodash`, and `jsonwebtoken`.
- **Image hygiene is acceptable but incomplete** because the image lacks a health check, content-trust workflow, and some unnecessary files are still present.

**Recommended improvements:**
- Rebuild the image on an updated base image containing Node `22.22.0` or later.
- Remove or upgrade `vm2` immediately because it is the single riskiest package in the image.
- Upgrade legacy application dependencies such as `lodash`, `jsonwebtoken`, `crypto-js`, `multer`, and `socket.io`.
- Add a `HEALTHCHECK` instruction.
- Sign images and enforce trusted image provenance in CI/CD.
- Remove unnecessary artefacts from the final runtime image.

## Docker Host Security Benchmarking

### CIS Docker Benchmark Summary

Docker Bench for Security was used as a **host-level** assessment of the local Docker engine. This is important: the benchmark evaluates the Docker host configuration as a whole, not only the Juice Shop image. For the report below, I focus only on the findings that are most relevant for securely deploying `bkimminich/juice-shop:v19.0.0`.

| Result Type | Count |
|------------|------:|
| PASS | 19 |
| WARN | 56 |
| FAIL | 0 |
| INFO | 120 |
| NOTE | 9 |

### Juice Shop-Relevant Findings

The most relevant findings for a secure Juice Shop deployment are the following:

| Control | Finding | Why it matters for Juice Shop | Recommended action |
|---------|---------|-------------------------------|--------------------|
| `2.2` | Network traffic is not restricted between containers on the default bridge | If Juice Shop is deployed alongside other services on the default bridge, lateral movement becomes easier after compromise | Use a dedicated user-defined network and avoid the default bridge for production |
| `2.9` | User namespace support is not enabled | A container breakout would have a larger host impact because container UIDs are not remapped | Enable user namespace remapping where operationally feasible |
| `2.12` | Docker client authorization is not enabled | Anyone with Docker daemon access can control Juice Shop containers and effectively gain host-level power | Restrict Docker group access and use authorization controls where available |
| `2.13` | Centralized / remote logging is not configured | Security incidents affecting Juice Shop would be harder to investigate and retain evidence for | Forward container logs to a central logging backend |
| `2.14` | Containers are not restricted from acquiring new privileges daemon-wide | Juice Shop should be started with stronger runtime privilege restrictions | Use `--security-opt=no-new-privileges` for production deployments |
| `4.5` | Docker Content Trust is not enabled | Pulling unsigned images weakens supply-chain integrity for Juice Shop deployments | Verify image provenance and enforce trusted/signed images in CI/CD |
| `4.6` | Images are missing `HEALTHCHECK` instructions | Juice Shop can appear "running" even when it is unhealthy, reducing operational visibility | Add a `HEALTHCHECK` to the image or enforce external liveness/readiness checks |

### Interpretation for This Lab

- The benchmark confirms that **host-level Docker hardening still matters even when the application image itself is reasonably structured**.
- For Juice Shop specifically, the most actionable takeaways are:
  - use signed / trusted images,
  - avoid the default bridge network,
  - enforce `no-new-privileges`,
  - and ensure the service has proper health monitoring.
- The benchmark also supports the deployment choices made in Task 3: the hardened and production profiles already move in the right direction by using `no-new-privileges` and runtime limits.


## Secure Deployment Configuration Analysis

### Configuration Comparison

All three deployment profiles returned `HTTP 200`, so the added restrictions did not break basic functionality.

| Profile | HTTP | Capabilities | Security Options | Memory | CPU | PIDs | Restart Policy |
|---------|------|--------------|------------------|--------|-----|------|----------------|
| Default | 200 | Default capability set | None explicitly set | Unlimited | Unlimited | Unlimited | `no` |
| Hardened | 200 | `CapDrop=[ALL]` | `no-new-privileges` | `512 MiB` | `1.0 CPU` configured | Unlimited | `no` |
| Production | 200 | `CapDrop=[ALL]`, `CapAdd=[CAP_NET_BIND_SERVICE]` | `no-new-privileges`; default Docker seccomp remained enabled | `512 MiB`, `memory-swap=512 MiB` | `1.0 CPU` configured | `100` | `on-failure` |

**Runtime behaviour:**
- `juice-default` used about `172.9 MiB` with no memory ceiling.
- `juice-hardened` used about `91.86 MiB / 512 MiB`.
- `juice-production` used about `95.93 MiB / 512 MiB`.

On this host, `docker inspect` recorded CPU in a way that did not surface a readable `CpuQuota` value in the saved output, but the containers were launched with `--cpus=1.0` for the hardened and production profiles.

### Security Measure Analysis

#### `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities split the privileges traditionally associated with root into smaller units such as network administration, raw socket access, time changes, or binding privileged ports.

- `--cap-drop=ALL` removes the default capability set from the container, which reduces the impact of a compromise and blocks many post-exploitation actions.
- This prevents attack paths such as tampering with network configuration, abusing raw sockets, or using unnecessary kernel-facing privileges.
- `--cap-add=NET_BIND_SERVICE` adds back only the capability required to bind ports below `1024`.
- In this specific Juice Shop run, the application listens on port `3000`, so the extra capability is not strictly required. However, it demonstrates the least-privilege pattern used for typical production services on ports `80` and `443`.
- The trade-off is compatibility: dropping all capabilities can break software that implicitly expects the default container capability set.

#### `--security-opt=no-new-privileges`

This flag prevents processes inside the container from gaining additional privileges through mechanisms such as `setuid` binaries or file capabilities after execution.

- It helps stop local privilege escalation after initial compromise.
- It is particularly useful when an attacker gains code execution inside the container but still tries to pivot into a more privileged process.
- The downside is that applications relying on `setuid` helpers or privilege-changing binaries may stop working.

#### `--memory=512m` and `--cpus=1.0`

Without resource limits, a single buggy or malicious container can consume excessive CPU time and memory, degrading or denying service to other workloads on the host.

- Memory limits reduce the impact of memory leaks, oversized payload handling, and deliberate memory-exhaustion attacks.
- CPU limits reduce noisy-neighbour behaviour and limit the damage from hot loops or compute-heavy abuse.
- The main risk of setting limits too low is self-inflicted instability: the container may become slow, OOM-killed, or unable to handle legitimate traffic spikes.

#### `--pids-limit=100`

A fork bomb creates large numbers of processes until the host exhausts PID or scheduling resources.

- PID limiting constrains the number of concurrent processes the container can create.
- This directly reduces the blast radius of fork-bomb style denial of service.
- The right value depends on the process model of the application, worker pool size, expected concurrency, and sidecar usage. The limit should be low enough to constrain abuse but high enough not to break normal behaviour.

#### `--restart=on-failure:3`

This restart policy tells Docker to restart the container automatically only when it exits with a failure status, and only up to three times.

- It is beneficial for transient faults such as short-lived crashes after dependency hiccups or startup races.
- It is safer than `always` because it avoids endless restart loops for intentionally stopped containers and reduces the chance of masking persistent failure.
- `always` maximises availability but can make incident diagnosis harder and can repeatedly revive a badly broken container.

### Critical Thinking Questions

#### Which profile is best for development?

The **Default** profile is the most practical choice for development because it minimizes friction during debugging, avoids unexpected behaviour from strict limits, and reflects the broadest compatibility. 

#### Which profile is best for production?

The **Production** profile is clearly the best fit for production because it combines least privilege, resource controls, process-count restriction, and an automatic recovery policy. It meaningfully reduces both exploit impact and accidental service instability.

#### What real-world problem do resource limits solve?

Resource limits solve the **noisy neighbour / runaway process** problem. A compromised or buggy service should not be able to starve the whole host of CPU time, memory, or process slots.

#### If an attacker exploits Default vs Production, what actions are blocked in Production?

Compared with the Default profile, the Production profile makes several attacker actions harder or impossible:

- It blocks use of the default Linux capability set because all capabilities are dropped except one narrowly scoped capability.
- It blocks privilege escalation via `no-new-privileges`.
- It constrains memory exhaustion and CPU abuse with runtime limits.
- It limits process creation with `--pids-limit=100`, reducing fork-bomb style attacks.
- It reduces operational instability by restarting only on controlled failure conditions instead of running unbounded.

#### What additional hardening would improve the production profile?

- Mount the root filesystem as read-only with `--read-only`.
- Use explicit non-root user enforcement in the runtime configuration even though the image already uses UID `65532`.
- Pin the image by digest and enforce signed-image verification.
- Add a `HEALTHCHECK` instruction and integrate runtime monitoring / alerting.
