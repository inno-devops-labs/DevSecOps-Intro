# Lab 7 — Container Security: Image Scanning & Deployment Hardening

> **Student:** ellilin
> **Branch:** feature/lab7
> **Date:** 2026-03-22
> **Environment:** macOS + Docker Desktop 4.45.0 (`docker` 28.3.3, engine `linux/arm64`)

---

## Executive Summary

This lab assessed the OWASP Juice Shop image `bkimminich/juice-shop:v19.0.0` from three angles:

- **Image vulnerability scanning:** Docker Scout found **118 vulnerabilities in 48 packages**: **11 Critical, 65 High, 30 Medium, 5 Low, 7 Unspecified**.
- **Image configuration review:** Dockle found **no FATAL/WARN issues**, but it did report missing **content trust**, missing **HEALTHCHECK**, and unnecessary `.DS_Store` files in the image.
- **Deployment hardening:** all three deployment profiles remained functional (`HTTP 200`), while the hardened and production profiles added meaningful restrictions on capabilities, privileges, memory, CPU, PIDs, and restart behavior.

Two environment-specific adjustments were necessary:

1. **Docker Bench**: the containerized invocation from the lab failed on Docker Desktop/macOS due mount/runtime differences, so I used the upstream project’s **host script** instead.
2. **Seccomp**: the literal lab flag `--security-opt=seccomp=default` is not valid on this Docker version. I applied Docker’s **official default seccomp profile JSON** explicitly, which enforces the intended default seccomp policy.

Artifacts are stored under `labs/lab7/`:

- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/scanning/snyk-results.txt`
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/hardening/docker-bench-results-clean.txt`
- `labs/lab7/analysis/deployment-comparison.txt`
- `labs/lab7/analysis/image-user.txt`
- `labs/lab7/analysis/cpu-details.txt`
- `labs/lab7/analysis/seccomp-default.json`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Docker Scout Results

**Target:** `bkimminich/juice-shop:v19.0.0`  
**Base image:** `gcr.io/distroless/nodejs22-debian12:latest`  
**Packages indexed:** `1004`

| Severity | Count |
|----------|------:|
| Critical | 11 |
| High | 65 |
| Medium | 30 |
| Low | 5 |
| Unspecified | 7 |
| **Total** | **118** |

### 1.2 Top 5 Critical/High Vulnerabilities

| CVE | Package | Severity | Why it matters |
|-----|---------|----------|----------------|
| CVE-2026-22709 | `vm2@3.9.17` | Critical | Sandbox escape / protection failure in a JavaScript sandbox dependency. If reachable by attacker-controlled input, this can turn "sandboxed" code execution into full application compromise. |
| CVE-2023-37903 | `vm2@3.9.17` | Critical | OS command injection in `vm2`. This is especially dangerous because sandbox libraries are often trusted as a security boundary. |
| CVE-2025-55130 | `node@22.18.0` | Critical | Vulnerability in the Node.js runtime shipped by the image base. Runtime-level flaws affect every application process in the container, not just one library. |
| CVE-2019-10744 | `lodash@2.4.2` | Critical | Prototype pollution in an old `lodash` release. This can corrupt application object behavior and sometimes lead to authorization bypasses or code execution chains. |
| CVE-2023-46233 | `crypto-js@3.3.0` | Critical | Risky / broken cryptographic behavior in a crypto library dependency. Weak crypto primitives can undermine token, password, or integrity protections. |

Other notable high-risk packages included `jsonwebtoken`, `minimist`, `tar`, `socket.io-parser`, `sequelize`, `ws`, `glob`, and `ip`.

### 1.3 Snyk Comparison

I attempted the lab’s Snyk comparison in two stages:

1. Native `linux/arm64` run of `snyk/snyk:docker`
2. Fallback run with `--platform linux/amd64`

Results:

- The native run failed because the published `snyk/snyk:docker` image did not provide a matching `linux/arm64` manifest in this environment.
- The emulated `linux/amd64` run started successfully, but Snyk then returned **`401 Unauthorized`** because no valid `SNYK_TOKEN` was configured.

So:

- **Docker Scout comparison data is complete**
- **Snyk comparison is attempted and evidenced, but not fully executable without Snyk credentials**

Evidence: `labs/lab7/scanning/snyk-results.txt`

### 1.4 Dockle Configuration Findings

Dockle produced **no FATAL or WARN findings** for this image. It reported the following informational issues:

| Check | Level | Finding | Why it matters |
|-------|-------|---------|----------------|
| `CIS-DI-0005` | INFO | Docker Content Trust not enabled | Unsigned pulls reduce supply-chain assurance and make tampering or registry-side substitution harder to detect. |
| `CIS-DI-0006` | INFO | No `HEALTHCHECK` instruction | Orchestrators and operators lack a built-in liveness signal, which delays failure detection and auto-recovery. |
| `DKL-LI-0003` | INFO | Unnecessary `.DS_Store` files inside `node_modules` | Extra files increase image noise and indicate build hygiene issues; not critical alone, but they should not ship in production artifacts. |
| `DKL-LI-0001` | SKIP | Could not inspect `/etc/shadow` / `master.passwd` | This was a scanner limitation for the image layout, not evidence of a password weakness. |

### 1.5 Security Posture Assessment

**Does the image run as root?**  
No. `docker inspect` shows the image runs as user **`65532`**, so the image already avoids the most obvious "run as root" anti-pattern.

**Overall assessment:**  
Runtime user configuration is better than expected, but the package security posture is weak. The dominant risk is not root execution, but the large number of outdated high-risk dependencies inside the application layer.

**Recommended improvements:**

- Rebuild the image after upgrading vulnerable application dependencies, especially `vm2`, `lodash`, `jsonwebtoken`, `tar`, `socket.io`, `ws`, and the Node.js runtime.
- Add a `HEALTHCHECK` instruction.
- Enable image signing / verification (`DOCKER_CONTENT_TRUST`, Sigstore/Cosign, or equivalent).
- Remove accidental development artifacts such as `.DS_Store`.
- Pin the base image by digest and rebuild regularly.
- Keep the non-root user, and combine it with hardened runtime flags such as `no-new-privileges`, seccomp, read-only root filesystem, and resource limits.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Execution Notes

The containerized `docker/docker-bench-security` invocation from the lab handout failed on Docker Desktop/macOS because its Linux-oriented mount assumptions conflicted with Docker Desktop’s runtime behavior. The upstream project README explicitly calls out special macOS handling and also documents a **host-script** execution path.

I therefore ran the upstream benchmark script locally from a cloned copy of `docker/docker-bench-security`, which successfully produced benchmark output against the local Docker daemon.

### 2.2 Summary Statistics

Counts from `labs/lab7/hardening/docker-bench-results-clean.txt`:

| Result | Count |
|--------|------:|
| PASS | 18 |
| WARN | 21 |
| FAIL | 0 |
| INFO | 104 |
| NOTE | 9 |

The benchmark did **not** produce any explicit `[FAIL]` results in this environment. It produced many `[WARN]` and `[INFO]` findings, with several host checks partially degraded by the fact that this is Docker Desktop on macOS rather than a native Linux host.

### 2.3 Analysis of Warnings

Most relevant warnings:

| Check | Warning | Security impact | Remediation |
|-------|---------|-----------------|-------------|
| 1.1.1 | Separate partition for containers not created | Container data can compete with the rest of the host/VM filesystem; disk exhaustion can affect broader platform stability. | Use a dedicated data root / storage allocation in production Linux hosts. |
| 1.1.3 / 1.1.4 | Auditing not configured for Docker daemon and runtime paths | Weakens forensic visibility and incident response. | Enable Linux audit rules on production Docker hosts. |
| 2.2 | Inter-container traffic on default bridge not restricted | Containers on the same bridge can talk to each other more freely than least privilege would suggest. | Use custom networks, network policy controls, or disable unnecessary ICC where supported. |
| 2.9 | User namespace support not enabled | Container root is mapped more directly to host root inside the Linux VM, increasing impact if combined with another escape primitive. | Enable `userns-remap` or use rootless mode where feasible. |
| 2.12 | Docker authorization not enabled | No plugin-based policy gate for client actions against the daemon. | Add authorization plugins or stronger daemon access controls in shared environments. |
| 2.13 | Centralized / remote logging not configured | Limits detection, retention, and post-incident correlation. | Forward daemon and container logs to a central SIEM/log platform. |
| 2.14 | Containers not restricted from acquiring new privileges by default | Setuid/setgid helpers or file capabilities inside containers may still become useful in some images. | Enforce `--security-opt=no-new-privileges` by policy or admission control. |
| 2.15 | Live restore disabled | Containers can be disrupted during daemon restart. This is primarily an availability risk. | Enable `live-restore` where operationally appropriate. |
| 2.16 | Userland proxy enabled | Slightly larger networking attack surface and more moving parts. | Disable `userland-proxy` if not required. |
| 3.15 / 3.16 | Docker socket ownership / permissions warning | A broadly writable or broadly accessible Docker socket is effectively root-equivalent control over the daemon. | Restrict socket access to the smallest trusted admin group. |
| 4.5 | Content trust disabled | Increases software supply-chain risk. | Enable signature verification / trusted publishing. |
| 4.6 | Missing `HEALTHCHECK` in images | Delays detection of unhealthy containers. | Add `HEALTHCHECK` to production images. |

### 2.4 Important Interpretation Caveat

This benchmark was run on **Docker Desktop for macOS**, not a dedicated Linux server. That matters because:

- Some checks expect Linux files such as `systemctl` units and `/etc/docker/*` layouts that do not exist on macOS in the same form.
- Some warnings are therefore environmental rather than true production misconfigurations.
- The results are still useful for understanding Docker CIS controls, but they should not be interpreted as a clean one-to-one audit of a hardened Linux host.

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Functional Comparison

All three profiles remained available after startup:

| Profile | URL | HTTP Result |
|---------|-----|-------------|
| Default | `http://localhost:3001` | 200 |
| Hardened | `http://localhost:3002` | 200 |
| Production | `http://localhost:3003` | 200 |

### 3.2 Resource Snapshot

| Profile | CPU | Memory Usage / Limit | Memory % |
|---------|-----|----------------------|---------:|
| Default | 0.51% | 102.2 MiB / 15.6 GiB | 0.64% |
| Hardened | 0.51% | 93.17 MiB / 512 MiB | 18.20% |
| Production | 0.51% | 92.95 MiB / 512 MiB | 18.15% |

### 3.3 Configuration Comparison Table

| Setting | Default | Hardened | Production |
|--------|---------|----------|------------|
| Container user | `65532` | `65532` | `65532` |
| Capabilities dropped | none | `ALL` | `ALL` |
| Capabilities added | none | none | `NET_BIND_SERVICE` |
| `no-new-privileges` | no | yes | yes |
| Seccomp | implicit engine default | implicit engine default | explicit Docker default seccomp profile |
| Memory limit | none | `512m` | `512m` |
| Swap behavior | unlimited/default host behavior | implicit total `1 GiB` because `--memory` was set without `--memory-swap` | `512m` total, so effectively **no swap** |
| CPU limit | none | `--cpus=1.0` | `--cpus=1.0` |
| PID limit | none | none | `100` |
| Restart policy | `no` | `no` | `on-failure:3` |

**Implementation note:** Docker 28 does not accept the literal lab syntax `seccomp=default`. To preserve the intended control, I explicitly applied Docker’s official default seccomp profile JSON from the `moby/profiles` repository.

### 3.4 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities split traditional root privileges into smaller per-thread privilege units. Instead of giving a process unrestricted root powers, the kernel can grant only the specific capabilities it actually needs.

Dropping **all** capabilities reduces the kernel attack surface and blocks many post-exploitation actions that depend on elevated kernel permissions. Examples include privileged networking, raw sockets, namespace operations, time changes, module loading, and other admin-style operations.

`CAP_NET_BIND_SERVICE` specifically permits binding to **privileged ports below 1024**. That is why operators often add it back for services listening on ports 80 or 443 without otherwise granting broad privilege.

Security trade-off:

- **Benefit:** much smaller privilege set
- **Cost:** some applications break if they genuinely need a dropped capability

For this specific Juice Shop container, the application listens on port `3000`, so `NET_BIND_SERVICE` is not strictly necessary for this lab run. In a real production service terminating directly on `80/443`, it would be a reasonable single capability to re-add.

#### b) `--security-opt=no-new-privileges`

`no_new_privs` is a Linux kernel control that prevents a process from gaining new privileges across `execve()`. With it enabled, **setuid/setgid binaries and file capabilities cannot elevate the process after exec**.

This mainly helps against privilege-escalation chains where an attacker already has code execution in the container and then tries to leverage privileged helper binaries or file capabilities.

Potential downside:

- Software that relies on setuid helpers or similar exec-time privilege changes can stop working.

For general application containers, that is usually a good trade: most web workloads do not need privilege escalation helpers at runtime.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits, a container can use as much memory and CPU as the host scheduler allows. Docker explicitly documents that unrestricted memory consumption can trigger OOM conditions and destabilize the host.

Memory limits help contain:

- accidental leaks
- malicious memory exhaustion
- denial-of-service conditions that aim to starve other workloads

CPU limits help prevent a noisy or compromised container from monopolizing CPU time and degrading co-located services.

Risk of setting limits too low:

- container crashes from OOM
- CPU throttling
- higher latency
- failed startup under real production load

This is why limits must be validated with realistic load testing.

#### d) `--pids-limit=100`

A **fork bomb** is a process explosion attack where a process repeatedly creates children until the host or cgroup exhausts available PIDs and scheduling capacity.

`--pids-limit=100` constrains the maximum number of processes/threads the container can create, which helps contain:

- deliberate fork bombs
- runaway worker spawning
- thread leaks

Choosing the right limit:

- measure normal steady-state and peak process/thread counts
- add reasonable headroom for bursts
- test under load before production rollout

Too high provides little protection. Too low causes legitimate workloads to fail under concurrency spikes.

#### e) `--restart=on-failure:3`

This policy restarts the container **only if it exits with a non-zero status**, and retries at most **3** times.

When auto-restart is beneficial:

- transient crashes
- short-lived dependency hiccups
- occasional runtime faults where a fresh process recovers service quickly

When auto-restart is risky:

- persistent crash loops can hide underlying defects
- repeated restarts can amplify side effects such as duplicate writes or noisy alerting

`on-failure` vs `always`:

- `on-failure` is more conservative and only reacts to failed exits
- `always` tries to restart regardless of why the container stopped, including after daemon restart

For application workloads, `on-failure:3` is often safer than `always` because it avoids infinite retry behavior and leaves room for operator intervention.

### 3.5 Critical Thinking Answers

**1. Which profile for DEVELOPMENT? Why?**  
Use **Default** or at most **Hardened**. Development favors simplicity and fewer moving parts. The default profile is easiest for debugging, but the hardened profile is a better choice if the team wants production-like restrictions early without adding too much operational friction.

**2. Which profile for PRODUCTION? Why?**  
Use **Production**. It preserves application functionality while adding least-privilege capability handling, `no-new-privileges`, explicit seccomp policy, memory/CPU limits, PID limits, and controlled restart behavior.

**3. What real-world problem do resource limits solve?**  
They prevent one container from degrading the rest of the node. In practice this protects against memory leaks, traffic spikes, bad deployments, fork bombs, and abusive workloads that would otherwise starve neighboring services.

**4. If an attacker exploits Default vs Production, what actions are blocked in Production?**  
Production blocks or constrains several post-exploitation paths:

- unrestricted process spawning is constrained by `--pids-limit=100`
- privilege gain through exec-time helpers is blocked by `no-new-privileges`
- many risky syscalls are filtered by seccomp
- broad Linux capability use is removed because `ALL` capabilities are dropped
- denial-of-service through memory exhaustion is constrained by memory limits
- CPU abuse is constrained by the CPU limit

**5. What additional hardening would you add?**

- `--read-only` root filesystem
- `--tmpfs /tmp` and other explicit writable mounts only where required
- explicit non-root UID/GID in Kubernetes/Compose manifests too, not just image metadata
- user namespace remapping or rootless Docker on Linux hosts
- image digest pinning and signature verification
- egress restrictions / network policy
- AppArmor or SELinux policy in addition to seccomp
- vulnerability scanning and policy gates in CI/CD
- a real `HEALTHCHECK`

---

## Conclusion

The image is already better than a worst-case baseline because it does **not** run as root, but that is outweighed by a large backlog of vulnerable dependencies. Runtime hardening materially improved the security posture without breaking the application. The strongest practical lessons from this lab are:

- non-root is necessary but not sufficient
- package hygiene dominates image risk
- runtime controls like capabilities, seccomp, `no-new-privileges`, and cgroup limits meaningfully reduce post-exploitation impact

---

## References

- Docker Scout CVE output captured in `labs/lab7/scanning/scout-cves.txt`
- Dockle output captured in `labs/lab7/scanning/dockle-results.txt`
- Docker Bench output captured in `labs/lab7/hardening/docker-bench-results.txt`
- Docker Docs, Resource constraints: https://docs.docker.com/engine/containers/resource_constraints/
- Docker Docs, Restart policies: https://docs.docker.com/engine/containers/start-containers-automatically/
- Docker Docs, Seccomp profiles: https://docs.docker.com/engine/security/seccomp/
- Linux kernel docs, `no_new_privs`: https://docs.kernel.org/userspace-api/no_new_privs.html
- Linux capabilities manual: https://man7.org/linux/man-pages/man7/capabilities.7.html
- Docker Bench for Security README: https://github.com/docker/docker-bench-security
