# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

## Overview

Target image:

```text
bkimminich/juice-shop:v19.0.0
```

Artifacts collected for this lab:

- `labs/lab7/scanning/scout-quickview.txt`
- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/snyk-results.txt`
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/analysis/deployment-comparison.txt`

Methodology notes:

- Docker Scout CLI was installed locally because it was not present in the workspace initially.
- The published `docker/docker-bench-security:latest` image is outdated for this host: it contains Docker client `18.06.1-ce` with API `1.38`, while the host daemon is Docker `29.3.0` and requires API `>= 1.40`. I therefore ran the current upstream `docker-bench-security` script locally and saved the benchmark output to the required artifact path.
- The lab handout uses `--security-opt=seccomp=default`. On this Docker `29.3.0` host that value is interpreted as a file path named `default`, so I used `--security-opt=seccomp=builtin`, which explicitly enables Docker's built-in default seccomp profile.
- The prescribed Snyk scan was attempted exactly as requested, but the workspace does not contain a valid `SNYK_TOKEN`. The result is a saved `401 Unauthorized` error rather than a vulnerability report.

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Scan Summary

#### Docker Scout Quickview

```text
Target: bkimminich/juice-shop:v19.0.0
Digest: 37cc73163c4c
Base image: distroless/static:nonroot
```

| Severity | Count |
|----------|------:|
| CRITICAL | 12 |
| HIGH | 72 |
| MEDIUM | 35 |
| LOW | 5 |
| UNSPECIFIED | 13 |

Important observation:

- Scout reports **0 known vulnerabilities in the base image** (`distroless/static:nonroot`).
- The risk is concentrated in the **application/runtime dependency layer**, not the distroless base itself.

#### Docker Scout CVE Details

Detailed `critical,high` scan result:

- **84 critical/high vulnerabilities**
- **37 vulnerable packages**

#### Snyk Comparison Status

The Snyk step could not complete because external credentials are missing in this environment.

Saved output:

```text
ERROR Authentication error (SNYK-0005)
Status: 401 Unauthorized
```

So the lab contains evidence of the attempted Snyk execution, but not a usable Snyk vulnerability comparison.

#### Dockle Configuration Assessment

Dockle reported:

- **FATAL:** 0
- **WARN:** 0
- **INFO:** 3
- **SKIP:** 1

This means the image is relatively clean from a Dockerfile/image-configuration perspective, even though the dependency layer is highly vulnerable.

### 1.2 Top 5 Critical/High Vulnerabilities

| CVE | Package | Severity | Impact | Fixed Version |
|-----|---------|----------|--------|---------------|
| `CVE-2026-22709` | `vm2 3.9.17` | CRITICAL | Promise callback sanitization bypass allows sandbox escape and arbitrary code execution. | `3.10.2` |
| `CVE-2023-37903` | `vm2 3.9.17` | CRITICAL | OS command injection path enables sandbox escape and remote code execution. | No fix listed in Scout |
| `CVE-2023-37466` | `vm2 3.9.17` | CRITICAL | Promise handler sanitization bypass leads to code injection and sandbox escape. | `3.10.0` |
| `CVE-2023-32314` | `vm2 3.9.17` | CRITICAL | Proxy-based sandbox escape can create host objects and execute code on the server. | `3.9.18` |
| `CVE-2026-33937` | `handlebars 4.7.7` | CRITICAL | Crafted AST input can inject arbitrary JavaScript into `Handlebars.compile()`, leading to server-side RCE. | `4.7.9` |

Additional high-risk packages worth noting even outside the top five:

- `sequelize 6.37.7` — `CVE-2026-30951` (HIGH), SQL injection in JSON/JSONB cast handling
- `socket.io-parser 4.0.5` — `CVE-2026-33151` (HIGH), memory exhaustion / DoS
- `ws 7.4.6` — `CVE-2024-37890` (HIGH), crash via excessive headers
- `node 22.18.0` — 1 critical + 4 high findings, fix target `22.22.0`

### 1.3 Dockle Configuration Findings

Dockle did **not** report any `FATAL` or `WARN` issues. That is important: the image has serious dependency vulnerabilities, but the image configuration itself is not obviously reckless.

Relevant INFO findings:

| Finding | Why it matters |
|---------|----------------|
| `CIS-DI-0005` — Content trust not enabled | Pull/build provenance is weaker. Without signing/verification, supply-chain tampering is harder to detect. |
| `CIS-DI-0006` — No `HEALTHCHECK` instruction | Orchestrators and operators cannot distinguish "process exists" from "application is healthy". Recovery is slower and blind restarts are more likely. |
| `DKL-LI-0003` — Unnecessary `.DS_Store` files present | Extra files increase image noise, leak build-environment artifacts, and signal sloppy build hygiene. |

Non-actionable skip:

- `DKL-LI-0001` (`/etc/shadow` not found) is expected for a distroless-style image and is not a security issue by itself.

### 1.4 Security Posture Assessment

#### Does the image run as root?

No.

`docker image inspect` shows:

```text
User: 65532
Base image: distroless/static:nonroot
```

This is a strong positive signal. The image already follows one important container hardening rule: **do not run the application as root**.

#### Overall assessment

Strengths:

- Non-root runtime user (`65532`)
- Distroless nonroot base image
- No Dockle `FATAL` or `WARN`
- Base image itself shows `0C/0H/0M/0L` in Scout quickview

Weaknesses:

- Very large dependency attack surface: `12C + 72H`
- Multiple direct RCE-class issues in `vm2` and `handlebars`
- Additional high-risk web-facing issues in `sequelize`, `ws`, and `socket.io-parser`
- No `HEALTHCHECK`
- Content trust/signing not enabled

#### Recommended improvements

1. Rebuild the image with patched dependencies, prioritizing `vm2`, `handlebars`, `sequelize`, `ws`, and the Node runtime.
2. Add a CI gate that fails builds on new critical/high vulnerabilities.
3. Add a proper `HEALTHCHECK`.
4. Enable image signing/content trust or Sigstore/cosign-style verification in the delivery pipeline.
5. Remove unnecessary files from the final image.
6. Keep the runtime non-root and pair it with runtime hardening such as dropped capabilities, `no-new-privileges`, seccomp, PID limits, and resource limits.
7. Consider `--read-only` plus dedicated writable `tmpfs` mounts for directories the app actually needs.

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 Benchmark Summary

Tool:

```text
docker-bench-security v1.6.0 (upstream script, executed locally)
```

Output summary from the numbered CIS checks:

| Result | Count |
|--------|------:|
| PASS | 46 |
| WARN | 32 |
| FAIL | 0 |
| INFO | 36 |
| NOTE (manual checks) | 11 |

Additional benchmark metadata:

- **Total checks:** 117
- **Score:** 6

Important interpretation note:

- This benchmark run produced **no explicit `FAIL` lines**; instead, actionable deviations are represented mostly as `WARN`.
- The host is shared with other running containers already present in the workspace (`lab09-control-plane`, `buildx_buildkit_kamal-local-docker-container0`), so some runtime warnings describe the **current host/container estate**, not Juice Shop specifically.

### 2.2 Main Findings and Security Impact

| Check | Finding | Security Impact | Remediation |
|------|---------|-----------------|-------------|
| `1.1.1` | No separate partition for containers | Easier host disk exhaustion and weaker isolation of Docker storage. | Put `/var/lib/docker` on a dedicated partition or volume. |
| `1.1.3` to `1.1.18` | Audit rules missing for Docker/containerd files and directories | Weak forensic visibility; daemon abuse or tampering is harder to detect. | Add `auditd` rules for Docker, containerd, runc, config files, and sockets. |
| `2.2` | Inter-container traffic on default bridge not restricted | Containers on the default bridge can communicate more freely than desired, increasing lateral movement risk. | Prefer user-defined networks, disable inter-container communication where possible, and enforce segmentation. |
| `2.9` | User namespace support not enabled | Container UID 0 is closer to host privilege semantics than necessary. | Enable `userns-remap` or use rootless Docker where practical. |
| `2.12` | No authorization plugin for Docker client commands | Any user with daemon access has broad power over the host. | Add an authorization plugin or tighten daemon access paths. |
| `2.13` | Centralized/remote logging not configured | Logs can be lost locally during host failure or tampering. | Ship container and daemon logs to a central log platform. |
| `2.14` | Additional privileges are not restricted daemon-wide | Containers can keep more privilege-escalation paths than necessary. | Enforce `no-new-privileges` by policy/orchestrator defaults. |
| `2.15` | Live restore disabled | Daemon restarts can interrupt containers unexpectedly. | Enable `live-restore` if operational model requires it. |
| `2.16` | Userland proxy not disabled | Larger networking surface and less direct kernel-managed forwarding. | Set `"userland-proxy": false` unless there is a compatibility reason. |
| `4.5` | Docker content trust disabled | Image provenance is not enforced. | Enable trusted signing/verification in the supply chain. |
| `4.6` | Many images lack `HEALTHCHECK`, including Juice Shop | Runtime health cannot be assessed reliably. | Add explicit health checks to production images. |
| `5.5` | Privileged containers are running | A compromised privileged container can often reach host-level control. | Eliminate `--privileged` and grant only the specific capabilities required. |
| `5.11`, `5.12`, `5.29` | Some running containers have no memory/CPU/PID limits | Easy denial-of-service and noisy-neighbor resource starvation. | Set sane per-service limits based on profiling. |
| `5.13` | Root filesystem writable for some containers | Malware or attacker tooling can persist more easily inside the container. | Use `--read-only` and mount only required writable paths. |
| `5.22` | Seccomp disabled for at least one running container | Larger syscall attack surface and weaker kernel protection. | Use default or custom seccomp profiles unless a specific syscall exception is justified. |
| `5.26` | Some containers can acquire additional privileges | Post-exploitation privilege escalation remains easier. | Enable `--security-opt no-new-privileges`. |

### 2.3 Practical Conclusion

The benchmark shows a host that is **functional but not hardened enough for production**. The most important themes are:

- missing audit coverage
- weak daemon policy defaults
- lack of runtime constraints on some containers
- presence of privileged/root-running containers
- incomplete supply-chain controls

If this were a real production host, I would prioritize:

1. removing privileged/root-running containers where possible
2. enabling memory/CPU/PID limits everywhere
3. enforcing `no-new-privileges`, seccomp, and non-root defaults
4. enabling user namespace remapping/rootless operation
5. adding centralized logging and audit rules

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison

All three profiles started successfully and returned HTTP `200`.

Runtime functionality result:

| Profile | HTTP Result |
|---------|------------:|
| Default | 200 |
| Hardened | 200 |
| Production | 200 |

Security configuration comparison from `docker inspect`:

| Profile | User | CapAdd | CapDrop | Security Options | Memory | Swap | CPU | PIDs | Restart |
|---------|------|--------|---------|------------------|--------|------|-----|------|---------|
| Default | `65532` | none | none | none | unlimited | unlimited | unlimited | unlimited | `no` |
| Hardened | `65532` | none | `ALL` | `no-new-privileges` | `512 MiB` | `1 GiB` | `1.0` | unlimited | `no` |
| Production | `65532` | `NET_BIND_SERVICE` | `ALL` | `no-new-privileges`, `seccomp=builtin` | `512 MiB` | `512 MiB` | `1.0` | `100` | `on-failure:3` |

Observed resource usage snapshot:

| Profile | CPU | Memory Usage |
|---------|-----|--------------|
| Default | `1.70%` | `135.8 MiB / 15.35 GiB` |
| Hardened | `0.53%` | `91.76 MiB / 512 MiB` |
| Production | `0.47%` | `106.1 MiB / 512 MiB` |

Key observation:

- Hardening **did not break the application**.
- Because Juice Shop already runs as non-root and listens on port `3000`, it tolerates capability dropping and privilege restrictions well.

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities are fine-grained privilege units that split up what used to be "root powers" into separate pieces. Instead of giving a process full superuser privilege, the kernel can grant only the exact capabilities it needs.

Why `--cap-drop=ALL` helps:

- It removes the container's default kernel capabilities.
- A compromised process loses many post-exploitation options such as mounting filesystems, reconfiguring networking, opening raw sockets, or performing other privileged operations.
- This reduces container breakout and lateral-movement opportunities.

Why add back `NET_BIND_SERVICE`:

- That capability is only needed to bind to ports below `1024`.
- In this lab, Juice Shop listens on port `3000`, so **it does not actually need this capability**.
- In a real production image that binds to `80` or `443` inside the container, adding back only `NET_BIND_SERVICE` would be a reasonable least-privilege compromise.

Security trade-off:

- Dropping all capabilities is excellent for containment.
- Every capability added back should be justified by actual runtime need, because each one increases the attack surface after compromise.

#### b) `--security-opt=no-new-privileges`

This flag prevents processes from gaining extra privilege during `execve()`.

What it prevents:

- `setuid`/`setgid` binaries from elevating privilege
- tools like `sudo` or `su` from working as privilege-escalation helpers
- some post-exploitation escalation paths that rely on executing a more privileged binary

Why it matters:

- If an attacker gets code execution inside the container, `no-new-privileges` blocks one common next step: turning that foothold into a stronger local privilege context.

Downsides:

- It can break software that legitimately expects `sudo`, `su`, or `setuid` behavior.
- Kernel documentation also notes that it can interfere with some LSM-based tightening-on-exec behavior, so it should be tested with the target workload.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits:

- one container can monopolize host memory or CPU
- memory leaks and abusive requests can destabilize the node
- a single noisy service can degrade unrelated workloads

What memory limiting prevents:

- host-wide memory exhaustion
- easy denial-of-service through oversized requests, leaks, or intentionally abusive workloads
- OOM cascades that hit neighboring services

Risk of setting limits too low:

- container restarts or OOM kills during normal spikes
- latency increases due to CPU throttling
- application failures during startup, cache warmup, or large batch jobs

In other words, limits improve isolation, but they must be sized from real measurements.

#### d) `--pids-limit=100`

A fork bomb is a process-creation attack where a program rapidly spawns children until the system runs out of process slots and becomes unstable.

Why PID limiting helps:

- it caps the number of processes/threads a container may create
- it contains runaway process creation inside that one container
- it protects the host and neighboring workloads from process-table exhaustion

How to choose the right limit:

- measure normal peak process/thread count under load
- include worker pools, exec hooks, shell/debug sessions, and monitoring agents
- add modest headroom, then validate under stress testing

#### e) `--restart=on-failure:3`

This policy means:

- restart the container only when it exits with a non-zero status
- stop retrying after 3 failed restart attempts

When auto-restart is helpful:

- transient crashes
- temporary dependency failures
- short-lived resource hiccups

When it is risky:

- it can hide bad crash loops from operators
- repeated restarts can create log noise and extra resource churn
- if the app is compromised and exits repeatedly, restart can keep reviving a bad state

`on-failure` vs `always`:

- `on-failure` is more conservative and does not restart on clean exits
- `always` restarts regardless of exit reason and also comes back after daemon restart
- for production services, `always` can improve availability, but `on-failure` is often safer when you want failures to stay visible and bounded

### 3.3 Critical Thinking Answers

#### 1. Which profile for DEVELOPMENT? Why?

I would choose **Hardened** for day-to-day development.

Why:

- it keeps the app usable (`HTTP 200`)
- it catches privilege assumptions early
- it adds meaningful guardrails without adding the operational behavior of restart loops and tight PID controls

`Default` is easier for debugging, but it normalizes bad security defaults and hides problems that will appear later in staging/production.

#### 2. Which profile for PRODUCTION? Why?

**Production** is the correct production choice.

Why:

- least privilege (`cap-drop=ALL`)
- privilege escalation blocked (`no-new-privileges`)
- syscall attack surface reduced (`seccomp=builtin`)
- resource exhaustion contained (memory/CPU/PID limits)
- bounded resilience (`on-failure:3`)

It provides the best compromise between availability and containment.

#### 3. What real-world problem do resource limits solve?

They solve the **noisy neighbor / host starvation** problem.

In shared hosts and clusters, an unbounded container can consume disproportionate CPU, RAM, or process slots and degrade every other service on the node. Limits turn a host-wide incident into a single-service incident.

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

Compared with `Default`, the `Production` profile blocks or constrains:

- easy privilege escalation via `setuid`/`sudo` style paths
- use of Docker's default capability set, because all capabilities are dropped and only one is re-added
- many risky syscalls thanks to the default seccomp profile
- unlimited process spawning via fork bomb (`pids-limit=100`)
- unlimited memory/CPU abuse (`512 MiB`, `1 CPU`)
- infinite auto-restart behavior, because retries are capped at `3`

It does **not** make the app invulnerable, but it narrows what an attacker can do after a successful exploit.

#### 5. What additional hardening would you add?

1. `--read-only` root filesystem with explicit writable `tmpfs` mounts
2. AppArmor/SELinux policy tuned for this container
3. Remove `NET_BIND_SERVICE` here, because Juice Shop does not need it on port `3000`
4. User-defined network segmentation and ingress policy
5. Image signing/verification and SBOM attestation
6. Runtime health check and alerting
7. Rootless Docker or user namespace remapping on the host
8. Secrets from an external secret store instead of baked config/env

---

## Final Conclusion

The Juice Shop image is a good example of why image security must be assessed at **multiple layers**:

- the **base image choice is good** (`distroless/static:nonroot`, non-root runtime, no base-image CVEs in Scout quickview)
- the **dependency layer is bad** (`12C + 72H`, including multiple RCE-class issues)
- the **runtime configuration matters a lot**, because the app continues to function even when strong hardening is applied

The most important lesson from this lab is that a "working container" is not the same thing as a "production-ready container". Least privilege, syscall filtering, resource isolation, restart policy, and host daemon hardening all materially change the blast radius of a compromise.

---

## Research Sources

- Docker run reference: https://docs.docker.com/reference/cli/docker/container/run/
- Docker resource constraints: https://docs.docker.com/engine/containers/resource_constraints/
- Docker restart policies: https://docs.docker.com/engine/containers/start-containers-automatically/
- Docker seccomp profiles: https://docs.docker.com/engine/security/seccomp/
- Linux capabilities man page: https://man7.org/linux/man-pages/man7/capabilities.7.html
- Linux kernel `no_new_privs`: https://www.kernel.org/doc/html/v6.5/userspace-api/no_new_privs.html
- Docker Bench Security README: https://github.com/docker/docker-bench-security
