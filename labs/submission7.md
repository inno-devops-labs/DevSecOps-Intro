# Lab 7 — Container Security: Image Scanning & Deployment Hardening

**Date:** March 22, 2026  
**Branch:** `feature/lab7`  
**Target image:** `bkimminich/juice-shop:v19.0.0`

## Task 1 — Image Vulnerability & Configuration Analysis

### Scanner Execution Summary

- `Docker Scout` completed with authenticated results:
  - `quickview`: `11C 65H 30M 5L 7?` for `bkimminich/juice-shop:v19.0.0`
  - `cves`: `48 vulnerable packages` and `87 vulnerabilities` total
  - base image auto-detected as `distroless/static:nonroot` with `0C 0H 0M 0L`
  - Evidence: `labs/lab7/scanning/scout-quickview.txt`, `labs/lab7/scanning/scout-cves.txt`
- `Snyk` scan executed successfully far enough to produce both OS and application findings:
  - OS/base scan: `Tested 10 dependencies ... found 6 issues`
  - App dependency scan: `Tested 975 dependencies ... found 47 issues`
  - Final command ended with `403 Forbidden` after findings were printed (report content still captured).
  - Evidence: `labs/lab7/scanning/snyk-results.txt`
- `Dockle` image configuration scan completed.
  - Evidence: `labs/lab7/scanning/dockle-results.txt`

### Top 5 Critical/High Vulnerabilities

| # | CVE / Advisory | Package | Severity | Impact | Fixed Version |
|---|---|---|---|---|---|
| 1 | `CVE-2026-22709` (Scout) | `vm2@3.9.17` | Critical | Sandbox protection failure can enable code execution escape | `3.10.2` |
| 2 | `CVE-2023-37903` (Scout) | `vm2@3.9.17` | Critical | OS command injection in JavaScript sandbox dependency | No fixed version |
| 3 | `CVE-2025-55130` (Scout) | `node@22.18.0` | Critical | Critical runtime vulnerability in Node.js engine used by app | `22.22.0` |
| 4 | `CVE-2019-10744` (Scout) | `lodash@2.4.2` | Critical | Prototype pollution can lead to application logic compromise | `4.17.12` |
| 5 | `CVE-2025-69421` (`SNYK-DEBIAN12-OPENSSL-15123192`) | `openssl/libssl3@3.0.17-1~deb12u2` | High | TLS/crypto issue in OS layer impacting confidentiality/integrity | `3.0.18-1~deb12u2` |

### Dockle Configuration Findings

`Dockle` produced **no `FATAL` and no `WARN`** findings in this run, but reported security-relevant `INFO` items:

- `CIS-DI-0005`: Content trust is not enabled.
  - Risk: image provenance/signing verification is not enforced, increasing supply-chain tampering risk.
- `CIS-DI-0006`: No `HEALTHCHECK` instruction.
  - Risk: orchestrators and operations tooling cannot reliably detect unhealthy container state.
- `DKL-LI-0003`: unnecessary files detected (`.DS_Store` artifacts in `node_modules` paths).
  - Risk: extra artifacts increase image noise and attack surface footprint.

### Security Posture Assessment

- **Does the image run as root?**  
  No. `docker image inspect` reports `User=65532`, so the image defaults to non-root execution.

- **Recommended security improvements**
  - Upgrade/patch vulnerable dependencies (especially `node`, `multer`, `vm2`, OpenSSL layer).
  - Add `HEALTHCHECK` to image metadata.
  - Enable Docker Content Trust / signed image verification in CI and deployment.
  - Rebuild image frequently to absorb base-layer security fixes.
  - Gate releases on high/critical vulnerability thresholds.

## Task 2 — Docker Host Security Benchmarking (CIS)

Source: `labs/lab7/hardening/docker-bench-results.txt`  
ANSI-cleaned copy: `labs/lab7/hardening/docker-bench-results-clean.txt`

### Summary Statistics

- `PASS`: **25**
- `WARN`: **15**
- `FAIL`: **0**
- `INFO`: **27**
- `NOTE`: **7**

Counts above are normalized on control IDs (patterns like `X.Y`) from the cleaned benchmark output, matching the reported `Checks: 74`.
Benchmark-reported score in this run: `10`.

### Analysis of Failures

No explicit `[FAIL]` results were reported in this run.

### Key Warning Analysis and Remediation

Most important warnings observed:

1. `1.1` Separate partition for containers not created.  
   - Impact: disk exhaustion on Docker data can affect host/system partitions.
   - Remediation: mount `/var/lib/docker` on dedicated storage.

2. `1.5`–`1.9` Auditing is not fully configured for Docker daemon/files/service/socket.  
   - Impact: reduced forensic visibility and weaker incident investigation capability.
   - Remediation: enable `auditd` rules for Docker daemon/socket/files.

3. `2.8` User namespace support not enabled.  
   - Impact: weaker UID/GID isolation between container and host.
   - Remediation: enable `userns-remap` in daemon config.

4. `2.11` Authorization for Docker client commands not enabled.  
   - Impact: insufficient policy-based control over daemon actions.
   - Remediation: use Docker authorization plugins / RBAC controls.

5. `2.12` Centralized logging not configured.  
   - Impact: harder detection/correlation of container abuse across systems.
   - Remediation: configure remote log driver/SIEM pipeline.

6. `2.14` Live restore not enabled.  
   - Impact: daemon restarts can interrupt container availability.
   - Remediation: set `"live-restore": true` in daemon config.

7. `2.15` Userland proxy not disabled.  
   - Impact: unnecessary networking surface and performance overhead.
   - Remediation: set `"userland-proxy": false` in daemon config.

8. `2.18` Containers are not globally restricted from acquiring new privileges (daemon default).  
   - Impact: weaker default posture for containers launched without explicit hardening flags.
   - Remediation: enforce `no-new-privileges` through daemon policy or orchestrator baseline.

9. `4.5` Content trust not enabled.  
   - Impact: no signature/provenance enforcement for pulled images.
   - Remediation: enable Docker Content Trust / image signature verification policy.

10. `4.6` Missing `HEALTHCHECK` instructions in images (including Juice Shop image).  
   - Impact: slower detection of unhealthy containers and weaker self-healing behavior.
   - Remediation: define container health probes in image/build process.

## Task 3 — Deployment Security Configuration Analysis

Source: `labs/lab7/analysis/deployment-comparison.txt`

### Runtime Comparison (Functionality + Resources)

- Functionality:
  - `Default`: HTTP `200`
  - `Hardened`: HTTP `200`
  - `Production`: HTTP `200`
- Resource usage snapshot:
  - `juice-default`: `108.4MiB / 13.34GiB` (no memory limit)
  - `juice-hardened`: `95.78MiB / 512MiB`
  - `juice-production`: `97.82MiB / 512MiB`

### Configuration Comparison Table

| Setting | Default | Hardened | Production |
|---|---|---|---|
| Capabilities dropped | none | `ALL` | `ALL` |
| Capabilities added | none | none | `NET_BIND_SERVICE` |
| Security options | none | `no-new-privileges` | `no-new-privileges` |
| Memory limit | none (`0`) | `512m` | `512m` |
| Memory swap | none (`0`) | `1g` effective | `512m` (swap disabled) |
| CPU limit | none | `--cpus=1.0` (`NanoCpus=1000000000`) | `--cpus=1.0` (`NanoCpus=1000000000`) |
| PIDs limit | none | none | `100` |
| Restart policy | `no` | `no` | `on-failure:3` |

Note: `CPUQuota/CPUPeriod` showed `0` in inspect output because this Docker version tracks the configured CPU cap through `NanoCpus` for `--cpus`.
Note: explicit `--security-opt=seccomp=default` failed on this host (`open default: no such file or directory`), so runtime testing used Docker's implicit default seccomp behavior.

### Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

- Linux capabilities split root powers into smaller privileges.
- Dropping all capabilities blocks many privilege-abuse paths (network admin actions, kernel interface abuse, etc.).
- `NET_BIND_SERVICE` is re-added only when binding low ports may be needed.
- Trade-off: least privilege improves security but may break software expecting broader kernel privileges.

#### b) `--security-opt=no-new-privileges`

- Prevents processes from gaining extra privileges via `setuid`, `setgid`, or file capabilities.
- Mitigates local privilege escalation chains after initial code execution.
- Downsides: can break legacy programs that depend on privilege elevation behavior.

#### c) `--memory=512m` and `--cpus=1.0`

- Without limits, a compromised or buggy container can consume excessive host RAM/CPU and starve neighbors.
- Memory limit helps contain memory exhaustion/DoS impact.
- Limits that are too low can cause OOM kills, throttling, latency spikes, and false health failures.

#### d) `--pids-limit=100`

- A fork bomb rapidly creates processes until PID table/resources are exhausted.
- PID limits constrain blast radius and protect host/process scheduler stability.
- Right sizing requires observing normal process count + burst margin under realistic load tests.

#### e) `--restart=on-failure:3`

- Restarts container only when it exits non-zero, up to 3 retries.
- Useful for transient crashes and short-lived failures.
- Risk: repeated restart loops can hide root causes and increase noise.
- `on-failure` is safer than `always` for many services because it avoids perpetual restarts even on clean stop scenarios.

### Critical Thinking Answers

1. **Best profile for development:**  
   `Default` or `Hardened` depending on team needs.  
   - `Default` is simplest for debugging.
   - `Hardened` is better for early security parity while still easy to run.

2. **Best profile for production:**  
   `Production` due least privilege + resource controls + PID cap + controlled restart behavior.

3. **Real-world problem solved by resource limits:**  
   Prevents single-service runaway usage from causing multi-tenant outages (`noisy neighbor` and DoS containment).

4. **If attacker exploits Default vs Production, what is blocked in Production?**  
   - Harder privilege escalation (`no-new-privileges`, dropped capabilities).  
   - Reduced ability to exhaust host resources (memory/CPU/PID caps).  
   - Narrower post-exploit operating envelope because only minimal privileges remain.

5. **Additional hardening to add**
   - Explicit seccomp profile (default/baseline hardened profile pinned by policy).
   - Read-only root filesystem and dedicated `tmpfs` mounts.
   - `--user` pinning in runtime policy (even though image already sets non-root user).
   - AppArmor/SELinux enforcement profiles.
   - Network policies/egress restrictions and runtime IDS.
   - Signed images + SBOM attestation + policy gate in CI/CD.

## Evidence Files

- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/scout-quickview.txt`
- `labs/lab7/scanning/snyk-results.txt`
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/hardening/docker-bench-results-clean.txt`
- `labs/lab7/analysis/deployment-comparison.txt`
