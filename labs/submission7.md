# Lab 7 - Container Security: Image Scanning and Deployment Hardening

## Scope

- Analysis date: `2026-03-24`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Evidence directories:
  - `labs/lab7/scanning`
  - `labs/lab7/hardening`
  - `labs/lab7/analysis`

## Environment Notes

- `docker scout cves` is installed but requires Docker Hub login in this environment. Output is captured in `labs/lab7/scanning/scout-cves.txt`.
- `SNYK_TOKEN` was not set, so Snyk scan could not authenticate. Output is captured in `labs/lab7/scanning/snyk-results.txt`.
- To complete Task 1 vulnerability analysis, a fallback high/critical scan was run with Trivy and saved to `labs/lab7/scanning/trivy-high-critical.txt`.
- `--security-opt=seccomp=default` failed on this Docker Desktop host. The production profile was rerun without this flag and the limitation is recorded in `labs/lab7/analysis/deployment-comparison.txt`.

## Task 1 - Image Vulnerability and Configuration Analysis

### 1.1 Top 5 Critical/High Vulnerabilities

Source: `labs/lab7/scanning/trivy-high-critical.txt`

| CVE | Package | Severity | Installed | Fixed | Impact |
| --- | --- | --- | --- | --- | --- |
| `CVE-2023-32314` | `vm2` | Critical | `3.9.17` | `3.9.18` | Sandbox escape in `vm2`, can lead to arbitrary code execution outside sandbox. |
| `CVE-2023-37466` | `vm2` | Critical | `3.9.17` | `3.10.0` | Promise sanitization bypass enabling sandbox escape. |
| `CVE-2023-37903` | `vm2` | Critical | `3.9.17` | not fixed in installed branch | Custom inspect function abuse can break out of sandbox. |
| `CVE-2026-22709` | `vm2` | Critical | `3.9.17` | `3.10.2` | Additional sandbox escape path in `vm2`. |
| `CVE-2024-37890` | `ws` | High | `7.4.6` | `7.5.10` (or supported newer lines) | DoS risk via large HTTP header handling in WebSocket processing. |

Risk interpretation:
- Critical findings are concentrated in `vm2`, which is high impact because sandbox escapes can invalidate code isolation assumptions.
- A network-exposed DoS issue in `ws` increases availability risk under malicious traffic patterns.

### 1.2 Dockle Configuration Findings

Source: `labs/lab7/scanning/dockle-results.txt`

- `FATAL`: none
- `WARN`: none
- `INFO` findings:
  - `CIS-DI-0005` - Content trust not enabled (`DOCKER_CONTENT_TRUST=1` not set).
  - `CIS-DI-0006` - No `HEALTHCHECK` instruction.
  - `DKL-LI-0003` - Unnecessary files (`.DS_Store`) present in image.

Security concerns:
- No content trust means pulled images are not cryptographically verified.
- Missing healthcheck reduces detection of unhealthy containers and can delay automated recovery.
- Unnecessary files increase image noise and can expose build-time artifacts.

### 1.3 Security Posture Assessment

- Does the image run as root: **No**. Runtime user is `65532` (from deployment inspect output).
- Strengths:
  - Non-root execution by default.
- Weaknesses:
  - High/critical dependency vulnerabilities (`vm2`, `ws`).
  - Missing `HEALTHCHECK`.
  - No content-trust enforcement in pull/build workflow.
- Recommendations:
  - Upgrade vulnerable Node dependencies (`vm2`, `ws`) and rebuild image.
  - Add `HEALTHCHECK` to Dockerfile.
  - Enforce signed image verification (`DOCKER_CONTENT_TRUST=1` or Sigstore/Cosign policies).
  - Keep a regular image rebuild cadence for base OS and app dependency patches.

## Task 2 - Docker Host Security Benchmarking

Source: `labs/lab7/hardening/docker-bench-results.txt`

### 2.1 Summary Statistics

- `PASS`: `19`
- `WARN`: `45`
- `FAIL`: `0`
- `INFO`: `99`
- `NOTE`: `7`
- Total checks reported: `74`
- Benchmark score: `4`

### 2.2 Analysis of Findings and Remediation

There were no explicit `[FAIL]` entries, but the warning volume is high and indicates material hardening gaps:

1. `1.1` No separate partition for container storage.
   - Impact: host disk pressure and weaker isolation boundaries.
   - Remediation: move Docker data root to dedicated partition with restrictive mount options.

2. `1.5`, `1.6` Auditing not configured for daemon/files.
   - Impact: weaker forensic visibility and reduced incident traceability.
   - Remediation: enable auditd (Linux) rules for daemon binary, socket, and Docker state paths.

3. `2.6` Daemon TLS authentication not configured.
   - Impact: remote daemon access can be intercepted/abused.
   - Remediation: disable TCP listener if not needed, otherwise enforce mutual TLS.

4. `2.8` User namespace remapping disabled.
   - Impact: weaker host protection if container breakout occurs.
   - Remediation: enable `userns-remap` in daemon config.

5. `2.11`, `2.12` No daemon authz plugin / centralized logging.
   - Impact: weak command authorization control and limited monitoring at scale.
   - Remediation: configure authorization plugin and send logs to centralized SIEM/logging backend.

6. `2.14`, `2.15`, `2.18` Live restore off, userland proxy on, and no-new-privileges restrictions not enforced daemon-wide.
   - Impact: larger attack surface and reduced runtime safety defaults.
   - Remediation: set `live-restore=true`, `userland-proxy=false`, and apply restrictive defaults in daemon/runtime policies.

7. `3.15` Docker socket ownership mismatch.
   - Impact: over-broad access to Docker API can become root-equivalent on host.
   - Remediation: correct socket ownership/permissions and restrict group membership.

8. `4.5`, `4.6` Content trust and healthchecks absent across many local images.
   - Impact: supply chain trust and service resilience gaps.
   - Remediation: enforce signed images and require `HEALTHCHECK` in build standards.

## Task 3 - Deployment Security Configuration Analysis

Sources:
- `labs/lab7/analysis/deployment-comparison.txt`
- `labs/lab7/analysis/deployment-ps.txt`

### 3.1 Configuration Comparison Table

| Setting | Default (`3001`) | Hardened (`3002`) | Production (`3003`) |
| --- | --- | --- | --- |
| HTTP status | `200` | `200` | `200` |
| `CapDrop` | none | `ALL` | `ALL` |
| `CapAdd` | none | none | `CAP_NET_BIND_SERVICE` |
| `SecurityOpt` | none | `no-new-privileges` | `no-new-privileges` |
| Memory | unlimited (`0`) | `512MiB` | `512MiB` |
| Memory swap | unlimited (`0`) | `1GiB` | `512MiB` |
| CPU | unlimited (`NanoCpus=0`) | `1 CPU` (`NanoCpus=1000000000`) | `1 CPU` (`NanoCpus=1000000000`) |
| PID limit | none | none | `100` |
| Restart policy | `no` | `no` | `on-failure:3` |
| Runtime user | `65532` | `65532` | `65532` |

Runtime compatibility note:
- `seccomp=default` was not accepted by this host runtime and was omitted in the production test run.

### 3.2 Security Measure Analysis

`a) --cap-drop=ALL and --cap-add=NET_BIND_SERVICE`
- Linux capabilities split root privileges into smaller units.
- Dropping all capabilities removes many privilege-escalation paths (raw sockets, kernel-level operations, etc.).
- `NET_BIND_SERVICE` is added back only when binding to privileged ports is required.
- Trade-off: strongest least-privilege posture, but some app behaviors can break if required caps are missing.

`b) --security-opt=no-new-privileges`
- Prevents processes from gaining extra privileges (for example via setuid binaries).
- Helps block post-exploit privilege escalation.
- Downside: workloads that rely on privilege elevation mechanisms may fail.

`c) --memory=512m and --cpus=1.0`
- Without limits, a container can monopolize host resources and cause noisy-neighbor outages.
- Memory limits reduce blast radius of memory exhaustion and some DoS patterns.
- Limits set too low can cause OOM kills or degraded application latency.

`d) --pids-limit=100`
- A fork bomb rapidly spawns processes until system resources are exhausted.
- PID limits cap process count per container and contain that failure mode.
- Right value depends on baseline process count + headroom under realistic peak load.

`e) --restart=on-failure:3`
- Restarts container automatically on non-zero exit, up to 3 retries.
- Good for transient crashes; risky if failures are persistent and hide root causes/noise logs.
- `on-failure` is safer than `always` for avoiding endless restart loops during broken deploys.

### 3.3 Critical Thinking Answers

1. Development profile:
   - `Default` or lightly hardened profile.
   - Reason: easier debugging and fewer false breakages while building features.

2. Production profile:
   - `Production` (with seccomp re-enabled where supported).
   - Reason: least-privilege capabilities, resource guards, PID limit, and controlled auto-restart behavior.

3. Real-world resource-limit problem solved:
   - Prevents a single compromised or buggy container from causing node-wide outage by CPU/memory starvation.

4. If attacker exploits Default vs Production:
   - Production blocks many actions via dropped capabilities and `no-new-privileges`.
   - Production constrains abuse impact with memory/CPU/PID limits and bounded restart policy.

5. Additional hardening to add:
   - Read-only root filesystem (`--read-only`) with explicit writable mounts.
   - Drop all unnecessary network exposure and use internal networks.
   - Explicit seccomp/apparmor profiles (host-compatible).
   - Image signature verification policy admission.
   - Runtime detection (Falco) and centralized audit/log alerting.

## Generated Artifacts

- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/snyk-results.txt`
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/scanning/trivy-high-critical.txt`
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/analysis/deployment-ps.txt`
- `labs/lab7/analysis/deployment-comparison.txt`
