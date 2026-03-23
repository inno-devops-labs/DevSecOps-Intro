# Submission 7 — Container Security: Image Scanning & Deployment Hardening

## Environment Notes
- Host OS: macOS (Docker Desktop)
- Target image: `bkimminich/juice-shop:v19.0.0`
- Working artifacts saved under `labs/lab7/`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### 1) Docker Scout results (saved: `labs/lab7/scanning/scout-cves.txt`)

**Summary:**
- Total vulnerabilities: **118** in **48** packages
- Critical: **11**
- High: **65**
- Medium: **30**
- Low: **5**
- Unspecified: **7**

### Top 5 Critical/High vulnerabilities

| CVE | Package | Severity | Impact |
|---|---|---|---|
| CVE-2026-23950 | `tar` | High | Path traversal / archive handling issue that may enable file overwrite/extraction abuse. |
| CVE-2026-31802 | `tar` | High | Path traversal in archive processing; can lead to integrity compromise of files. |
| CVE-2024-29415 | `ip` | High | SSRF risk; app logic may be abused to reach internal network resources. |
| CVE-2024-37890 | `ws` | High | NULL pointer dereference / potential DoS from crafted websocket input. |
| CVE-2026-30951 | `sequelize` | High | SQL injection risk in affected versions, potentially exposing/conflicting data integrity. |

### 2) Dockle configuration findings (saved: `labs/lab7/scanning/dockle-results.txt`)

Dockle output in this run reported `INFO` + `SKIP`, with no explicit `FATAL`/`WARN` lines.

Notable findings:
- `CIS-DI-0005`: Content trust is not enabled (`DOCKER_CONTENT_TRUST=1` not set).
  - **Concern:** reduces supply-chain integrity guarantees for pulled images.
- `CIS-DI-0006`: `HEALTHCHECK` instruction missing.
  - **Concern:** orchestrators cannot reliably detect unhealthy container state.
- `DKL-LI-0003`: unnecessary files present (`.DS_Store` in dependencies).
  - **Concern:** image hygiene issue; can leak build environment artifacts and increase attack surface.

### 3) Security posture assessment

- **Does image run as root?** No. `docker inspect` reports `User=65532` (non-root).
- **Recommended improvements:**
  1. Upgrade vulnerable npm dependencies (especially `tar`, `ws`, `sequelize`, `ip`, `multer`).
  2. Add `HEALTHCHECK` in Dockerfile.
  3. Enable image signing/content trust in CI/CD.
  4. Rebuild regularly and pin secure base image digest.
  5. Add policy gates to block critical/high CVEs at release.

### Snyk comparison status
- Output file: `labs/lab7/scanning/snyk-results.txt`
- Result summary: Snyk reported **47 issues** in **975 dependencies** tested within the `/juice-shop/package.json` package context, alongside an additional 6 OS/base-image issues. Snyk provides structured remediation advice, recommending exact version bumps for high-severity vulnerabilities like `body-parser`, `express`, `glob`, `multer`, `socket.io`, and `sequelize`. In comparison against Docker Scout, we notice more targeted package paths but generally detecting the same high-severity issues (like SQL injection in `sequelize` and resource exhaustion in `multer`). Snyk CLI failed at the end with a 403 Forbidden interacting with the remote dashboard using the token, but successfully performed the local manifest evaluation first.

---

## Task 2 — Docker Host Security Benchmarking

### CIS benchmark output
- Saved to: `labs/lab7/hardening/docker-bench-results.txt`
- Tool version: Docker Bench Security v1.6.0 (run from source)

### Summary statistics (from current run)
- PASS: **35**
- WARN: **74**
- FAIL: **0**
- INFO: **115**

> Note: On macOS/Docker Desktop, some Linux-host checks are not directly applicable (`systemctl`, Linux file paths, GNU/BSD command differences). These appear as informational warnings/noise in output.

### Failure analysis and remediation
No explicit `[FAIL]` entries were reported in this run.

### High-priority WARN analysis (security impact + remediation)

1. **2.9 User namespace support not enabled**
   - **Impact:** weaker user isolation between container and host kernel identities.
   - **Remediation:** enable user namespace remapping where supported and compatible.

2. **2.14 `no-new-privileges` not daemon-enforced**
   - **Impact:** processes may still gain privilege via setuid/setgid binaries.
   - **Remediation:** enforce `--security-opt=no-new-privileges` in runtime policies.

3. **5.11 / 5.12 memory and CPU limits missing (for some running containers)**
   - **Impact:** DoS risk via resource exhaustion.
   - **Remediation:** set `--memory`, `--memory-swap`, `--cpus` for all production containers.

4. **5.29 PIDs limit not set**
   - **Impact:** fork bomb process-exhaustion risk.
   - **Remediation:** set `--pids-limit` based on workload profile.

5. **4.6 missing HEALTHCHECK in multiple images**
   - **Impact:** poor failure detection; delayed recovery.
   - **Remediation:** add robust, app-level health probes.

---

## Task 3 — Deployment Security Configuration Analysis

### Collected comparison evidence
- Saved to: `labs/lab7/analysis/deployment-comparison.txt`
- Functional test:
  - Default: HTTP 200
  - Hardened: HTTP 200
  - Production: HTTP 200

### 1) Configuration comparison table

| Parameter | Default (`juice-default`) | Hardened (`juice-hardened`) | Production (`juice-production`) |
|---|---|---|---|
| `CapDrop` | none | `ALL` | `ALL` |
| `CapAdd` | none | none | `NET_BIND_SERVICE` |
| `SecurityOpt` | none | `no-new-privileges` | `no-new-privileges` |
| Memory | unlimited | `512m` | `512m` |
| Memory swap | unlimited | host default (~1GiB shown) | `512m` |
| CPU | unlimited | `1.0` | `1.0` |
| PIDs limit | none | none | `100` |
| Restart policy | `no` | `no` | `on-failure:3` |

### 2) Security measure analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
- Linux capabilities split root privileges into smaller units.
- Dropping all capabilities prevents broad privilege abuse after compromise.
- `NET_BIND_SERVICE` is re-added only if binding low ports (<1024) is needed.
- Trade-off: better security, but apps needing extra kernel privileges may break.

#### b) `--security-opt=no-new-privileges`
- Prevents process from gaining additional privileges via setuid/setgid or file capabilities.
- Blocks privilege-escalation paths after initial code execution.
- Downside: software depending on privilege elevation may fail.

#### c) `--memory=512m` and `--cpus=1.0`
- Without limits, one container can starve host resources and impact other services.
- Memory limits reduce DoS/blast radius of leaks or malicious load.
- Too-low limits can cause OOM kills, latency spikes, and instability.

#### d) `--pids-limit=100`
- A fork bomb rapidly spawns processes until the system cannot create new ones.
- PID limits cap process count per container and preserve host stability.
- Right value depends on observed normal peak process count + headroom.

#### e) `--restart=on-failure:3`
- Restarts container when it exits non-zero, up to 3 retries.
- Useful for transient crashes; risky if persistent crash loop masks root cause.
- `on-failure` restarts only on failure; `always` restarts regardless of exit reason.

### 3) Critical thinking answers

1. **Which profile for development? Why?**
   - **Hardened**: close to production while still simple and debuggable.

2. **Which profile for production? Why?**
   - **Production**: least privilege + resource controls + PID limits + restart policy.

3. **What real-world problem do resource limits solve?**
   - Prevent noisy-neighbor incidents and availability loss from runaway processes.

4. **If attacker exploits Default vs Production, what is blocked in Production?**
   - Harder privilege escalation (`no-new-privileges`), reduced kernel privilege surface (`cap-drop`), constrained DoS impact (memory/CPU/PIDs), controlled crash behavior (`on-failure:3`).

5. **Additional hardening to add**
   - Read-only root filesystem, drop all writable mounts unless required.
   - Non-root UID/GID with explicit `USER` and rootless mode where feasible.
   - Custom seccomp/apparmor profile.
   - Image signature verification and admission policies.
   - Runtime monitoring and egress network restrictions.

---

## Files produced
- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/snyk-results.txt` (currently auth error)
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/analysis/deployment-comparison.txt`

