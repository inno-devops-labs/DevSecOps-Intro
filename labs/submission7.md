# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

**Target image:** `bkimminich/juice-shop:v19.0.0`  
**Environment:** macOS + OrbStack/Docker 28.5.2 on Apple Silicon (`arm64`)  
**Artifacts:** `labs/lab7/scanning/`, `labs/lab7/hardening/`, `labs/lab7/analysis/`

This submission documents the scans I ran, the evidence I collected, and the security analysis for the three required tasks. I did not create any Git commits. All outputs were generated locally from the repository root.

## What I Did

### Step 1: Prepared the lab directories

```bash
cd /Users/pavorkmert/DevSecOps
mkdir -p labs/lab7/{scanning,hardening,analysis}
```

### Step 2: Pulled the target image

```bash
docker pull bkimminich/juice-shop:v19.0.0
```

### Step 3: Installed Docker Scout and ran the CVE scan

```bash
curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
docker scout cves bkimminich/juice-shop:v19.0.0 | tee labs/lab7/scanning/scout-cves.txt
```

Docker Scout completed successfully and reported:

- **11 Critical**
- **65 High**
- **30 Medium**
- **5 Low**
- **7 Unspecified**

Total: **118 vulnerabilities in 48 packages**

### Step 4: Ran Snyk comparison

The `snyk/snyk:docker` image required `amd64` emulation on Apple Silicon, so I ran it with `--platform linux/amd64` and passed a valid `SNYK_TOKEN`:

```bash
docker run --platform linux/amd64 --rm \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 --severity-threshold=high \
  | tee labs/lab7/scanning/snyk-results.txt
```

Snyk authenticated successfully and produced real scan results for both the image OS layer and npm dependency tree:

- **OS/deb analysis:** **6 issues** found across 10 dependencies
- **Application/npm analysis:** **47 issues** found across 975 dependencies

The most important Snyk findings overlapped with Docker Scout: vulnerable `node@22.18.0`, `vm2@3.9.17`, `multer@1.4.5-lts.2`, `crypto-js@3.3.0`, `lodash@2.4.2`, `sequelize@6.37.7`, `socket.io@3.1.2`, `tar`, and `qs`.

Snyk still ended with a final **`403 Forbidden`** response after printing the vulnerability results. That appears to be an organization/account limitation on the Snyk side rather than an authentication failure, because the scanner had already completed dependency analysis and emitted findings into `labs/lab7/scanning/snyk-results.txt`.

### Step 5: Ran Dockle configuration analysis

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  bkimminich/juice-shop:v19.0.0 | tee labs/lab7/scanning/dockle-results.txt
```

Dockle produced:

- **FATAL:** 0
- **WARN:** 0
- **INFO:** 3
- **SKIP:** 1

### Step 6: Ran Docker Bench Security

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro --label docker_bench_security \
  docker/docker-bench-security | tee labs/lab7/hardening/docker-bench-results.txt
```

After removing ANSI color codes and counting only benchmark control lines, I got:

- **PASS:** 37
- **WARN:** 28
- **INFO:** 37
- **NOTE:** 10

The tool also reported:

- **Checks:** 105
- **Score:** 7

There were **no `FAIL` lines** in this run; the environment produced warnings rather than hard fails.

### Step 7: Deployed and compared three security profiles

Port `3001` was already occupied by a local Grafana container, so I used `3101-3103` instead. That does not affect the security comparison.

```bash
docker run -d --name juice-default -p 3101:3000 \
  bkimminich/juice-shop:v19.0.0

docker run -d --name juice-hardened -p 3102:3000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m \
  --cpus=1.0 \
  bkimminich/juice-shop:v19.0.0

docker run -d --name juice-production -p 3103:3000 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --memory=512m \
  --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  --restart=on-failure:3 \
  bkimminich/juice-shop:v19.0.0
```

I then saved the HTTP checks, resource usage, and `docker inspect` output to `labs/lab7/analysis/deployment-comparison.txt`.

All three profiles returned **HTTP 200**.

One environment-specific note: the lab text uses `--security-opt=seccomp=default`, but in this OrbStack setup that literal form expected a profile file path and failed with `open default: no such file or directory`. The Docker Bench run still confirmed that the engine default seccomp profile was enabled at runtime (`5.21 PASS`), so I kept the production profile hardened with the other runtime controls and relied on the engine default seccomp behavior.

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Top 5 Critical/High vulnerabilities

Below are the most important findings from `labs/lab7/scanning/scout-cves.txt`.

1. **CVE-2026-22709 in `vm2@3.9.17` — Critical**
   Package used for sandboxing JavaScript code. A protection mechanism failure in a sandbox library is especially dangerous because it can let attacker-controlled code escape expected isolation. Scout shows a fix in `3.10.2`.

2. **CVE-2023-37903 in `vm2@3.9.17` — Critical**
   OS command injection in `vm2`. If an attacker can influence code executed through this dependency, this can become remote command execution inside the application context. Scout reports **no fixed version** for the affected range in this line.

3. **CVE-2025-55130 in `node@22.18.0` — Critical**
   A critical vulnerability in the Node.js runtime itself. This is high impact because it affects the runtime layer used by the whole application rather than a small leaf dependency. Scout shows a fixed version in **Node 22.22.0**.

4. **CVE-2019-10744 in `lodash@2.4.2` — Critical**
   Prototype pollution in an obsolete Lodash branch. Prototype pollution can let attackers tamper with object behavior and sometimes pivot into authorization bypass or application logic compromise. Scout points to a fix in **4.17.12**.

5. **CVE-2023-46233 in `crypto-js@3.3.0` — Critical**
   Use of a broken or risky cryptographic algorithm. This matters because weak or flawed crypto libraries directly affect token protection, data confidentiality, and signature integrity. Scout shows a fix in **4.2.0**.

Other notable high-risk packages included `jsonwebtoken`, `tar`, `multer`, `ws`, `ip`, `sequelize`, and `socket.io`.

### 1.1.1 Snyk comparison

Snyk broadly confirmed the same risk areas as Docker Scout, but the two tools emphasized different layers:

1. **Snyk identified both OS and application issues separately.**
   It reported an OS-layer issue in `openssl/libssl3` and several runtime issues in `node@22.18.0`, then a much larger npm dependency set in the application layer.

2. **Snyk highlighted concrete upgrade paths.**
   The report mapped vulnerable libraries to upgrade targets such as `multer@2.1.1`, `sequelize@6.37.8`, `socket.io@4.7.0`, and `sanitize-html@1.7.1`, which is useful for remediation planning.

3. **Scout surfaced a larger raw total; Snyk produced a more remediation-oriented dependency view.**
   Docker Scout reported **118 vulnerabilities in 48 packages**, while Snyk reported **6 OS issues** and **47 application issues** with actionable dependency upgrade chains.

4. **Both tools consistently identified the highest-risk dependency clusters.**
   In particular, `vm2`, old JWT-related packages, outdated `lodash`, `crypto-js`, `multer`, `socket.io`, `tar`, and the Node runtime appeared as recurring security hotspots.

### 1.2 Dockle configuration findings

From `labs/lab7/scanning/dockle-results.txt`:

- **No FATAL findings**
- **No WARN findings**
- **INFO: `CIS-DI-0005` Enable Docker Content Trust**
  This matters because without content trust there is no signature verification of pulled images, increasing the risk of pulling tampered or spoofed images.

- **INFO: `CIS-DI-0006` Missing `HEALTHCHECK`**
  This matters because orchestration and monitoring cannot reliably distinguish a live process from a healthy application. That delays failure detection and automatic recovery.

- **INFO: `DKL-LI-0003` Unnecessary files in the image**
  Dockle found `.DS_Store` files inside `node_modules`. This is low severity, but it still indicates image hygiene issues and unnecessary content in the shipped artifact.

- **SKIP: `DKL-LI-0001` Avoid empty password**
  Dockle could not inspect password databases in this image, so this check was skipped rather than passed.

### 1.3 Security posture assessment

#### Does the image run as root?

No. `docker image inspect` showed:

```text
User="65532"
```

So the image is already configured to run as a non-root user. That is a positive security control and reduces the blast radius of a container breakout or in-container code execution.

#### Overall posture

The image is better than a naive container image because it does **not** run as root. However, its package inventory is still weak from a vulnerability perspective: Docker Scout found a large number of critical and high vulnerabilities concentrated in Node.js and npm dependencies.

#### Improvements I recommend

1. Rebuild on a newer base/runtime and update Node.js to a fixed `22.22.0+` release.
2. Upgrade or remove vulnerable npm dependencies, especially `vm2`, `lodash`, `jsonwebtoken`, `crypto-js`, `tar`, and `ws`.
3. Add a `HEALTHCHECK` instruction to improve runtime observability and recovery.
4. Enable signed image workflows with Docker Content Trust or Sigstore/Cosign-style verification.
5. Remove unnecessary files from the image and consider reducing package sprawl with a slimmer build/runtime split.

## Task 2 — Docker Host Security Benchmarking

### 2.1 Summary statistics

From `labs/lab7/hardening/docker-bench-results.txt`:

- **PASS:** 37
- **WARN:** 28
- **INFO:** 37
- **NOTE:** 10
- **Checks:** 105
- **Score:** 7

This run produced **no explicit FAIL results**. In this environment, the important issues surfaced as warnings.

### 2.2 Analysis of major warnings and remediations

The most relevant warnings were:

1. **Audit logging not configured (`1.5`, `1.6`, `1.7`, `1.11`)**
   Impact: weak forensic visibility. If Docker daemon actions or file changes are not audited, post-incident investigation becomes much harder.
   Remediation: configure host audit rules for the Docker daemon, `/var/lib/docker`, `/etc/docker`, and `daemon.json`.

2. **Docker daemon exposed on TCP without TLS (`2.6`)**
   Impact: very high. Anyone who can reach an unauthenticated or weakly protected Docker API can effectively control the host.
   Remediation: disable remote TCP exposure if not required; otherwise require mutual TLS and restrict network access.

3. **User namespace remapping not enabled (`2.8`)**
   Impact: a container UID maps directly to host privileges more than necessary, increasing risk if the container is compromised.
   Remediation: enable Docker user namespace remapping or use rootless/container-isolated approaches where practical.

4. **Authorization plugin not enabled (`2.11`)**
   Impact: Docker client actions rely mainly on daemon access control. Fine-grained policy enforcement is missing.
   Remediation: add a Docker authorization plugin or place the daemon behind stricter administrative controls.

5. **Centralized logging not configured (`2.12`)**
   Impact: security events stay local and are easier to lose or tamper with.
   Remediation: configure a remote log driver or ship logs to a central logging platform with retention and alerting.

6. **Live restore disabled (`2.14`)**
   Impact: containers may stop during daemon restarts, which hurts availability.
   Remediation: enable `live-restore` if the workload and platform support it.

7. **Containers not restricted from acquiring new privileges (`2.18`, `5.25`)**
   Impact: processes can exploit setuid binaries or similar mechanisms to gain more privileges than intended.
   Remediation: set `no-new-privileges` by default where compatible.

8. **Containers missing health checks (`4.6`, `5.26`)**
   Impact: degraded self-healing and weaker detection of broken-but-running services.
   Remediation: add `HEALTHCHECK` in images and connect it to orchestration restart logic.

9. **Missing memory/CPU/PID limits on several running containers (`5.10`, `5.11`, `5.28`)**
   Impact: noisy-neighbor conditions and denial-of-service become easier because one container can consume too many host resources.
   Remediation: define memory, CPU, and PID limits for all long-lived services.

10. **Docker socket mounted into a container (`5.31`)**
    Impact: effectively grants control over the Docker daemon and often the host.
    Remediation: remove Docker socket mounts unless absolutely required; replace with narrower APIs or isolated helper services.

### 2.3 Overall benchmark conclusion

The host is usable for development, but it is not production-hardened. The most serious gaps are remote daemon exposure without TLS, lack of audit coverage, missing namespace hardening, and inconsistent runtime controls across existing containers.

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration comparison table

Evidence source: `labs/lab7/analysis/deployment-comparison.txt`

| Profile | CapDrop | CapAdd | Security options | Memory | Memory+Swap | CPU | PIDs | Restart |
|---|---|---|---|---:|---:|---:|---:|---|
| Default | none | none | none | unlimited | unlimited | unlimited | unlimited | `no` |
| Hardened | `ALL` | none | `no-new-privileges` | 512 MiB | 1 GiB | 1 CPU | unlimited | `no` |
| Production | `ALL` | `NET_BIND_SERVICE` | `no-new-privileges` | 512 MiB | 512 MiB | 1 CPU | 100 | `on-failure:3` |

All three profiles remained functional:

- Default: **HTTP 200**
- Hardened: **HTTP 200**
- Production: **HTTP 200**

Observed memory usage during the test:

- Default: **100.4 MiB**
- Hardened: **86.12 MiB**
- Production: **82.17 MiB**

### 3.2 Security measure analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Linux capabilities split the power of `root` into smaller privilege units such as binding privileged ports, changing network settings, loading kernel modules, or changing file ownership. This is safer than giving a process full superuser power.

Dropping **all** capabilities removes the default ambient privilege set available to the container. This helps block privilege abuse after code execution, such as changing network stack behavior, using packet capture features, or abusing kernel-facing operations that the application does not actually need.

`NET_BIND_SERVICE` is normally needed only to bind ports below `1024`. In this lab the application listens on container port `3000`, so it is not strictly necessary for Juice Shop itself; it is better understood as an example of selectively adding back only the one capability a service truly requires.

The trade-off is compatibility: if you drop everything blindly, some applications break. The secure pattern is to start from `ALL` dropped and then add back the smallest necessary set.

#### b) `--security-opt=no-new-privileges`

This flag prevents a process and its children from gaining extra privileges through mechanisms like `setuid`, `setgid`, or file capabilities after the container starts.

It primarily helps prevent post-exploitation privilege escalation. If an attacker gets code execution inside the container, they cannot use a privileged helper binary to elevate further.

The downside is mostly compatibility. Applications that legitimately rely on gaining privileges after start may stop working. For most web applications, enabling it is a good default.

#### c) `--memory=512m` and `--cpus=1.0`

Without resource limits, a container can consume excessive host memory or CPU and starve neighboring services. That is both an operational risk and a security risk because simple abusive workloads can become denial-of-service conditions.

Memory limiting helps contain memory exhaustion attacks, accidental leaks, and runaway processes. CPU limits reduce the impact of crypto-mining, tight loops, and abusive request amplification.

The risk of limits that are too low is false instability: legitimate workloads may be OOM-killed, throttled, or become slow enough to trigger cascading failures.

#### d) `--pids-limit=100`

A fork bomb is a process explosion attack where a program rapidly creates child processes until the system runs out of process table slots or related resources.

PID limiting directly reduces the damage because the container cannot create more than the configured number of processes. That protects the host and neighboring containers from process exhaustion.

The correct limit depends on the application model. A single-process web app can use a low limit; applications with workers, shell-outs, or complex sidecars need a larger threshold validated in testing.

#### e) `--restart=on-failure:3`

This policy restarts the container only if it exits with a non-zero status, and it does so at most three times.

Auto-restart is useful for transient failures, crashes, and short-lived dependency issues. It improves availability without requiring immediate operator action.

It is risky when a service is crash-looping because logs can grow quickly, failures can be masked, and external systems can be hammered repeatedly. `on-failure` is safer than `always` for many applications because it avoids restarting cleanly stopped containers and prevents infinite loops when the retry count is bounded.

### 3.3 Critical thinking answers

#### 1. Which profile is best for development?

**Hardened** is the best development profile.

It keeps the app fully functional while adding meaningful protections (`cap-drop=ALL`, `no-new-privileges`, memory and CPU limits) without the tighter operational constraints of the production profile. It is strict enough to surface compatibility issues early but not so strict that it complicates local work.

#### 2. Which profile is best for production?

**Production** is the best production profile.

It keeps the same main hardening as the hardened profile and adds explicit swap control, PID limiting, and restart handling. Those controls directly reduce abuse impact and improve service resilience under failure conditions.

#### 3. What real-world problem do resource limits solve?

They solve noisy-neighbor and denial-of-service problems. In shared hosts or clusters, one buggy or abused container can otherwise consume enough CPU, RAM, or processes to degrade unrelated workloads or even destabilize the node.

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

In Production, the attacker faces several additional barriers:

1. They do not receive the container’s default Linux capabilities because everything was dropped first.
2. They cannot gain extra privileges later through `setuid`/`setgid` style escalation because of `no-new-privileges`.
3. They cannot spawn unlimited processes because of the PID limit.
4. They cannot consume unlimited memory or CPU because of explicit runtime limits.
5. A simple crash does not create an endless restart loop because restart attempts are bounded.

That does not eliminate exploitation, but it significantly reduces blast radius and post-exploitation options.

#### 5. What additional hardening would I add?

1. Add `--read-only` and mount only the few writable paths the app genuinely needs.
2. Add a custom non-root UID/GID policy and verify file ownership inside the image.
3. Use a dedicated user-defined bridge network instead of the default bridge.
4. Bind only to `127.0.0.1` locally or place the app behind a hardened reverse proxy.
5. Add an explicit health check and wire it to container orchestration.
6. Use signed images and admission/policy checks before deployment.
7. Add AppArmor/SELinux profiles where supported by the host.

## Final Conclusion

The Juice Shop image has one strong baseline control already in place: it runs as a non-root user. However, Docker Scout still found a large concentration of critical and high vulnerabilities in Node.js and npm dependencies, so the image should not be treated as production-ready without dependency remediation.

On the host side, Docker Bench showed that the local Docker environment is acceptable for lab work but not hardened enough for production, especially because of missing audit coverage, weak daemon exposure controls, and inconsistent runtime restrictions across existing containers.

The deployment comparison demonstrated the main lesson of the lab: secure runtime flags usually preserve application functionality while materially shrinking post-exploitation blast radius. In my run, the hardened and production profiles both returned **HTTP 200**, which shows that practical hardening can be applied without breaking the application.
