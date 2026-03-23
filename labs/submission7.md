# Lab 7 Submission - Container Security: Image Scanning & Deployment Hardening

## Student / Context
- Name: `Danil Fishchenko`
- Branch: `feature/lab7`
- Scan date: `2026-03-23 19:21:21 MSK`
- Repository root: `DevSecOps-Intro/`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Host OS: `macOS`
- Docker platform context:
  - Docker Desktop `4.63.0`
  - Docker Engine `29.2.1`
  - Docker Scout `v1.20.0`
  - Engine security options: `seccomp=builtin`, `cgroupns`
- Tools used:
  - `docker scout`
  - `goodwithtech/dockle:latest`
  - `snyk/snyk:docker`
  - `docker/docker-bench-security` official scripts
  - `docker:cli` as a compatibility wrapper for the official `docker-bench-security` scripts on Docker Desktop

## Scope And Method
This lab evaluates container security at three layers:

1. Image layer - known vulnerabilities and image-level security posture.
2. Docker host / daemon layer - CIS benchmark style hardening checks.
3. Runtime layer - how different `docker run` security profiles change blast radius if the app is exploited.

Important environment notes:

- The required `Docker Scout` scan worked normally on this host.
- The required `Dockle` scan worked normally on this host.
- The `Snyk` container image did not provide an `arm64` manifest, so I reran it with `--platform linux/amd64`.
- After architecture emulation was fixed, `Snyk` still failed with `401 Unauthorized`, which confirms that a valid `SNYK_TOKEN` or prior `snyk auth` is required in this environment.
- The stock lab command for `docker-bench-security` failed on Docker Desktop because `-v /etc:/etc:ro` conflicted with Docker's own `/etc/hostname` mount, and the old bundled Docker CLI in that image could not talk to the current daemon reliably. To keep the benchmark method intact, I extracted the official benchmark scripts from the image and ran them inside a modern `docker:cli` container with the same host mounts. The working benchmark output is saved as `labs/lab7/hardening/docker-bench-results.txt`, and the stock failure log is preserved separately.
- The CIS benchmark reflects the full local Docker Desktop environment and all running containers at scan time, not only Juice Shop.

## Task 1 - Image Vulnerability And Configuration Analysis

### 1.1 Environment Setup
```bash
mkdir -p labs/lab7/scanning labs/lab7/hardening labs/lab7/analysis
docker pull bkimminich/juice-shop:v19.0.0
```

### 1.2 Commands Used
```bash
docker scout cves bkimminich/juice-shop:v19.0.0 > labs/lab7/scanning/scout-cves.txt

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  bkimminich/juice-shop:v19.0.0 > labs/lab7/scanning/dockle-results.txt

# First run from the lab instructions failed because the image has no linux/arm64 manifest.
docker run --rm \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 \
  --severity-threshold=high > labs/lab7/scanning/snyk-results.txt 2>&1

# Architecture-adjusted rerun to confirm the real blocker.
docker run --rm --platform linux/amd64 \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 \
  --severity-threshold=high > labs/lab7/scanning/snyk-results-amd64.txt 2>&1

docker image inspect bkimminich/juice-shop:v19.0.0 \
  --format 'User={{json .Config.User}} Healthcheck={{json .Config.Healthcheck}}'
```

### 1.3 Docker Scout Overview
`Docker Scout` reported:

- `11 Critical`
- `65 High`
- `30 Medium`
- `5 Low`
- `7 Unspecified`
- `1004` packages analyzed
- Base image: `gcr.io/distroless/nodejs22-debian12:latest`

This is a strong example of why "distroless" does not automatically mean "safe". The runtime is slimmer and non-root, but the application dependency tree still contains many severe npm findings.

### 1.4 Top 5 Critical / High Vulnerabilities

| CVE / Advisory | Package | Severity | Fixed Version | Why It Matters |
|---|---|---:|---|---|
| `CVE-2026-22709` | `vm2 3.9.17` | Critical | `3.10.2` | Protection mechanism failure in a sandbox library. If the app relies on `vm2` for isolation, a sandbox escape can turn user-controlled code into arbitrary code execution. |
| `CVE-2023-37903` | `vm2 3.9.17` | Critical | `not fixed` | OS command injection in `vm2`. This is especially severe because the dependency exists exactly to contain untrusted code, so failure defeats the trust boundary. |
| `CVE-2019-10744` | `lodash 2.4.2` | Critical | `4.17.12` | Prototype pollution can corrupt application object state and, depending on the code path, lead to privilege bypass, logic abuse, or denial of service. |
| `CVE-2023-46233` | `crypto-js 3.3.0` | Critical | `4.2.0` | Broken or risky cryptographic behavior weakens confidentiality and integrity guarantees. Any feature that depends on this library can inherit insecure crypto assumptions. |
| `CVE-2021-44906` | `minimist 0.2.4` | Critical | `1.2.6` | Another severe object/prototype manipulation issue. Even "small" utility packages can become high-value attack surfaces when they are deeply reused transitively. |

Additional high-risk observation:

- The base Node runtime itself (`node 22.18.0`) carries `1 Critical` and `4 High` findings in Scout, with the fixed version reported as `22.22.0`. That means even before touching application code, the image should be rebuilt on a newer Node patch level.

### 1.5 Dockle Configuration Findings
`Dockle` did not report any `FATAL` or `WARN` findings for this image. That is notable and positive. The output only contained:

- `INFO CIS-DI-0005`: Docker Content Trust is not enabled.
- `INFO CIS-DI-0006`: no `HEALTHCHECK` instruction in the image.
- `INFO DKL-LI-0003`: unnecessary files present, including `.DS_Store` files in `node_modules`.
- `SKIP DKL-LI-0001`: password file checks could not be evaluated, which is not surprising for a distroless-style image.

Security interpretation:

- Missing `HEALTHCHECK` is an operational security issue because unhealthy containers may stay in service longer than they should, which increases mean time to detect failure and can hide exploitation side effects.
- Disabled content trust means image authenticity is not being enforced at pull time. In a stronger supply-chain posture, this would be replaced by signature verification and admission policy checks.
- Unnecessary files are low severity, but they still represent avoidable attack surface and sloppy build hygiene.

### 1.6 Snyk Comparison Status
The Snyk comparison could not be completed successfully in this environment for two separate, reproducible reasons:

1. The default `snyk/snyk:docker` image pull failed on `arm64` because no matching manifest was available.
2. The `amd64` rerun under emulation reached the scanner, but then failed with:
   - `ERROR Authentication error (SNYK-0005)`
   - `Status: 401 Unauthorized`

Conclusion:

- The remaining blocker is credentials, not connectivity.
- To complete the Snyk portion fully on this host, I would need a valid `SNYK_TOKEN` or a prior authenticated `snyk auth` session.

### 1.7 Security Posture Assessment
The image posture is mixed:

- Positive:
  - The image runs as non-root user `65532`.
  - The base image is distroless, which reduces some surface area compared with a full distro image.
  - `Dockle` found no `FATAL` or `WARN` image-configuration issues.
- Negative:
  - `Docker Scout` still reports many serious dependency vulnerabilities.
  - The runtime base (`node 22.18.0`) is itself behind on security fixes.
  - There is no `HEALTHCHECK`.
  - There is no integrity enforcement such as content trust / signature verification at pull time.

Recommended improvements:

1. Rebuild on a patched Node 22 image level.
2. Upgrade or replace vulnerable npm dependencies, especially `vm2`, `lodash`, `crypto-js`, `jsonwebtoken`, and `minimist`.
3. Add a `HEALTHCHECK` to make failures visible to the platform.
4. Enable signature verification / trusted image promotion in CI/CD.
5. Generate an SBOM and enforce a "no Critical vulnerabilities" release gate.

## Task 2 - Docker Host Security Benchmarking

### 2.1 Commands Used
Stock lab command attempted first:

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro --label docker_bench_security \
  docker/docker-bench-security > labs/lab7/hardening/docker-bench-results-stock-failure.txt 2>&1
```

Observed stock failure on Docker Desktop:

- read-only `/etc` bind prevented Docker from mounting `/etc/hostname`
- the old CLI bundled in `docker/docker-bench-security` also had daemon-compatibility issues

Working execution using the official extracted benchmark scripts:

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v "$(pwd)/labs/lab7/hardening/docker-bench-src":/src \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/hostetc:ro \
  docker:cli sh -lc '
    apk add --no-cache iproute2 procps util-linux coreutils >/dev/null &&
    cp -a /hostetc/. /etc/ 2>/dev/null || true &&
    cd /src &&
    sh docker-bench-security.sh
  ' > labs/lab7/hardening/docker-bench-results.txt 2>&1
```

### 2.2 Summary Statistics

| Metric | Count |
|---|---:|
| `PASS` | `28` |
| `WARN` | `30` |
| `FAIL` | `0` |
| `INFO` | `44` |
| `NOTE` | `10` |
| Total checks | `105` |
| Score | `-3` |

Important interpretation:

- There were no formal `FAIL` results in this run.
- The host still has many meaningful `WARN` results, so "no FAIL" does not mean "secure".
- A number of `INFO` lines were caused by Docker Desktop abstraction layers, for example missing `/etc/docker/daemon.json` or other Linux host files not exposed in the same way as on a native Linux host.

### 2.3 High-Value Warning Analysis
I focused on warnings that represent real security risk instead of platform noise.

#### 1. `2.8 - Enable user namespace support`
Impact:

- Without user namespaces, container UIDs map more directly to host-root semantics.
- This increases the impact of container breakout or daemon misconfiguration.

Remediation:

- Enable user namespace remapping or move to a rootless runtime / rootless Docker where practical.

#### 2. `2.12 - Ensure centralized and remote logging is configured`
Impact:

- Local-only logs are easier to tamper with and harder to preserve during incident response.
- Distributed services become difficult to investigate after crashes or compromise.

Remediation:

- Send container logs to centralized logging infrastructure such as Loki, Elasticsearch, or a cloud logging service.

#### 3. `2.18` and `5.25 - Ensure containers are restricted from acquiring new privileges`
Impact:

- Containers without `no-new-privileges` can still gain privileges through `setuid` binaries or similar exec paths.
- This matters during post-exploitation, especially when an attacker can execute arbitrary binaries inside a compromised container.

Remediation:

- Set `--security-opt=no-new-privileges` for standalone containers.
- In Kubernetes, set `allowPrivilegeEscalation: false`.

#### 4. `5.4 - Ensure privileged containers are not used`
Impact:

- Privileged containers remove most isolation guarantees and are a classic container-escape risk multiplier.
- In my benchmark run, the active `kind` nodes triggered this warning.

Remediation:

- Avoid `--privileged` unless there is a strict infrastructure reason.
- For Kubernetes test clusters, isolate them from normal application workloads and do not reuse the same Docker host for sensitive services.

#### 5. `5.31 - Ensure the Docker socket is not mounted inside any containers`
Impact:

- Mounting `/var/run/docker.sock` effectively gives the container control over the Docker daemon.
- That can lead to host compromise through container creation, volume mounts, or image execution.

Remediation:

- Remove direct socket mounts from application containers.
- Use scoped APIs, sidecars, or dedicated build runners instead of exposing the daemon socket broadly.

#### 6. `5.10`, `5.11`, `5.12` - missing resource limits and read-only root filesystem
Impact:

- Unlimited CPU and memory enable denial-of-service from a single compromised or buggy container.
- Writable root filesystems make persistence and tampering easier.

Remediation:

- Set explicit CPU, memory, and PID limits.
- Use `--read-only` plus `tmpfs` / named volumes only where write access is truly required.

### 2.4 Benchmark Interpretation
The benchmark surfaced real weaknesses in the local Docker estate:

- missing `no-new-privileges`
- containers with no CPU / memory limits
- writable root filesystems
- privileged containers
- Docker socket mounts
- missing health checks

These are exactly the kinds of findings that matter in production because they increase blast radius after an exploit. Even though this host is Docker Desktop and not a dedicated Linux server, the benchmark still usefully shows that runtime hardening is inconsistent across the environment.

## Task 3 - Deployment Security Configuration Analysis

### 3.1 Commands Used
I first ran the profiles from the lab instructions. The `production` command needed one platform-specific adjustment:

- the lab uses `--security-opt=seccomp=default`
- on this Docker Engine, that value was interpreted as a file path and failed
- the equivalent working form was `--security-opt=seccomp=builtin`

Executed profiles:

```bash
docker run -d --name juice-default -p 3001:3000 \
  bkimminich/juice-shop:v19.0.0

docker run -d --name juice-hardened -p 3002:3000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m \
  --cpus=1.0 \
  bkimminich/juice-shop:v19.0.0

docker run -d --name juice-production -p 3003:3000 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt=seccomp=builtin \
  --memory=512m \
  --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  --restart=on-failure:3 \
  bkimminich/juice-shop:v19.0.0
```

Evidence collection:

```bash
curl -s -o /dev/null -w 'Default: HTTP %{http_code}\n' http://localhost:3001
curl -s -o /dev/null -w 'Hardened: HTTP %{http_code}\n' http://localhost:3002
curl -s -o /dev/null -w 'Production: HTTP %{http_code}\n' http://localhost:3003

docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}' \
  juice-default juice-hardened juice-production

docker inspect <container> --format '...'
```

### 3.2 Functional Verification
All three profiles stayed functional:

| Profile | HTTP Result | Observation |
|---|---:|---|
| `default` | `200` | App worked with no runtime restrictions. |
| `hardened` | `200` | Basic security restrictions did not break the app. |
| `production` | `200` | Stronger hardening still preserved normal service behavior. |

Observed resource snapshot:

| Container | CPU | Memory Usage |
|---|---:|---:|
| `juice-default` | `0.64%` | `156.6 MiB / 5.786 GiB` |
| `juice-hardened` | `0.63%` | `105.8 MiB / 512 MiB` |
| `juice-production` | `0.59%` | `92.55 MiB / 512 MiB` |

### 3.3 Configuration Comparison Table

| Setting | `default` | `hardened` | `production` |
|---|---|---|---|
| Image user | `65532` | `65532` | `65532` |
| `CapDrop` | `null` | `["ALL"]` | `["ALL"]` |
| `CapAdd` | `null` | `null` | `["CAP_NET_BIND_SERVICE"]` |
| `SecurityOpt` | `null` | `["no-new-privileges"]` | `["no-new-privileges","seccomp=builtin"]` |
| Memory | unlimited | `512 MiB` | `512 MiB` |
| Memory swap | unlimited | `1 GiB` effective default | `512 MiB` |
| CPU | unlimited | `1 CPU` | `1 CPU` |
| PID limit | none | none | `100` |
| Restart policy | `no` | `no` | `on-failure:3` |
| Read-only rootfs | `false` | `false` | `false` |

### 3.4 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
Linux capabilities split "root-like" powers into smaller privileges such as raw networking, mount operations, process tracing, and binding low ports.

Why drop all capabilities:

- It minimizes what a compromised process can do against the kernel and surrounding system.
- This reduces post-exploitation options such as packet capture, raw socket abuse, or other privileged kernel interactions.

Why add back `NET_BIND_SERVICE`:

- In general, it is only needed when an application must bind to ports below `1024`.
- In this specific Juice Shop setup the app listens on `3000`, so the capability is not functionally required here. In this lab it mostly demonstrates the principle "remove everything, add back only what is actually necessary".

Security trade-off:

- Fewer capabilities improve isolation.
- Adding back a capability should be justified by a real runtime requirement, otherwise it is unnecessary privilege.

#### b) `--security-opt=no-new-privileges`
This flag prevents the process and its children from gaining extra privileges during execution, including via `setuid` / `setgid` transitions.

What attack it helps prevent:

- Privilege escalation after code execution inside the container.
- It limits damage from malicious binaries or abused helper tools that would otherwise elevate privilege on exec.

Downsides:

- Some legacy software that expects `setuid` behavior can break.
- It may surface hidden assumptions in older images or admin/debug workflows.

#### c) `--memory=512m` and `--cpus=1.0`
Without resource limits:

- one container can starve the host
- a memory leak can trigger OOM conditions
- a malicious process can create noisy-neighbor denial of service

Memory limiting specifically helps contain:

- intentional heap exhaustion
- accidental leaks
- abuse patterns that try to crash or destabilize the node

Risk of setting limits too low:

- legitimate requests can fail
- the app can restart repeatedly
- latency may spike under normal load

The goal is not "lowest possible limit", but "measured limit plus safety margin".

#### d) `--pids-limit=100`
A fork bomb is a process-spawning loop that rapidly consumes all available process IDs and scheduler capacity.

Why PID limiting helps:

- it caps process explosion inside the container
- it protects the host and neighboring workloads from process-table exhaustion

How to choose the value:

- measure normal steady-state process and thread count
- include expected burst headroom
- keep the cap tight enough to stop abuse but high enough not to break normal runtime behavior

#### e) `--restart=on-failure:3`
This policy restarts the container only after a non-zero exit, and only up to three times.

When auto-restart is useful:

- transient crashes
- timing issues during dependency startup
- short-lived infrastructure hiccups

When it is risky:

- crash loops can hide persistent bugs
- repeated retries can amplify load or repeat unsafe side effects

`on-failure` vs `always`:

- `on-failure` is narrower and usually safer for application workloads because it only reacts to abnormal exit.
- `always` also restarts cleanly stopped containers, which can be undesirable during debugging, maintenance, or failure analysis.

### 3.5 Critical Thinking Questions

#### 1. Which profile for development?
I would choose `hardened` for development.

Reason:

- It kept the app fully functional (`HTTP 200`).
- It already enforces least privilege and basic resource limits.
- It is less likely than the production profile to interfere with developer workflows during debugging.

I would not choose `default` unless I specifically needed to reproduce a compatibility issue caused by hardening.

#### 2. Which profile for production?
I would choose `production`.

Reason:

- It preserves availability (`HTTP 200`).
- It drops all capabilities and only re-adds a narrow one.
- It enforces `no-new-privileges`.
- It limits CPU, memory, swap, and PIDs.
- It adds bounded restart behavior.
- It explicitly pins the built-in seccomp profile on this engine.

#### 3. What real-world problem do resource limits solve?
They solve multi-tenant stability and denial-of-service risk.

In real platforms, the common failure mode is not only "the app is hacked", but also:

- one bad release leaks memory
- one service pegs CPU
- one compromised workload deliberately exhausts host resources

Limits keep a single container from taking down the whole node.

#### 4. If an attacker exploits Default vs Production, what actions are blocked in Production?
Compared with `default`, an exploited process in `production` is constrained in several ways:

- it cannot rely on the default capability set because all capabilities are dropped first
- it cannot gain new privileges through exec transitions because of `no-new-privileges`
- it cannot consume unlimited memory or CPU
- it cannot spawn unlimited processes because of `--pids-limit=100`
- it is subject to the built-in seccomp policy explicitly
- restart behavior is bounded instead of uncontrolled

Important nuance:

- All three profiles still run as image user `65532`, so the image was already non-root before runtime hardening.
- The big difference is not "root vs non-root", but "unbounded default runtime vs explicitly constrained runtime".

#### 5. What additional hardening would I add?
I would add:

1. `--read-only` root filesystem.
2. `--tmpfs /tmp` or dedicated writable mounts for only the paths the app needs.
3. Explicit interface binding if public exposure is not required.
4. Custom AppArmor / SELinux policy where the platform supports it.
5. Image pinning by digest plus signature verification.
6. Health checks in the image.
7. Rootless container runtime where possible.
8. Network segmentation / firewalling so the container only reaches what it actually needs.

## Challenges Encountered

### 1. Snyk architecture and authentication blockers
- `snyk/snyk:docker` had no native `arm64` manifest.
- After switching to `--platform linux/amd64`, the scan reached Snyk but failed with `401 Unauthorized`.
- This is a real credentials issue, not a Docker networking issue.

### 2. `docker-bench-security` on Docker Desktop
- The stock lab command failed because a read-only bind of `/etc` blocked Docker's own hostname mount.
- The old Docker CLI bundled inside `docker/docker-bench-security` was also a poor fit for the modern Docker Desktop daemon.
- Rehosting the official scripts inside `docker:cli` preserved the benchmark logic while making it runnable on this machine.

### 3. `seccomp=default` vs `seccomp=builtin`
- The lab instruction uses `seccomp=default`.
- On this engine, the accepted built-in profile identifier is `builtin`.
- The working production run therefore used `seccomp=builtin`, which is the local equivalent of "use the default built-in seccomp profile".

## Evidence Files
- `labs/lab7/scanning/scout-cves.txt`
- `labs/lab7/scanning/dockle-results.txt`
- `labs/lab7/scanning/snyk-results.txt`
- `labs/lab7/scanning/snyk-results-amd64.txt`
- `labs/lab7/hardening/docker-bench-results.txt`
- `labs/lab7/hardening/docker-bench-results-stock-failure.txt`
- `labs/lab7/hardening/docker-bench-results-adapted.txt`
- `labs/lab7/hardening/docker-bench-results-workaround.txt`
- `labs/lab7/hardening/docker-bench-results-rehosted.txt`
- `labs/lab7/hardening/docker-bench-src/`
- `labs/lab7/analysis/deployment-comparison.txt`

## Final Conclusion
This lab demonstrates a realistic DevSecOps lesson:

- A container image can be non-root and still be highly vulnerable because of outdated dependencies.
- A host can look "mostly fine" but still expose dangerous runtime patterns such as privileged containers, Docker socket mounts, and missing `no-new-privileges`.
- Runtime hardening matters because it constrains blast radius even when the application itself is compromised.

The strongest practical takeaway is that container security is layered. Image scanning, daemon / host hardening, and runtime restrictions each solve different parts of the problem, and none of them is enough on its own.
