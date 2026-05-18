# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Student Information

- Lab: Lab 7 — Container Security
- Topic: Image Scanning & Deployment Hardening
- Target Image: `bkimminich/juice-shop:v19.0.0`

---

# Task 1 — Image Vulnerability & Configuration Analysis

## 1.1 Environment Setup

Created the following working directory structure:

```bash
mkdir -p labs/lab7/{scanning,hardening,analysis}
cd labs/lab7
```

Pulled the target image locally:

```bash
docker pull bkimminich/juice-shop:v19.0.0
```

---

## 1.2 Docker Scout Vulnerability Analysis

Executed vulnerability scanning using Docker Scout:

```bash
docker scout cves bkimminich/juice-shop:v19.0.0
```

The scan identified several critical vulnerabilities, primarily originating from the `vm2` sandbox package and Node.js runtime dependencies.

### Top 5 Critical / High Vulnerabilities

| CVE ID | Package | Severity | Description / Impact | Fixed Version |
|---|---|---|---|---|
| CVE-2026-22709 | vm2 3.9.17 | Critical | Protection mechanism failure allowing sandbox escape and potential remote code execution. Attackers could fully compromise the containerized application. | 3.10.2 |
| CVE-2023-37903 | vm2 3.9.17 | Critical | OS command injection vulnerability enabling arbitrary command execution inside the application environment. | Not fixed |
| CVE-2023-37466 | vm2 3.9.17 | Critical | Code injection vulnerability allowing attackers to execute malicious JavaScript outside the intended sandbox restrictions. | 3.10.0 |
| CVE-2023-32314 | vm2 3.9.17 | Critical | Injection vulnerability affecting downstream components and enabling arbitrary code execution. | 3.9.18 |
| CVE-2025-55130 | node 22.18.0 | Critical | Vulnerability affecting the Node.js runtime shipped in the base image. A compromised runtime can affect the entire application stack. | 22.22.0 |

### Docker Scout Observations

The majority of critical vulnerabilities are connected to the `vm2` package. Since `vm2` is intended to isolate untrusted JavaScript execution, vulnerabilities in this package are especially dangerous because they completely defeat the purpose of sandboxing.

The image also uses a distroless Node.js base image:

```Dockerfile
FROM gcr.io/distroless/nodejs22-debian12
```

While distroless images reduce attack surface compared to full operating system images, vulnerable application dependencies still introduce major security risks.

---

## 1.3 Snyk Vulnerability Comparison

Executed Snyk container scanning:

```bash
docker run --rm \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 --severity-threshold=high
```

### Critical Findings from Snyk

| Vulnerability | Severity | Package | Notes |
|---|---|---|---|
| Sandbox Bypass | Critical | vm2@3.9.17 | Allows escaping the JavaScript sandbox environment |
| Remote Code Execution (RCE) | Critical | vm2@3.9.17 | Enables arbitrary remote code execution |
| Remote Code Execution (RCE) | Critical | vm2@3.9.17 | Additional RCE vector identified by Snyk |
| Arbitrary Code Injection | Critical | marsdb@0.6.11 | No upgrade or patch currently available |
| Uncaught Exception | Critical | multer@1.4.5-lts.2 | Can lead to denial of service and application instability |

### Comparison Between Docker Scout and Snyk

Docker Scout focused primarily on operating system packages and image dependency vulnerabilities, while Snyk provided additional insight into vulnerable Node.js application dependencies.

Snyk also identified application-level vulnerabilities that were not immediately highlighted in Docker Scout results, including issues in `marsdb` and `multer`.

Using multiple scanners provides broader visibility into container security posture because different tools maintain different vulnerability databases and detection logic.

---

## 1.4 Dockle Configuration Assessment

Executed Dockle security configuration analysis:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  bkimminich/juice-shop:v19.0.0
```

### Dockle Findings

| Level | Check ID | Finding | Security Impact |
|---|---|---|---|
| INFO | CIS-DI-0005 | Docker Content Trust not enabled | Images are not cryptographically verified before pull/build operations |
| INFO | CIS-DI-0006 | Missing HEALTHCHECK instruction | Orchestrators cannot automatically detect unhealthy containers |
| INFO | DKL-LI-0003 | Unnecessary files included (.DS_Store files) | Extra files slightly increase attack surface and image size |
| SKIP | DKL-LI-0001 | Could not detect password files | Distroless image structure prevented validation |

### Security Posture Assessment

The image appears more secure than many standard container images because it uses a distroless Node.js base image and non-root ownership during copy operations:

```Dockerfile
COPY --from=installer --chown=65532:0 /juice-shop .
```

This indicates the application is likely not running directly as root inside the container.

However, several major security concerns still exist:

1. Multiple critical RCE vulnerabilities exist in application dependencies
2. No HEALTHCHECK instruction is defined
3. Docker Content Trust is not enabled
4. Vulnerable dependencies remain unpatched
5. Some unnecessary files are included in the final image

### Recommended Security Improvements

1. Upgrade `vm2` immediately to a patched version
2. Upgrade Node.js runtime to a fixed release
3. Add a `HEALTHCHECK` instruction
4. Enable Docker Content Trust
5. Remove unnecessary files during build
6. Continuously scan images in CI/CD pipelines
7. Pin dependencies and regularly apply security patches

---

# Task 2 — Docker Host Security Benchmarking

## 2.1 CIS Docker Benchmark Execution

Attempted to execute the provided CIS Docker Benchmark command:

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro --label docker_bench_security \
  docker/docker-bench-security
```

### Observed Compatibility Issues

During execution, two compatibility problems were encountered:

1. The `-e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST` environment variable handling no longer behaves consistently on modern Docker installations when the variable is unset.

2. The benchmark container was unable to properly communicate with the Docker socket in the current environment, preventing full benchmark execution.

These issues appear related to differences between older benchmark documentation and modern Docker runtime behavior, especially in restricted or rootless Docker environments.

### Troubleshooting and Analysis

The benchmark tool itself remains valid and widely used, but execution can depend heavily on:

- Docker daemon permissions
- Host operating system configuration
- Rootless vs rootful Docker setup
- Container runtime restrictions
- Socket mount permissions

The Docker socket issue specifically demonstrates an important security principle:

> Access to `/var/run/docker.sock` effectively grants root-equivalent control over the Docker host.

Many hardened environments intentionally restrict socket access to reduce the risk of container breakout or host compromise.

### Expected CIS Benchmark Areas

Even though the benchmark could not fully complete in this environment, the tool is designed to assess:

1. Host configuration security
2. Docker daemon configuration
3. Docker daemon configuration files
4. Container image and build security
5. Container runtime security

### Security Impact Discussion

The CIS Docker Benchmark is important because it identifies insecure defaults and configuration weaknesses that could allow:

- Privilege escalation
- Container breakout
- Unauthorized host access
- Weak isolation between workloads
- Insecure daemon exposure

### Proposed Remediation Practices

Recommended Docker hardening practices include:

1. Restrict access to the Docker socket
2. Run containers as non-root users
3. Enable Docker Content Trust
4. Apply resource limits to all containers
5. Drop unnecessary Linux capabilities
6. Use seccomp and AppArmor profiles
7. Continuously audit daemon configuration
8. Keep Docker Engine updated

---

# Task 3 — Deployment Security Configuration Analysis

## 3.1 Deployment Profiles

Three deployment profiles were tested:

1. Default configuration
2. Hardened configuration
3. Production-hardened configuration

All containers started successfully and returned HTTP 200 responses.

---

## 3.2 Functionality Test Results

| Profile | HTTP Status |
|---|---|
| Default | HTTP 200 |
| Hardened | HTTP 200 |
| Production | HTTP 200 |

All profiles remained functional despite additional security restrictions.

---

## 3.3 Resource Usage Comparison

| Container | CPU Usage | Memory Usage | Memory % |
|---|---|---|---|
| juice-default | 0.45% | 172.6 MiB / 15.25 GiB | 1.11% |
| juice-hardened | 0.48% | 93.5 MiB / 512 MiB | 18.26% |
| juice-production | 0.60% | 93.05 MiB / 512 MiB | 18.17% |

### Observations

The default profile had unrestricted memory access to the host system, while the hardened and production profiles enforced strict limits.

Resource limiting reduced potential abuse opportunities and improved workload isolation.

---

## 3.4 Security Configuration Comparison

| Setting | Default | Hardened | Production |
|---|---|---|---|
| Capabilities Dropped | None | ALL | ALL |
| Capabilities Added | None | None | NET_BIND_SERVICE |
| Security Options | None | no-new-privileges | no-new-privileges |
| Memory Limit | Unlimited | 512 MB | 512 MB |
| CPU Limit | Unlimited | 1 CPU | 1 CPU |
| PID Limit | Unlimited | Unlimited | 100 |
| Restart Policy | no | no | on-failure |

---

# Security Measure Analysis

## a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

### What are Linux capabilities?

Linux capabilities divide root privileges into smaller individual permissions. Instead of giving a process full root access, specific capabilities can be granted only when required.

Examples include:
- Network administration
- Raw socket creation
- Binding to privileged ports
- System time modification

### What attack vector does dropping ALL capabilities prevent?

Dropping all capabilities prevents privilege escalation attacks where attackers attempt to abuse elevated kernel-level permissions from inside a compromised container.

This significantly reduces the impact of container compromise.

### Why add back `NET_BIND_SERVICE`?

`NET_BIND_SERVICE` allows applications to bind to privileged ports below 1024.

Some production applications require this capability to expose standard ports such as:
- 80 (HTTP)
- 443 (HTTPS)

### Security Trade-Off

Adding back only required capabilities follows the principle of least privilege:
- Better security than full root access
- Still allows required functionality
- Reduced attack surface

---

## b) `--security-opt=no-new-privileges`

### What does this flag do?

This flag prevents processes inside the container from gaining additional privileges during execution.

Even if a binary has the SUID bit set, it cannot elevate privileges.

### What attacks does it prevent?

It helps prevent:
- Privilege escalation
- SUID exploitation
- Escaping restricted execution contexts

### Downsides

Some applications that legitimately require privilege escalation may fail to function correctly.

However, most modern containerized applications do not require privilege escalation.

---

## c) `--memory=512m` and `--cpus=1.0`

### What happens without resource limits?

Without limits:
- Containers can consume all available host resources
- One compromised container can affect the entire host
- Denial-of-service conditions become more likely

### What attacks do memory limits help prevent?

Memory limits help mitigate:
- Memory exhaustion attacks
- Fork bombs
- Resource starvation attacks

### Risks of limits that are too low

If limits are too restrictive:
- Applications may crash
- Performance may degrade
- Containers may restart repeatedly

Resource limits must be carefully tuned for workload requirements.

---

## d) `--pids-limit=100`

### What is a fork bomb?

A fork bomb rapidly creates huge numbers of processes until the host system becomes unusable.

This can completely exhaust PID resources.

### How does PID limiting help?

PID limits restrict how many processes a container can create.

This prevents:
- Fork bombs
- Runaway process spawning
- Host instability

### Determining the correct limit

The limit should be:
- High enough for normal application behavior
- Low enough to prevent abuse

Monitoring real production workloads helps determine safe thresholds.

---

## e) `--restart=on-failure:3`

### What does this policy do?

The container automatically restarts if it exits with an error, up to three retry attempts.

### When is auto-restart beneficial?

Useful for:
- Temporary failures
- Crashes caused by transient issues
- Improving service availability

### When can it be risky?

Automatic restart can hide:
- Persistent application failures
- Security issues
- Misconfigurations

### `on-failure` vs `always`

| Policy | Behavior |
|---|---|
| on-failure | Restarts only after failed exits |
| always | Always restarts regardless of exit reason |

`on-failure` is safer because it avoids restarting intentionally stopped containers.

---

# Critical Thinking Questions

## 1. Which profile is best for DEVELOPMENT?

The default profile is best for development because it provides fewer restrictions and maximum flexibility for debugging and testing.

Developers often need unrestricted access for troubleshooting, package installation, and experimentation.

---

## 2. Which profile is best for PRODUCTION?

The production profile is best for production deployments because it applies multiple layers of hardening:

- Capability restrictions
- Resource limits
- PID limiting
- Automatic restart policy
- Privilege escalation prevention

These controls significantly reduce the impact of successful attacks.

---

## 3. What real-world problem do resource limits solve?

Resource limits prevent a single container from exhausting shared host resources.

This protects:
- Multi-tenant systems
- Kubernetes nodes
- Shared CI/CD runners
- Cloud infrastructure

Without limits, one compromised or malfunctioning container could impact all workloads running on the host.

---

## 4. If an attacker exploits Default vs Production, what actions are blocked in Production?

In the production profile, attackers would face several restrictions:

- Limited Linux capabilities
- No privilege escalation
- Restricted process creation
- Restricted memory usage
- Restricted CPU usage

This makes:
- Container breakout
- Host compromise
- Denial-of-service attacks
- Resource exhaustion

significantly harder compared to the default profile.

---

## 5. Additional Hardening Recommendations

Additional hardening measures could include:

1. Read-only root filesystem
2. Custom seccomp profiles
3. AppArmor or SELinux enforcement
4. Rootless containers
5. Network segmentation
6. Image signing and verification
7. Continuous vulnerability scanning
8. Runtime threat detection
9. Kubernetes Pod Security Standards
10. Multi-stage minimal container builds

---

# Conclusion

This lab demonstrated the importance of layered container security practices.

Key findings include:

- Container images can contain severe vulnerabilities even when using minimal base images
- Multiple scanning tools provide broader security visibility
- Resource limits and capability restrictions greatly improve isolation
- Production container deployments should never rely on default configurations
- Defense-in-depth is critical for modern containerized workloads

The hardened and production profiles showed that strong security restrictions can be applied while maintaining full application functionality.
