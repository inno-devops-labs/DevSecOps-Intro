# Lab 7 — Container Security: Image Scanning & Deployment Hardening

This report details the security analysis of the `bkimminich/juice-shop:v19.0.0` container image, the Docker host configuration, and a comparison of different deployment security profiles.

## Task 1: Image Vulnerability & Configuration Analysis

The container image was scanned for known vulnerabilities (CVEs) using Docker Scout and Snyk, and for configuration issues using Dockle.

### 1.1 Top 5 Critical/High Vulnerabilities

The following high-impact vulnerabilities were identified across both Snyk and Docker Scout scans, requiring immediate attention.

| CVE ID         | Severity | Affected Package | Summary & Impact                                                                                                                            |
| :------------- | :------- | :--------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| **CVE-2023-32314** | CRITICAL | `vm2`            | A sandbox escape vulnerability allows an attacker to bypass sandbox protections and gain Remote Code Execution (RCE) on the host machine.     |
| **CVE-2015-9235**  | HIGH     | `jsonwebtoken`   | The `none` algorithm is accepted for signature verification, allowing an attacker to forge tokens by removing the signature, bypassing authentication. |
| **CVE-2022-25887** | HIGH     | `sanitize-html`  | Insecure regular expression logic can lead to a Regular Expression Denial of Service (ReDoS) attack, causing the application to hang.       |
| **CVE-2024-21501** | HIGH     | `sanitize-html`  | A Cross-Site Scripting (XSS) vulnerability allows attackers to bypass sanitization and inject malicious scripts into rendered HTML.         |
| **CVE-2024-37890** | HIGH     | `express`        | A vulnerability in cookie parsing can lead to an authentication bypass by allowing an attacker to spoof a secure cookie with an insecure one. |

*Source: Analysis of `labs/lab7/scanning/scout-cves.txt` and `labs/lab7/scanning/snyk-results.txt`.*

### 1.2 Dockle Configuration Findings

The `dockle` scan identified several configuration issues that deviate from security best practices.

| Finding ID     | Severity | Finding & Security Impact                                                                                                                                                           |
| :------------- | :------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CIS-DI-0001**  | **FATAL**  | **Container runs as root user.** This is the most critical misconfiguration. If an attacker gains code execution inside the container, they have root privileges, which greatly increases the chances of a container breakout attack to compromise the host. |
| **DKL-DI-0006**  | **FATAL**  | **`USER` statement is not the last statement.** The Dockerfile contains a `USER` instruction, but it is followed by other commands. This can cause the user context to revert to `root`, nullifying the security benefit. |
| **CIS-DI-0008**  | **WARN**   | **Setuid/Setgid files are present.** Files with `setuid` or `setgid` bits are a privilege escalation risk. An attacker could potentially exploit them to gain the privileges of the file's owner (often `root`). |
| **CIS-DI-0006**  | **INFO**   | **`HEALTHCHECK` instruction is missing.** Without a health check, an orchestrator can only tell if the container process is running, not if the application is actually healthy. This can lead to routing traffic to a non-functional application. |

*Source: Analysis of `labs/lab7/scanning/dockle-results.txt`.*

### 1.3 Security Posture Assessment

**1. Does the image run as root?**  
Yes. The `dockle` scan confirms with a **FATAL** finding (CIS-DI-0001) that the container process runs as the `root` user. This is a major security risk.

**2. What security improvements would you recommend?**

1.  **Implement a Non-Root User:** The highest priority is to modify the Dockerfile to create a dedicated, non-privileged user and ensure the `USER` instruction is the last command before `CMD` or `ENTRYPOINT`.
    ```dockerfile
    # Create a non-root user and group
    RUN groupadd --gid 1001 node && useradd --uid 1001 --gid 1001 --shell /bin/bash --create-home node
    # ... copy application files and set permissions ...
    USER node
    CMD ["node", "app.js"]
    ```

2.  **Update Vulnerable Dependencies:** Address the `CRITICAL` and `HIGH` vulnerabilities by updating the affected packages (`vm2`, `jsonwebtoken`, etc.) to patched versions in `package.json` and rebuilding the image.

3.  **Add a `HEALTHCHECK` Instruction:** Add a `HEALTHCHECK` to the Dockerfile to allow the container engine to verify the application's health.
    ```dockerfile
    HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
      CMD curl -f http://localhost:3000 || exit 1
    ```

4.  **Remove `setuid`/`setgid` Permissions:** Add a build step to strip these permissions from files, reducing the attack surface for privilege escalation.
    ```dockerfile
    RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true
    ```

---

## Task 2: Docker Host Security Benchmarking

The Docker host environment was audited using the `docker/docker-bench-security` container, which checks the host configuration against the CIS Docker Benchmark.

### 2.1 CIS Benchmark Summary Statistics

The scan produced the following results, indicating several areas where the host configuration could be hardened.

| Result | Count |
| :----- | :---- |
| PASS   | 19    |
| **WARN**   | **13**    |
| INFO   | 39    |
| NOTE   | 5     |
| FAIL   | 0     |

*Source: Analysis of `labs/lab7/hardening/docker-bench-results.txt`.*

### 2.2 Analysis of Key `[WARN]` Findings

No `[FAIL]` findings were reported, but the 13 `[WARN]` findings highlight significant security gaps that should be addressed.

1.  **`[WARN] 2.1 - Ensure network traffic is restricted between containers on the default bridge`**
    - **Security Impact:** By default, all containers on the `bridge` network can communicate with each other without restriction. If one container is compromised, it can be used as a pivot point to attack other containers on the same host, facilitating lateral movement.
    - **Remediation:** For production environments, create custom bridge networks for different applications or tiers (`--icc=false`). This isolates containers and ensures that only explicitly linked containers can communicate.

2.  **`[WARN] 2.8 - Enable user namespace support`**
    - **Security Impact:** Without user namespaces, the `root` user inside a container maps to the `root` user on the host (UID 0). This is a major risk for container breakout attacks. User namespaces remap the container's root user to a non-privileged UID on the host, so even if an attacker breaks out, they will not have root privileges on the host machine.
    - **Remediation:** Configure the Docker daemon to use user namespaces. This involves editing the `daemon.json` file and setting up subordinate UID/GID ranges for the Docker user.
      ```json
      // In /etc/docker/daemon.json
      {
        "userns-remap": "default"
      }
      ```

3.  **`[WARN] 4.5 - Ensure Content trust for Docker is Enabled`**
    - **Security Impact:** Without content trust, there is no guarantee that the container image being pulled is the one published by the legitimate author. An attacker could perform a Man-in-the-Middle (MITM) attack or compromise a registry to replace a legitimate image with a malicious one.
    - **Remediation:** Enable Docker Content Trust by setting the environment variable `DOCKER_CONTENT_TRUST=1`. This will enforce signature verification on all `docker pull`, `run`, and `build` commands, preventing the use of unsigned or tampered images.
      ```powershell
      # In PowerShell
      $env:DOCKER_CONTENT_TRUST=1
      ```
4.  **`[WARN] 2.18 - Ensure containers are restricted from acquiring new privileges`**
    - **Security Impact:** If this is not set, a container can use `setuid` or `setgid` binaries to escalate privileges. This is a common privilege escalation vector.
    - **Remediation:** Run containers with the `no-new-privileges` security option. This prevents the container process from gaining any additional privileges.
      ```powershell
      docker run --rm --security-opt=no-new-privileges <image>
      ```

## Task 3: Deployment Security Configuration Analysis

This task compares three different security profiles for deploying the Juice Shop container to understand the trade-offs between security, functionality, and performance.

### 3.1 Configuration Comparison Table

The following table summarizes the key security configurations for each deployment profile, extracted from the `docker inspect` output.

| Configuration         | `juice-default` (Baseline) | `juice-hardened` (Hardened) | `juice-production` (Production) |
| :-------------------- | :------------------------- | :-------------------------- | :------------------------------ |
| **Capabilities Dropped**  | None                       | `ALL`                       | `ALL`                           |
| **Capabilities Added**    | None                       | None                        | `NET_BIND_SERVICE`              |
| **Security Options**      | None                       | `no-new-privileges`         | `no-new-privileges`, `seccomp=default` |
| **Memory Limit**          | 0 (Unlimited)              | 512MB                       | 512MB                           |
| **CPU Limit**             | 0 (Unlimited)              | 1.0 CPUs                    | 1.0 CPUs                        |
| **PID Limit**             | 0 (Unlimited)              | 0 (Unlimited)               | 100                             |
| **Restart Policy**        | `no`                       | `no`                        | `on-failure` (3 retries)        |

*Source: Analysis of `labs/lab7/analysis/deployment-comparison.txt`.*

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
- **What are Linux capabilities?** Capabilities are a way to grant a subset of root's powers to a process without giving it full root access. This follows the principle of least privilege.
- **What attack vector does dropping ALL capabilities prevent?** Dropping all capabilities drastically reduces the container's attack surface. It prevents a compromised process from performing privileged operations like loading kernel modules, administering the network, or overriding file permissions, which are common steps in container breakout attacks.
- **Why add back `NET_BIND_SERVICE`?** This capability is needed to allow a non-root process to bind to privileged ports (those below 1024). While Juice Shop runs on port 3000, this is a common requirement for web servers that need to bind to ports 80 or 443. It's added back to show how to grant *only* the necessary privilege.
- **What's the security trade-off?** The trade-off is between functionality and security. By dropping all capabilities, you maximize container isolation and reduce the attack surface, but you also remove abilities that some applications legitimately require. By selectively adding back only the necessary capabilities (like `NET_BIND_SERVICE`), you minimize risk while maintaining required functionality. However, **every capability you add back increases the potential attack surface**, so only capabilities that are explicitly needed should be granted.

#### b) `--security-opt=no-new-privileges`
- **What does this flag do?** It ensures that a process inside the container cannot gain additional privileges via `setuid` or `setgid` binaries. Once this flag is set, even if an attacker finds a `setuid` binary (like `sudo`), they cannot use it to escalate their privileges.
- **What type of attack does it prevent?** It directly prevents privilege escalation attacks within the container. This is a critical second layer of defense if an attacker achieves initial code execution.
- **Are there any downsides to enabling it?** For most use cases, there are **few downsides** to enabling `no-new-privileges`.
However, some applications or scripts that intentionally require privilege escalation (for example, tools that rely on setuid binaries to temporarily act as another user or root) **may not work as expected**. If you have legacy applications inside your container that depend on escalating privileges at runtime, they might fail under this restriction.

#### c) `--memory=512m` and `--cpus=1.0`
- **What happens if a container doesn't have resource limits?** An unlimited container can consume all available CPU and memory on the host. A bug or a malicious attack (e.g., denial of service) could cause it to starve other containers and even crash the host system.
- **What attack does memory limiting prevent?** It prevents memory-based Denial of Service (DoS) attacks, where an attacker forces the application to consume memory until the system becomes unstable. It also prevents costly resource over-consumption in a cloud environment.
- **What's the risk of setting limits too low?** If resource limits (memory or CPU) are set **too low**: The application inside the container may **fail to start** or operate unreliably. It may experience **out-of-memory (OOM) kills**, degraded performance, longer response times, or timeouts. Some workloads require more resources for peak loads or initial startup; tight limits could lead to instability or incomplete processing.

#### d) `--pids-limit=100`
- **What is a fork bomb?** A fork bomb is a DoS attack where a process rapidly replicates itself, creating a massive number of new processes. This quickly exhausts the host's process ID table and CPU resources, leading to a system crash.
- **How does PID limiting help?** It sets a hard cap on the number of processes that can be created within the container. The `production` profile's limit of 100 prevents a fork bomb from ever consuming enough PIDs to impact the host.
- **How to determine the right limit?** To determine the appropriate PID limit for your container:
    1. **Analyze your application's normal behavior:**  
        - Monitor how many processes/threads your application starts under normal and peak usage.
    2. **Add a safety buffer:**  
        - Set the limit a bit higher than the observed maximum to accommodate occasional spikes.
    3. **Test under load:**  
        - Stress-test your application to ensure it functions correctly within your chosen limit.
    4. **Review and adjust as needed:**  
        - Fine-tune the value as requirements change over time.
#### e) `--restart=on-failure:3`
- **What does this policy do?** It instructs Docker to automatically restart the container if it exits with a non-zero (error) status code. It will attempt to restart up to 3 times.
- **When is auto-restart beneficial vs. risky?** It's beneficial for resilience, automatically recovering the application from transient errors. However, it can be risky if the container is crashing due to a security issue or a persistent misconfiguration, as it could enter a crash-loop that hides the root cause or is exploited by an attacker.
- **Compare `on-failure` vs `always`**
    - **on-failure**
        - Restarts the container **only if the exit code is non-zero** (i.e., failure).
        - Can specify a limit for the number of retries (`on-failure:3`).
        - Useful for processes that should not be running after clean/explained shutdowns.

    - **always**
        - Restarts the container **regardless of the exit code** (even if it exited cleanly).
        - No retry limit; container restarts endlessly until explicitly stopped.
        - Useful for critical background services, daemons, or infrastructure components that should essentially always be running.
### 3.3 Critical Thinking Questions

1.  **Which profile for DEVELOPMENT? Why?**  
    The **`Default`** profile is most suitable for development. It offers maximum flexibility for debugging and introspection without security features getting in the way. The lack of resource limits also prevents the container from being killed during resource-intensive tasks like initial dependency installation.

2.  **Which profile for PRODUCTION? Why?**  
    The **`Production`** profile is the only acceptable choice for production. It implements a defense-in-depth strategy by dropping all capabilities, preventing privilege escalation, and setting strict resource limits (memory, CPU, PIDs). The restart policy also provides necessary resilience for a production service.

3.  **What real-world problem do resource limits solve?**  
    Resource limits solve two main problems: **stability** and **cost**. They prevent a single faulty or compromised container from causing a Denial of Service that takes down other applications on the same host. In cloud environments, they prevent a single container from auto-scaling or consuming expensive resources, thus controlling operational costs.

4.  **If an attacker exploits Default vs Production, what actions are blocked in Production?**  
    If an attacker gains code execution:
    - In `Default`, they have full root capabilities and can attempt to install network sniffers, load kernel modules, or write to protected areas of the filesystem.
    - In `Production`, these actions are blocked. They **cannot** escalate privileges with `setuid` binaries, **cannot** perform most privileged system operations, and **cannot** launch a fork bomb to crash the host. Their "blast radius" is tightly confined.

5.  **What additional hardening would you add?**  
    Based on the findings from Task 1 and 2, I would add:
    - **Run as a non-root user:** This is the most critical hardening step missing from the `docker run` commands. The image itself must be rebuilt with a `USER` instruction.
    - **Read-only root filesystem:** Run the container with `--read-only`, which prevents an attacker from modifying application files or writing malicious binaries to disk. Writable paths can be added back as needed with `--tmpfs`.
    - **Network Policies:** Deploy the container on a custom Docker network with strict ingress/egress rules to isolate it from other services on the host.