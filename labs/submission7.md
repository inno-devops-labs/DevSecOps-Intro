# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### Top 5 Critical/High Vulnerabilities

Based on the scans from Docker Scout and Snyk, the following are the most significant vulnerabilities identified in the `bkimminich/juice-shop:v19.0.0` image:

| CVE ID | Affected Package | Severity | Impact |
| :--- | :--- | :--- | :--- |
| **CVE-2026-22709** | `vm2` (3.9.17) | CRITICAL | **Protection Mechanism Failure:** Allows attackers to bypass the sandbox and execute arbitrary code on the host. |
| **CVE-2023-37903** | `vm2` (3.9.17) | CRITICAL | **OS Command Injection:** Improper neutralization allows for execution of unauthorized system commands. |
| **CVE-2025-55130** | `node` (22.18.0) | CRITICAL | **Race Condition:** Found in the Node.js runtime, potentially leading to memory corruption or privilege escalation. |
| **CVE-2025-69421** | `openssl/libssl3` | HIGH | **Information Leak:** Vulnerability in the SSL/TLS library that could compromise encrypted communication. |
| **CVE-2025-6838727** | `braces` (2.3.2) | HIGH | **Resource Consumption:** Prototype pollution and ReDoS risks within deeply nested dependency trees. |

### Dockle Configuration Findings

The `dockle` assessment identified several best-practice and configuration issues:

*   **CIS-DI-0005 (Enable Content Trust):**
    *   **Concern:** The image was pulled without digital signature verification. This opens the risk of using a tampered or malicious image that has been "poisoned" in a registry.
*   **CIS-DI-0006 (Missing HEALTHCHECK):**
    *   **Concern:** Without a `HEALTHCHECK` instruction, the Docker engine cannot determine if the application inside is actually functional, only if the process is running. This can lead to traffic being routed to "zombie" containers.
*   **DKL-LI-0003 (Unnecessary Files):**
    *   **Concern:** The presence of `.DS_Store` files in `node_modules`. These files increase the attack surface and can potentially leak metadata about the development environment.

### Security Posture Assessment

*   **Does the image run as root?**
    Based on the Snyk output the container is "distroless" (no shell available). It runs from generic distroless nonroot user (UID 65532) - verified with `docker inspect juice-shop | grep -i user`
*   **Security Improvements Recommended:**
    1.  **Update Node.js Base Image:** Move from `node:22.18.0` to `22.22.0` or later to patch the CRITICAL race condition and high-severity symlink vulnerabilities.
    2.  **Replace `vm2`:** The `vm2` library is heavily compromised with multiple CRITICAL vulnerabilities and is no longer actively maintained. It should be replaced with a more secure sandboxing alternative.
    3.  **Implement `USER` Instruction:** Explicitly create a non-privileged user (e.g., `appuser`) in the Dockerfile to adhere to the principle of least privilege.
    4.  **Add `HEALTHCHECK`:** Implement a health check command (e.g., calling the `/health` endpoint) to improve orchestration and availability.
    5.  **Clean Dependencies:** Use `.dockerignore` to prevent development artifacts like `.DS_Store` or local `node_modules` from being copied into the production image.

## Task 2 — Docker Host Security Benchmarking

### Summary Statistics
The CIS Docker Benchmark was performed using `docker-bench-security` to assess the host and daemon configuration.

*   **Total Pass:** 45
*   **Total Warn:** 35
*   **Total Info/Note:** 37
*   **Final Score:** 12

### Analysis of Failures & Warnings

The audit revealed several high-impact security gaps in the host and container runtime configuration:

| Check ID | Finding | Security Impact | Remediation Step |
| :--- | :--- | :--- | :--- |
| **1.1.3 - 1.1.18** | Missing Docker Auditing | Changes to Docker binaries, sockets, or configurations are not logged by the OS. This prevents forensic analysis after a compromise. | Configure `auditd` rules for `/usr/bin/docker`, `/etc/docker`, and `/var/lib/docker`. |
| **2.2** | Default Bridge Traffic | Containers on the default bridge can communicate with each other unrestricted, allowing lateral movement. | Set `"icc": false` in `daemon.json` or use custom user-defined bridge networks. |
| **2.14 / 5.26** | Privilege Escalation | Containers are not restricted from acquiring new privileges via `setuid` or `setgid` binaries. | Start containers with the `--security-opt=no-new-privileges` flag. |
| **5.11 / 5.12** | Missing Resource Limits | The `juice-shop` container has no memory or CPU limits, making the host vulnerable to Denial of Service (DoS). | Apply resource constraints using `--memory="512m"` and `--cpus="0.5"`. |
| **5.13** | Root FS is Read-Write | The container's root filesystem is mutable, allowing attackers to download and execute malicious tools if they gain shell access. | Run the container with the `--read-only` flag. |
| **2.13** | No Centralized Logging | Logs are only stored locally on the host, making them susceptible to tampering by an attacker. | Configure a logging driver (e.g., `syslog`, `gelf`, or `fluentd`) in the Docker daemon settings. |

### Propose Specific Remediation Steps
To improve the security score from 12 to a hardened state, the following actions are recommended:

1.  **Host Hardening:** Install `auditd` and add rules to monitor all Docker-related files and the `/usr/bin/runc` binary.
2.  **Daemon Configuration:** Update `/etc/docker/daemon.json` to include:
    ```json
    {
      "icc": false,
      "userns-remap": "default",
      "live-restore": true,
      "userland-proxy": false,
      "no-new-privileges": true
    }
    ```
3.  **Runtime Hardening:** When deploying the Juice Shop container, use a hardened execution command:
    ```bash
    docker run -d --name juice-shop \
      --read-only \
      --memory="512m" \
      --security-opt=no-new-privileges \
      -p 127.0.0.1:3000:3000 \
      bkimminich/juice-shop:v19.0.0
    ```

## Task 3 — Deployment Security Configuration Analysis

### 1. Configuration Comparison Table

The following data was extracted via `docker inspect` for the three deployment profiles:

| Feature | juice-default | juice-hardened | juice-production |
| :--- | :--- | :--- | :--- |
| **Capabilities (Dropped)** | None | `[ALL]` | `[ALL]` |
| **Capabilities (Added)** | None | None | `[NET_BIND_SERVICE]` |
| **Security Options** | `<no value>` | `[no-new-privileges]` | `[no-new-privileges]` |
| **Memory Limit** | Unlimited (`0`) | `512MiB` | `512MiB` |
| **CPU Limit (Quota)** | Unlimited (`0`) | `1.0` | `1.0` |
| **PIDs Limit** | Unlimited (`0`) | `<no value>` | `100` |
| **Restart Policy** | `no` | `no` | `on-failure (max 3)` |

### 2. Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`
*   **Linux Capabilities:** These break down the all-powerful `root` privileges into smaller, distinct units (e.g., `CAP_CHOWN`, `CAP_SYS_ADMIN`). Instead of giving a process full root power, you give it only what it needs.
*   **Attack Vector Prevented:** Dropping `ALL` prevents **Container Escape** and **Kernel Exploitation**. An attacker who gains root inside the container cannot mount filesystems, load kernel modules, or change network interfaces.
*   **Why add `NET_BIND_SERVICE`?** This allows a process to bind to privileged ports (those below 1024, like 80 or 443). Without it, if the app must listen on port 80, it will fail to start after dropping all caps.
*   **Security Trade-off:** Adding it back grants a small amount of network power, but it is vastly safer than leaving all 30+ default capabilities active.

#### b) `--security-opt=no-new-privileges`
*   **Function:** It prevents a process from gaining any more privileges than its parent had. Specifically, it disables the effects of `setuid` and `setgid` bits on executables.
*   **Attack Prevented:** It prevents **Local Privilege Escalation**. If an attacker finds a vulnerability in a tool like `sudo` or `ping` (which are setuid), they cannot use them to become a "true" root.
*   **Downsides:** It can break legacy applications or management tools that legitimately need to elevate privileges (e.g., some database installation scripts).

#### c) `--memory=512m` and `--cpus=1.0`
*   **No Resource Limits:** A single container can consume all host RAM and CPU, causing the host to crash or reboot (Resource Exhaustion).
*   **Attack Prevented:** **Denial of Service (DoS)**. It ensures one compromised or buggy container cannot "starve" the rest of the infrastructure.
*   **Risk of Low Limits:** If set too low, the application may suffer from **OOM (Out of Memory) Kills** or heavy CPU throttling, leading to service instability and high latency.

#### d) `--pids-limit=100`
*   **Fork Bomb:** A type of DoS attack where a process continually replicates itself to exhaust the process table, freezing the OS.
*   **PID Limiting:** It places a hard ceiling on the number of processes a container can spawn. If a fork bomb starts, it hits the limit of 100 and stops, saving the host.
*   **Determining the Limit:** Monitor the application under load using `docker stats`. If it normally uses 20 threads, a limit of 50 or 100 provides a safe buffer.

#### e) `--restart=on-failure:3`
*   **Policy Function:** Automatically restarts the container only if it exits with a non-zero error code, up to 3 times.
*   **Beneficial vs. Risky:** It is beneficial for handling transient errors (e.g., DB temporarily unavailable). It is risky if the app is crashing due to a security exploit that retriggers every time the process starts.
*   **on-failure vs. always:** `always` will restart even if you manually stop the container; `on-failure` is smarter as it assumes if the app exited cleanly (0), it was intentional.

### 3. Critical Thinking Questions

1.  **Which profile for DEVELOPMENT? Why?**
    **Default**. Developers need speed and flexibility. Hardened profiles can block debugging tools, profilers, and local logging, making it difficult to troubleshoot code during the build phase.

2.  **Which profile for PRODUCTION? Why?**
    **Production**. It implements the **Principle of Least Privilege**. It limits the "blast radius" of a compromise by restricting kernel access, preventing privilege escalation, and protecting host resources via PIDs and memory limits.

3.  **What real-world problem do resource limits solve?**
    They solve **"Noisy Neighbor"** issues. In a cloud environment, they prevent one poorly written app (or one under attack) from crashing 50 other applications sharing the same host hardware.

4.  **If an attacker exploits Default vs Production, what actions are blocked in Production?**
    In **Default**, an attacker could run a fork-bomb to kill the host, use `setuid` binaries to escalate privileges, or try to mount the host `/etc` to steal passwords. In **Production**, all these are blocked by PID limits, `no-new-privileges`, and `cap-drop=ALL`.

5.  **What additional hardening would you add?**
    I would add `--read-only` to make the root filesystem immutable and `--user 1000:1000` to ensure the application never starts as the root user ID in the first place, even before capabilities are dropped.
