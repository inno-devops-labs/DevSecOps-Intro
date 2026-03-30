# Lab 7 – Container Security Scanning and Hardening

## Task 1: Vulnerability Scanning

### Tools Used
- Docker Scout
- Dockle

### Summary of Findings (Docker Scout)
- Total vulnerabilities: 139
- Critical: 12
- High: 72
- Medium: 36
- Low: 6
- Unspecified: 13

### Notable Vulnerabilities
- CVE-2026-22709 (vm2) – Critical – Protection Mechanism Failure
- CVE-2023-37903 (vm2) – Critical – OS Command Injection
- CVE-2025-55130 (Node.js) – Critical
- CVE-2019-10744 (lodash) – Critical – Prototype Pollution
- CVE-2015-9235 (jsonwebtoken) – Critical – Improper Input Validation

### Dockle Findings
- No FATAL or WARN issues detected
- INFO findings:
  - Content Trust is not enabled (CIS-DI-0005)
  - No HEALTHCHECK instruction in image (CIS-DI-0006)
  - Presence of unnecessary files (.DS_Store)

### Security Implications
The image contains multiple critical vulnerabilities, especially in JavaScript dependencies.  
While Dockle did not report critical misconfigurations, the absence of content trust and health checks indicates weak supply-chain and operational security practices.

## Task 2: Docker Bench Security

### Summary Statistics
- PASS: 40
- WARN: 64
- FAIL: 0
- INFO: 91

### Key Issues Identified
- No separate partition for containers (1.1)
- Auditing not configured for Docker daemon and files (1.5–1.9)
- User namespace support not enabled (2.8)
- Containers can acquire new privileges (2.18, 5.25)
- Containers running as root (minikube) (4.1)
- No HEALTHCHECK configured for many images (4.6, 5.26)
- Privileged container detected (minikube) (5.4)
- No PIDs limit set (5.28)
- Default seccomp profile disabled (5.21)

### Analysis
Many warnings are related to the Docker host configuration and the `minikube` container rather than the Juice Shop container itself.  
This indicates that the environment lacks proper hardening and secure defaults.

### Recommendations
- Enable user namespaces
- Enforce `no-new-privileges`
- Add HEALTHCHECK to images
- Configure auditing and logging
- Limit container resources (CPU, memory, PIDs)
- Avoid privileged containers

## Task 3: Runtime Security Hardening

### Deployment Profiles

#### Default Configuration
- No security restrictions
- No resource limits

#### Hardened Configuration
- Dropped all capabilities
- Enabled `no-new-privileges`
- Limited memory and CPU

#### Production Configuration
- Dropped all capabilities except `NET_BIND_SERVICE`
- Enabled `no-new-privileges`
- Set memory, CPU, and PID limits
- Configured restart policy

### Functionality Test
All configurations returned HTTP 200:
- Default: 200
- Hardened: 200
- Production: 200

This shows that security hardening did not break application functionality.

### Resource Usage Comparison
- Default: No limits, low memory usage (~99 MB)
- Hardened: Memory limited to 512 MB (~93 MB used)
- Production: Similar usage (~91 MB), with stricter controls

### Security Configuration Comparison

| Feature        | Default | Hardened | Production |
|----------------|--------|----------|------------|
| CapDrop        | None   | ALL      | ALL        |
| no-new-privs   | No     | Yes      | Yes        |
| Memory limit   | No     | Yes      | Yes        |
| CPU limit      | No     | Yes      | Yes        |
| PIDs limit     | No     | No       | Yes        |
| Restart policy | No     | No       | Yes        |

### Analysis
- Default configuration is insecure and lacks isolation
- Hardened configuration significantly improves security with minimal impact
- Production configuration provides the best balance of security and reliability

## Conclusion

The Juice Shop container contains numerous critical vulnerabilities and lacks proper runtime hardening by default.  
Applying container security best practices such as dropping capabilities, enforcing resource limits, and restricting privileges significantly improves security posture without affecting functionality.

Docker Bench results highlight that host-level configuration is equally important and must be secured alongside containers.