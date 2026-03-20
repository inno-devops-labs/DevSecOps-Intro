# Lab 7 — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1. Vulnerability scanning summary

Docker Scout could not be fully used because the CLI required Docker authentication in the current environment.

Snyk scanning could not be completed due to missing or invalid authentication credentials, resulting in a `401 Unauthorized` error.

An additional attempt to authenticate using `snyk auth` inside a container failed with an OAuth timeout, likely due to limitations of browser-based authentication flow in a containerized environment.

Therefore, vulnerability analysis was performed using Dockle.

---

### 2. Dockle Configuration Findings

**Observed findings:**

- `CIS-DI-0005`: Content trust for Docker is not enabled  
- `CIS-DI-0006`: No `HEALTHCHECK` instruction found in the image  
- `DKL-LI-0003`: Unnecessary files are present in the image:
  - `juice-shop/node_modules/extglob/lib/.DS_Store`
  - `juice-shop/node_modules/micromatch/lib/.DS_Store`

**Why these are security concerns:**

- Content trust being disabled reduces assurance that pulled images are authentic and not tampered with.
- Missing `HEALTHCHECK` makes it harder to detect failing or unhealthy containers automatically.
- Unnecessary files increase image size and may expose internal development artifacts.

---

### 3. Security Posture Assessment

**Does the image run as root?**  
No. The container runs with user ID `65532`, which indicates a non-root user.

**Assessment:**  
The image has a partially secure configuration. Running as a non-root user is a strong security practice. However, the lack of content trust, missing health checks, and inclusion of unnecessary files weaken the overall security posture.

**Recommended improvements:**

1. Enable Docker Content Trust.
2. Add a `HEALTHCHECK` instruction.
3. Remove unnecessary files from the image.
4. Perform regular vulnerability scans.
5. Keep dependencies updated.

---

## Task 2 — Docker Host Security Benchmarking

### 1. Summary Statistics

- Checks performed: 74  
- Final score: 4  

Multiple warnings were identified during the Docker Bench Security scan.

---

### 2. Analysis of Failures

| Check | Result | Security Impact | Remediation |
|------|--------|---------------|------------|
| Separate partition for containers | WARN | Weak isolation of Docker storage | Use dedicated partition |
| Auditing for Docker daemon | WARN | Reduced visibility | Enable audit logging |
| Auditing for `/var/lib/docker` | WARN | Weak forensic capabilities | Add audit rules |
| Default bridge networking | WARN | Containers communicate freely | Restrict network traffic |
| TLS for Docker daemon | WARN | Potential exposure | Enable TLS |
| User namespaces | WARN | Weaker isolation | Enable user namespaces |
| Authorization plugin | WARN | Weak access control | Add authorization plugin |
| Remote logging | WARN | Logs not centralized | Configure remote logging |
| Live restore | WARN | Containers affected by daemon restart | Enable live restore |
| New privileges restriction | WARN | Possible privilege escalation | Enforce `no-new-privileges` |
| Docker socket ownership | WARN | Risk of daemon control | Fix permissions |
| Content trust | WARN | Weak image integrity | Enable content trust |
| Missing HEALTHCHECK | WARN | Harder to detect failures | Add HEALTHCHECK |

**Overall assessment:**  
The Docker host is functional but not fully hardened. Several security controls are missing, especially around auditing, daemon configuration, and runtime isolation.

---

## Task 3 — Deployment Security Configuration Analysis

### 1. Configuration Comparison Table

| Profile | CapDrop | CapAdd | SecurityOpt | Memory | CPU | PIDs | Restart |
|--------|--------|--------|------------|--------|-----|------|--------|
| Default | none | none | default | none | none | none | no |
| Hardened | ALL | none | no-new-privileges | 512m | 1.0 | none | no |
| Production | ALL | NET_BIND_SERVICE | no-new-privileges | 512m | 1.0 | 100 | on-failure |

---

### 2. Practical observations

- The **default** and **hardened** containers initially ran successfully.
- The **production** container required removing the `seccomp=default` flag due to Docker Desktop limitations on Windows.
- The production container successfully returned HTTP `200`, confirming correct functionality.

---

### 3. Security Measure Analysis

#### `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

Dropping all capabilities reduces attack surface. Adding only required capabilities follows the principle of least privilege.

---

#### `--security-opt=no-new-privileges`

Prevents processes from gaining additional privileges, reducing risk of privilege escalation.

---

#### Resource limits (`--memory`, `--cpus`)

Protect the host from resource exhaustion and denial-of-service scenarios.

---

#### `--pids-limit`

Limits number of processes and protects against fork bombs.

---

#### `--restart=on-failure`

Improves availability while avoiding infinite restart loops.

---

### 4. Critical Thinking Questions

**1. Best profile for development?**  
Default, because it is less restrictive and easier for debugging.

**2. Best profile for production?**  
Production profile, because it applies least privilege, limits resources, and improves stability.

**3. What problem do resource limits solve?**  
They prevent a single container from consuming all system resources.

**4. What is blocked in production vs default?**  
Privilege escalation, excessive resource usage, and unrestricted capabilities.

**5. Additional hardening:**

- Use read-only filesystem  
- Enable AppArmor/SELinux  
- Use minimal base images  
- Implement continuous scanning  
- Use signed images  