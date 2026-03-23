# Lab 7 — Container Security: Image Scanning & Deployment Hardening

![difficulty](https://img.shields.io/badge/difficulty-intermediate-orange)
![topic](https://img.shields.io/badge/topic-Container%20Security-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Analyze container images for vulnerabilities, audit Docker host security, and compare secure deployment configurations.  
> **Deliverable:** A PR from `feature/lab7` to the course repo with `labs/submission7.md` containing vulnerability analysis, CIS benchmark results, and deployment security comparison. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- **Container image vulnerability scanning** using next-generation tools (Docker Scout, Snyk)
- **Docker security benchmarking** with CIS Docker Benchmark compliance assessment
- **Secure container deployment** analysis and configuration comparison
- **Container security assessment** using modern scanning and analysis tools
- **Security configuration impact** analysis for production deployments

These skills are essential for implementing container security in DevSecOps pipelines and production environments.

> Target application: OWASP Juice Shop (`bkimminich/juice-shop:v19.0.0`)

---

## Prerequisites

### Docker Scout CLI Setup

Docker Scout requires authentication and a CLI plugin installation.

#### Step 1: Install Docker Scout CLI Plugin

**For Linux/macOS:**
```bash
curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
```

**Verify installation:**
```bash
docker scout version
```

You should see output like: `version: v1.x.x`

#### Step 2: Docker Hub Authentication

Docker Scout requires a Docker Hub account and Personal Access Token (PAT).

**Create account and generate PAT:**

1. **Create Docker Hub account** (if needed): Visit https://hub.docker.com

2. **Generate PAT:**

   - Log in → Account Settings → Security → Personal Access Tokens
   - Click **New Access Token**
   - Description: `Lab7 Docker Scout Access`
   - Permissions: Select **Read, Write, Delete**
   - Click **Generate** and copy the token immediately

3. **Authenticate:**

   ```bash
   docker login
   # Username: your-docker-hub-username
   # Password: paste-your-PAT (not your password!)
   ```

4. **Verify access:**

   ```bash
   docker scout quickview busybox:latest
   # Should display vulnerability scan results
   ```

**Why PAT over password?**
- Limited scope permissions for least privilege
- Easy to revoke without changing account password
- Required for SSO-enabled organizations
- Better audit trail

Learn more: https://docs.docker.com/go/access-tokens/

---

## Tasks

### Task 1 — Image Vulnerability & Configuration Analysis (3 pts)

**Objective:** Scan container images for vulnerabilities and configuration issues.

#### 1.1: Setup Working Directory

```bash
mkdir -p labs/lab7/{scanning,hardening,analysis}
cd labs/lab7
```

#### 1.2: Vulnerability Scanning

```bash
# Pull the image to scan locally
docker pull bkimminich/juice-shop:v19.0.0

# Detailed CVE analysis
docker scout cves bkimminich/juice-shop:v19.0.0 | tee scanning/scout-cves.txt
```

**Understanding the output:**
- **C/H/M/L** = Critical/High/Medium/Low severity counts
- Look for CVE IDs, affected packages, and potential impact

#### 1.3: Snyk comparison

```bash
# Requires Snyk account: https://snyk.io
# Set token: export SNYK_TOKEN=your-token
docker run --rm \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 --severity-threshold=high \
  | tee scanning/snyk-results.txt
```

#### 1.4: Configuration Assessment

```bash
# Scan for security and best practice issues
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  bkimminich/juice-shop:v19.0.0 | tee scanning/dockle-results.txt
```

**Look for:**
- **FATAL/WARN** issues about running as root
- Exposed secrets in environment variables
- Missing security configurations
- File permission issues

**📊 Document in `labs/submission7.md`:**

1. **Top 5 Critical/High Vulnerabilities**
   - CVE ID, affected package, severity, and impact

2. **Dockle Configuration Findings**
   - List FATAL and WARN issues
   - Explain why each is a security concern

3. **Security Posture Assessment**
   - Does the image run as root?
   - What security improvements would you recommend?

---

### Task 2 — Docker Host Security Benchmarking (3 pts)

**Objective:** Audit Docker host configuration against CIS Docker Benchmark.

#### 2.1: Run CIS Docker Benchmark

```bash
# Run CIS Docker Benchmark security audit
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro --label docker_bench_security \
  docker/docker-bench-security | tee hardening/docker-bench-results.txt
```

**Understanding the output:**
- **[PASS]** - Security control properly configured
- **[WARN]** - Potential issue requiring review
- **[FAIL]** - Security control not properly configured
- **[INFO]** - Informational (no action needed)

**Key sections:**
1. Host Configuration
2. Docker daemon configuration  
3. Docker daemon configuration files
4. Container Images and Build Files
5. Container Runtime

**📊 Document in `labs/submission7.md`:**

1. **Summary Statistics**
   - Total PASS/WARN/FAIL/INFO counts

2. **Analysis of Failures** (if any)
   - List failures and explain security impact
   - Propose specific remediation steps

---

### Task 3 — Deployment Security Configuration Analysis (4 pts)

**Objective:** Compare deployment configurations to understand security hardening trade-offs.

#### 3.1: Deploy Three Security Profiles

```bash
# Profile 1: Default (baseline)
docker run -d --name juice-default -p 3001:3000 \
  bkimminich/juice-shop:v19.0.0

# Profile 2: Hardened (security restrictions)
docker run -d --name juice-hardened -p 3002:3000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m \
  --cpus=1.0 \
  bkimminich/juice-shop:v19.0.0

# Profile 3: Production (maximum hardening)
docker run -d --name juice-production -p 3003:3000 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt=seccomp=default \
  --memory=512m \
  --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  --restart=on-failure:3 \
  bkimminich/juice-shop:v19.0.0

# Wait for startup
sleep 15

# Verify all containers are running
docker ps -a --filter name=juice-
```

#### 3.2: Compare Configurations

```bash
# Test functionality
echo "=== Functionality Test ===" | tee analysis/deployment-comparison.txt
curl -s -o /dev/null -w "Default: HTTP %{http_code}\n" http://localhost:3001 | tee -a analysis/deployment-comparison.txt
curl -s -o /dev/null -w "Hardened: HTTP %{http_code}\n" http://localhost:3002 | tee -a analysis/deployment-comparison.txt
curl -s -o /dev/null -w "Production: HTTP %{http_code}\n" http://localhost:3003 | tee -a analysis/deployment-comparison.txt

# Check resource usage
echo "" | tee -a analysis/deployment-comparison.txt
echo "=== Resource Usage ===" | tee -a analysis/deployment-comparison.txt
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" \
  juice-default juice-hardened juice-production | tee -a analysis/deployment-comparison.txt

# Inspect security settings
echo "" | tee -a analysis/deployment-comparison.txt
echo "=== Security Configurations ===" | tee -a analysis/deployment-comparison.txt
for container in juice-default juice-hardened juice-production; do
  echo "" | tee -a analysis/deployment-comparison.txt
  echo "Container: $container" | tee -a analysis/deployment-comparison.txt
  docker inspect $container --format 'CapDrop: {{.HostConfig.CapDrop}}
SecurityOpt: {{.HostConfig.SecurityOpt}}
Memory: {{.HostConfig.Memory}}
CPU: {{.HostConfig.CpuQuota}}
PIDs: {{.HostConfig.PidsLimit}}
Restart: {{.HostConfig.RestartPolicy.Name}}' | tee -a analysis/deployment-comparison.txt
done
```

#### 3.3: Cleanup

```bash
docker stop juice-default juice-hardened juice-production
docker rm juice-default juice-hardened juice-production
```

**📊 Document in `labs/submission7.md`:**

#### 1. Configuration Comparison Table

Create a table from `docker inspect` output comparing all three profiles:
- Capabilities (dropped/added)
- Security options
- Resource limits (memory, CPU, PIDs)
- Restart policy

#### 2. Security Measure Analysis

Research and explain EACH security flag:

**a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`**
- What are Linux capabilities? (Research this!)
- What attack vector does dropping ALL capabilities prevent?
- Why do we need to add back NET_BIND_SERVICE?
- What's the security trade-off?

**b) `--security-opt=no-new-privileges`**
- What does this flag do? (Look it up!)
- What type of attack does it prevent?
- Are there any downsides to enabling it?

**c) `--memory=512m` and `--cpus=1.0`**
- What happens if a container doesn't have resource limits?
- What attack does memory limiting prevent?
- What's the risk of setting limits too low?

**d) `--pids-limit=100`**
- What is a fork bomb?
- How does PID limiting help?
- How to determine the right limit?

**e) `--restart=on-failure:3`**
- What does this policy do?
- When is auto-restart beneficial? When is it risky?
- Compare `on-failure` vs `always`

#### 3. Critical Thinking Questions

1. **Which profile for DEVELOPMENT? Why?**

2. **Which profile for PRODUCTION? Why?**

3. **What real-world problem do resource limits solve?**

4. **If an attacker exploits Default vs Production, what actions are blocked in Production?**

5. **What additional hardening would you add?**


---

## Acceptance Criteria

- ✅ Branch `feature/lab7` exists with commits for each task
- ✅ File `labs/submission7.md` contains required analysis for Tasks 1-3
- ✅ Vulnerability scanning completed with Docker Scout
- ✅ CIS Docker Benchmark audit completed
- ✅ Deployment security comparison completed
- ✅ All scan outputs committed to `labs/lab7/`
- ✅ PR from `feature/lab7` → **course repo main branch** is open
- ✅ PR link submitted via Moodle before the deadline

---

## How to Submit

1. Create a branch for this lab and push it to your fork:

   ```bash
   git switch -c feature/lab7
   # create labs/submission7.md with your findings
   git add labs/submission7.md labs/lab7/
   git commit -m "docs: add lab7 submission - container security analysis"
   git push -u origin feature/lab7
   ```

2. Open a PR from your fork's `feature/lab7` branch → **course repository's main branch**.

3. In the PR description, include:

   ```text
   - [x] Task 1 done — Advanced Image Security & Configuration Analysis
   - [x] Task 2 done — Docker Security Benchmarking & Assessment
   - [x] Task 3 done — Secure Container Deployment Analysis
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Rubric (10 pts)

| Criterion                                                        | Points |
| ---------------------------------------------------------------- | -----: |
| Task 1 — Image vulnerability & configuration analysis           |  **3** |
| Task 2 — Docker host security benchmarking                      |  **3** |
| Task 3 — Deployment security configuration analysis             |  **4** |
| **Total**                                                        | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission7.md`
- Include evidence from tool outputs to support your analysis
- Research security concepts thoroughly—don't copy-paste
- Focus on understanding trade-offs between security and usability

<details>
<summary>Container Security Resources</summary>

**Documentation:**
- [Docker Security](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

</details>

<details>
<summary>Expected Security Findings</summary>

**Image Vulnerabilities:**
- Outdated base packages with CVEs
- Vulnerable dependencies
- Missing security patches

**CIS Benchmark:**
- Insecure daemon configuration
- Missing resource limits
- Excessive privileges

**Deployment Gaps:**
- Running as root
- Unnecessary capabilities
- No resource limits

</details>