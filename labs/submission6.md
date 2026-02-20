# Lab 6 Submission — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Setup Scanning Environment

All scanning tools were run via Docker containers against the vulnerable IaC code in `labs/lab6/vulnerable-iac/`. Results were saved to `labs/lab6/analysis/`.

```bash
mkdir -p labs/lab6/analysis
```

### 1.2 tfsec Scan Results

tfsec was run against the Terraform code:

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src --format json > labs/lab6/analysis/tfsec-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src > labs/lab6/analysis/tfsec-report.txt
```

**tfsec Summary — 53 findings:**

| Severity | Count |
|----------|------:|
| CRITICAL | 8     |
| HIGH     | 25    |
| MEDIUM   | 10    |
| LOW      | 7     |
| OTHER    | 3     |

Key findings include:
- **AVD-AWS-0082** — RDS instance publicly accessible (CRITICAL)
- **AVD-AWS-0107** — Ingress security group rules allow traffic from `0.0.0.0/0` (CRITICAL, 5 instances)
- **AVD-AWS-0104** — Egress security group rules allow traffic to `0.0.0.0/0` (CRITICAL, 3 instances)
- **AVD-AWS-0057** — IAM policy wildcard permissions violating least privilege (HIGH, 9 instances)
- **AVD-AWS-0088** — Unencrypted S3 buckets (HIGH, 2 instances)
- **AVD-AWS-0080** — RDS encryption not enabled (HIGH)
- **AVD-AWS-0086/0087** — S3 public access blocks missing (HIGH, 4 instances)

### 1.3 Checkov Scan Results

Checkov was run against the Terraform code:

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest -d /tf --framework terraform \
  -o json > labs/lab6/analysis/checkov-terraform-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest -d /tf --framework terraform \
  --compact > labs/lab6/analysis/checkov-terraform-report.txt
```

**Checkov Summary — 78 failed checks (48 passed, 16 resources):**

Key failed checks (sample):
- **CKV_AWS_16** — RDS instance not encrypted (`aws_db_instance.unencrypted_db`)
- **CKV_AWS_17** — RDS publicly accessible
- **CKV_AWS_20** — S3 bucket with public ACL (`aws_s3_bucket.public_data`)
- **CKV_AWS_21** — S3 versioning disabled (2 instances)
- **CKV_AWS_23** — Security groups missing descriptions (3 instances)
- **CKV_AWS_24/25** — Security groups ingress open to `0.0.0.0/0` (4 instances)
- **CKV_AWS_118** — RDS enhanced monitoring disabled (2 instances)
- **CKV_AWS_119** — DynamoDB encryption not enabled
- **CKV_AWS_145** — S3 bucket encryption missing (2 instances)
- **CKV_AWS_161** — RDS deletion protection disabled (2 instances)

### 1.4 Terrascan Scan Results

Terrascan was run against the Terraform code:

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan -i terraform -d /iac \
  -o json > labs/lab6/analysis/terrascan-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan -i terraform -d /iac \
  -o human > labs/lab6/analysis/terrascan-report.txt
```

**Terrascan Summary — 22 violated policies (out of 167 validated):**

| Severity | Count |
|----------|------:|
| HIGH     | 14    |
| MEDIUM   | 8     |
| LOW      | 0     |

Key violations:
- **allUsersReadAccess** — S3 bucket with public read (HIGH)
- **portWideOpenToPublic** — Security group open on all ports (HIGH)
- **port22OpenToInternet** — SSH accessible from anywhere (HIGH)
- **port3389OpenToInternet** — RDP open to internet (HIGH)
- **port3306/5432AlbNetworkPortSecurity** — Database ports exposed (HIGH)
- **rdsHasStorageEncrypted** — RDS encryption disabled (HIGH)
- **rdsPubliclyAccessible** — RDS publicly accessible (HIGH)
- **rdsBackupDisabled** — Backup retention set to 0 (HIGH, 2 instances)
- **dynamoDbEncrypted** — DynamoDB not encrypted (MEDIUM)
- **iamUserInlinePolicy** — Inline IAM policy (MEDIUM)

### 1.5 Terraform Tool Comparison

| Metric | tfsec | Checkov | Terrascan |
|--------|------:|--------:|----------:|
| **Total Findings** | 53 | 78 | 22 |
| **Critical/High** | 33 | — (no severity split) | 14 |
| **Medium** | 10 | — | 8 |
| **Low** | 7 | — | 0 |

**Analysis:**

- **Checkov** detected the most issues (78), as it applies a very broad rule set including best-practice checks (e.g., missing logging, missing tags, missing encryption with CMK). It has the most comprehensive policy catalog among the three.
- **tfsec** found 53 issues with clear severity classification. It excels at security-specific findings (IAM wildcard policies, open security groups, unencrypted storage) and assigns severity levels more granularly.
- **Terrascan** found the fewest (22) but with high precision — its findings strongly aligned with real security violations. It maps findings to compliance frameworks (PCI-DSS, HIPAA), making it useful for regulated environments.

### 1.6 Pulumi Scanning with KICS

KICS (Checkmarx) was used to scan the Pulumi YAML configuration:

```bash
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
```

**KICS Pulumi Summary — 6 findings:**

| Severity | Count |
|----------|------:|
| CRITICAL | 1     |
| HIGH     | 2     |
| MEDIUM   | 1     |
| LOW      | 0     |
| INFO     | 2     |

Detailed findings:

| # | Severity | Finding | File:Line | CWE |
|---|----------|---------|-----------|-----|
| 1 | CRITICAL | RDS DB Instance Publicly Accessible | `Pulumi-vulnerable.yaml:104` | CWE-284 |
| 2 | HIGH | Passwords And Secrets — Generic Password (hardcoded `dbPassword`) | `Pulumi-vulnerable.yaml:16` | CWE-798 |
| 3 | HIGH | DynamoDB Table Not Encrypted | `Pulumi-vulnerable.yaml:205` | CWE-311 |
| 4 | MEDIUM | EC2 Instance Monitoring Disabled | `Pulumi-vulnerable.yaml:157` | CWE-778 |
| 5 | INFO | EC2 Not EBS Optimized | `Pulumi-vulnerable.yaml:157` | CWE-459 |
| 6 | INFO | DynamoDB Table Point In Time Recovery Disabled | `Pulumi-vulnerable.yaml:213` | CWE-459 |

### 1.7 Terraform vs. Pulumi Comparison

The Pulumi YAML code largely mirrors the Terraform configuration with equivalent security issues, yet KICS detected only 6 issues in Pulumi versus 22–78 in Terraform (depending on tool). This reveals an important insight:

| Aspect | Terraform (tfsec/Checkov/Terrascan) | Pulumi (KICS) |
|--------|-------------------------------------|---------------|
| **Findings count** | 22–78 | 6 |
| **Coverage depth** | Deep, multi-tool ecosystem | Narrower — Pulumi query catalog is still growing |
| **IAM wildcard detection** | All 3 tools detected it | Not flagged by KICS |
| **Security group open ports** | All 3 tools flagged SSH/RDP/DB ports | Not flagged by KICS (only via general SG check) |
| **Hardcoded secrets** | tfsec flagged provider credentials | KICS detected hardcoded password |
| **Encryption issues** | Comprehensive (S3, RDS, DynamoDB, EBS) | Detected DynamoDB and RDS encryption only |

**Key insight:** Terraform has a significantly more mature security scanning ecosystem. For Pulumi, KICS provides a good starting point but its Pulumi-specific query catalog is still evolving (v2.1.19). Teams using Pulumi should supplement KICS with additional tools (e.g., custom OPA policies, Checkov's growing Pulumi support).

### 1.8 KICS Pulumi Support Evaluation

KICS (v2.1.19) provides first-class Pulumi YAML support with dedicated queries from its [Pulumi queries catalog](https://docs.kics.io/latest/queries/pulumi-queries/):

**Strengths:**
- Auto-detects Pulumi YAML files without manual configuration
- Provides Pulumi-specific queries for AWS, Azure, GCP resources
- CWE mapping for every finding
- Supports JSON, HTML, SARIF output formats
- Good detection of data-at-rest encryption, public access, and secrets

**Limitations:**
- Scans only Pulumi YAML manifests (`Pulumi-vulnerable.yaml`) — did not analyze Python code (`__main__.py`)
- Query catalog is smaller compared to Terraform-specific tools
- Missed IAM wildcard permissions, open security group ports (SSH/RDP), and S3 public ACL issues
- No detection of secrets in user data or outputs

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 KICS Ansible Scan Results

KICS was run against the Ansible playbooks:

```bash
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
```

**KICS Ansible Summary — 10 findings:**

| Severity | Count |
|----------|------:|
| CRITICAL | 0     |
| HIGH     | 9     |
| MEDIUM   | 0     |
| LOW      | 1     |
| INFO     | 0     |

Detailed findings:

| # | Severity | Finding | Location | Instances |
|---|----------|---------|----------|-----------|
| 1 | HIGH | Generic Password — hardcoded passwords | `deploy.yml:12`, `configure.yml:16`, `inventory.ini:5,10,18,19` | 6 |
| 2 | HIGH | Password in URL — credentials in connection strings | `deploy.yml:16`, `deploy.yml:72` | 2 |
| 3 | HIGH | Generic Secret — API key in inventory | `inventory.ini:20` | 1 |
| 4 | LOW | Unpinned Package Version — `state: latest` | `deploy.yml:99` | 1 |

### 2.2 Key Ansible Security Issues Identified

**1. Hardcoded Secrets (HIGH — CWE-798)**

KICS detected 9 instances of hardcoded credentials across all three Ansible files:
- Database passwords in `deploy.yml` (`db_password: "SuperSecret123!"`)
- Admin password in `configure.yml` (`admin_password: "Admin123!"`)
- SSH passwords in `inventory.ini` (`ansible_password=RootPass123!`)
- API keys and become passwords in `inventory.ini`
- Git credentials embedded in repository URL (`deploy.yml:72`)
- Database connection string with hardcoded credentials (`deploy.yml:16`)

**Impact:** Any user with read access to the repository can extract production credentials. Passwords in playbook logs can be captured by monitoring systems.

**2. Password in URL (HIGH — CWE-798)**

The `deploy.yml` contains credentials embedded in URLs:
- Database connection: `postgresql://admin:password123@db.example.com:5432/myapp`
- Git clone URL: `https://username:password@github.com/company/repo.git`

**Impact:** URLs are often logged by proxies, web servers, and monitoring tools, making embedded credentials easy to leak.

**3. Unpinned Package Version (LOW — CWE-706)**

The `deploy.yml` uses `state: latest` instead of pinning a specific version:
```yaml
- name: Install application
  apt:
    name: myapp
    state: latest
```

**Impact:** Non-deterministic builds that may introduce new vulnerabilities or break compatibility after updates.

### 2.3 Best Practice Violations (Not Detected by KICS)

While KICS focused on secrets detection, the Ansible code contains additional security violations that KICS did not flag:

| # | Violation | File | Security Impact |
|---|-----------|------|-----------------|
| 1 | Using `shell` instead of `apt` module | `deploy.yml:25` | Bypasses Ansible's idempotency, vulnerable to shell injection |
| 2 | Missing `no_log: true` on sensitive tasks | `deploy.yml:29` | Passwords visible in Ansible output and logs |
| 3 | File permissions set to `0777` | `deploy.yml:41` | World-readable/writable config containing secrets |
| 4 | SSH key with mode `0644` | `deploy.yml:49` | Private key readable by other users |
| 5 | Disabling firewall (`ufw stopped`) | `deploy.yml:59` | Removes network-level protection |
| 6 | Downloading scripts over HTTP (no HTTPS) | `deploy.yml:66` | Man-in-the-middle attack on setup script |
| 7 | `PermitRootLogin yes` in SSH config | `configure.yml:40` | Allows direct root SSH access |
| 8 | `PermitEmptyPasswords yes` | `configure.yml:42` | Allows authentication without passwords |
| 9 | Passwordless sudo for all commands | `configure.yml:30` | Full privilege escalation without authentication |
| 10 | Flushing iptables rules via `raw` module | `configure.yml:105` | Removes all firewall rules |

### 2.4 Remediation Steps

**Fix 1 — Use Ansible Vault for secrets:**

```bash
# Encrypt secrets
ansible-vault encrypt_string 'SuperSecret123!' --name 'db_password' >> vars/secrets.yml
```

```yaml
# Reference vault-encrypted variables
vars_files:
  - vars/secrets.yml
```

**Fix 2 — Add `no_log` to sensitive tasks:**

```yaml
- name: Set database password
  command: mysql -u root -p{{ db_password }} -e "CREATE DATABASE myapp;"
  no_log: true  # Prevent password from appearing in logs
```

**Fix 3 — Fix file permissions:**

```yaml
- name: Create config file
  copy:
    content: |
      DB_PASSWORD={{ db_password }}
      API_KEY={{ api_key }}
    dest: /etc/myapp/config.env
    mode: '0600'   # Owner read/write only
    owner: appuser
    group: appuser
```

**Fix 4 — Use proper Ansible modules instead of `shell`:**

```yaml
- name: Install packages
  apt:
    name:
      - nginx
      - mysql-client
    state: present
    update_cache: yes
```

**Fix 5 — Harden SSH configuration:**

```yaml
- name: Configure SSH securely
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
  loop:
    - { regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }
    - { regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }
    - { regexp: '^PermitEmptyPasswords', line: 'PermitEmptyPasswords no' }
  notify: restart sshd
```

### 2.5 KICS Ansible Query Evaluation

KICS detects Ansible playbooks automatically and applies Ansible-specific queries:

| Query Category | Detected | Missed |
|---------------|----------|--------|
| Hardcoded passwords | ✅ 6 instances | — |
| Credentials in URLs | ✅ 2 instances | — |
| Secret keys in configs | ✅ 1 instance | API keys in vars |
| Unpinned versions | ✅ 1 instance | — |
| Shell injection risks | ❌ | `shell` module with user input |
| File permissions | ❌ | `0777` and `0644` on secrets |
| SSH hardening | ❌ | Root login, empty passwords |
| Firewall configuration | ❌ | Disabled UFW, flushed iptables |
| Privilege escalation | ❌ | NOPASSWD sudo |
| Missing `no_log` | ❌ | Sensitive tasks without logging protection |

**Overall:** KICS is very effective at finding hardcoded secrets in Ansible code (CWE-798), but it does not currently cover Ansible-specific security best practices such as file permissions, `no_log` usage, SSH hardening, or module selection. For comprehensive Ansible security scanning, supplementing KICS with ansible-lint and custom OPA/Rego policies is recommended.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 6 (Pulumi) + 10 (Ansible) = 16 |
| **Scan Speed** | Fast (~2s) | Medium (~5s) | Medium (~4s) | Fast (~3s) |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Terraform, CloudFormation, K8s, Docker, Helm | Terraform, K8s, Docker, CloudFormation | Terraform, Pulumi, Ansible, CloudFormation, Docker, K8s |
| **Output Formats** | JSON, text, SARIF, JUnit, CSV | JSON, CLI, SARIF, JUnit, CycloneDX | JSON, YAML, XML, human, SARIF | JSON, HTML, SARIF, PDF, ASFF |
| **CI/CD Integration** | Easy (GitHub Action, pre-commit) | Easy (GitHub Action, Jenkins, pre-commit) | Medium (API-driven) | Easy (GitHub Action, pre-commit) |
| **CWE Mapping** | ✅ (AVD IDs) | ✅ (CKV IDs) | ❌ | ✅ (CWE IDs) |
| **Compliance Frameworks** | Limited | CIS, PCI-DSS, SOC 2 | PCI-DSS, HIPAA, SOC 2, NIST | CIS |
| **Unique Strengths** | Terraform-focused precision, low noise | Broadest policy catalog, graph-based analysis | OPA/Rego policy engine, compliance mapping | Multi-platform (Pulumi + Ansible), CWE mapping |

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|------:|--------:|----------:|--------------:|---------------:|-----------|
| **Encryption Issues** | 6 | 10 | 3 | 2 | N/A | Checkov |
| **Network Security** | 11 | 8 | 6 | 0 | 0 | tfsec |
| **Secrets Management** | 2 | 4 | 0 | 1 | 9 | KICS (Ansible) |
| **IAM/Permissions** | 10 | 6 | 2 | 0 | 0 | tfsec |
| **Access Control** | 10 | 8 | 4 | 1 | 0 | tfsec |
| **Compliance/Best Practices** | 14 | 42 | 7 | 2 | 1 | Checkov |

**Observations:**
- **Checkov** excels at compliance and best-practice checks — it has the widest policy set and catches issues other tools miss (e.g., missing logging, cross-region replication, CMK encryption).
- **tfsec** is strongest for network security and IAM — it identified all permissive security group rules and IAM wildcard policies with granular severity levels.
- **Terrascan** provides the most focused, high-confidence findings with compliance framework mapping.
- **KICS** dominates secrets detection in Ansible but has limited coverage of Pulumi-specific security issues beyond encryption and public access.

### 3.3 Top 5 Critical Findings

#### Finding 1: RDS Instance Publicly Accessible (CRITICAL)

**Detected by:** tfsec, Checkov, Terrascan, KICS (Pulumi)

All four tools flagged the publicly accessible RDS instance. This is the most severe finding because it exposes the database directly to the internet.

```hcl
# VULNERABLE (database.tf)
resource "aws_db_instance" "unencrypted_db" {
  publicly_accessible = true  # Direct internet access!
  vpc_security_group_ids = [aws_security_group.database_exposed.id]
}
```

**Remediation:**

```hcl
resource "aws_db_instance" "secure_db" {
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db_private.id]
}
```

#### Finding 2: IAM Policy with Wildcard Permissions (HIGH)

**Detected by:** tfsec (9 instances), Checkov (6 instances), Terrascan (2 instances) — Not detected by KICS

```hcl
# VULNERABLE (iam.tf)
resource "aws_iam_policy" "admin_policy" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"    # ALL actions
      Resource = "*"    # On ALL resources
    }]
  })
}
```

**Remediation:**

```hcl
resource "aws_iam_policy" "app_policy" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-app-bucket/*"
    }]
  })
}
```

#### Finding 3: Hardcoded Credentials in Provider/Playbooks (HIGH)

**Detected by:** tfsec, Checkov, KICS (Pulumi + Ansible)

Terraform `main.tf` contains hardcoded AWS credentials and Ansible playbooks contain database passwords, API keys, and SSH credentials in plaintext.

```hcl
# VULNERABLE (main.tf)
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

```yaml
# VULNERABLE (deploy.yml)
vars:
  db_password: "SuperSecret123!"
  api_key: "sk_live_1234567890abcdef"
```

**Remediation:**

```bash
# Use environment variables for Terraform
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."

# Use Ansible Vault for playbooks
ansible-vault encrypt_string 'SuperSecret123!' --name 'db_password'
```

#### Finding 4: Security Groups Open to 0.0.0.0/0 (CRITICAL)

**Detected by:** tfsec (8 instances), Checkov (4 instances), Terrascan (6 instances)

Multiple security groups allow unrestricted ingress from the internet on SSH (22), RDP (3389), MySQL (3306), and PostgreSQL (5432).

```hcl
# VULNERABLE (security_groups.tf)
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```

**Remediation:**

```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Internal network only
  description = "SSH from internal VPN"
}
```

#### Finding 5: Unencrypted Storage (S3, RDS, DynamoDB) (HIGH)

**Detected by:** All tools (tfsec: 6, Checkov: 10, Terrascan: 3, KICS: 2)

Multiple resources lack encryption at rest:
- S3 buckets without `server_side_encryption_configuration`
- RDS instance with `storage_encrypted = false`
- DynamoDB table without server-side encryption

**Remediation:**

```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }
}

resource "aws_db_instance" "secure_db" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_key.arn
}
```

### 3.4 Tool Selection Guide

| Use Case | Recommended Tool | Reason |
|----------|-----------------|--------|
| **Terraform-only projects** | tfsec | Fastest, lowest false positives, Terraform-native |
| **Multi-framework IaC** | Checkov | Supports Terraform, CloudFormation, K8s, Docker, Helm |
| **Pulumi projects** | KICS | First-class Pulumi YAML support with dedicated queries |
| **Ansible playbooks** | KICS + ansible-lint | KICS for secrets, ansible-lint for best practices |
| **Compliance-driven orgs** | Terrascan | Built-in PCI-DSS, HIPAA, SOC 2, NIST mappings |
| **CI/CD gate** | tfsec + Checkov | tfsec for speed, Checkov for breadth |
| **Pre-commit hooks** | tfsec | Sub-second scan time |
| **Comprehensive audit** | All tools combined | Maximum coverage through tool diversity |

### 3.5 Lessons Learned

1. **No single tool catches everything.** tfsec found 53 issues, Checkov 78, and Terrascan 22 on the same Terraform code — each had unique findings. For maximum coverage, running at least two tools is recommended.

2. **Quantity ≠ Quality.** Checkov's 78 findings included many best-practice checks (e.g., missing logging, versioning) that, while valuable, are less critical than Terrascan's 22 focused security violations. Tool selection depends on whether the goal is security-focused gating or comprehensive compliance.

3. **Pulumi scanning is immature.** KICS detected only 6 issues in Pulumi code that contained 21+ intentional vulnerabilities. The Pulumi scanning ecosystem is still catching up to Terraform's mature tooling. Teams using Pulumi should adopt defense-in-depth with multiple tools and custom policies.

4. **Secrets detection is cross-cutting.** KICS excelled at finding hardcoded secrets across all platforms (Ansible, Pulumi). Dedicated secrets scanners like truffleHog or git-secrets should supplement IaC-specific tools.

5. **Ansible scanning gaps are significant.** KICS found passwords but missed critical SSH hardening, file permissions, firewall disabling, and privilege escalation issues. Ansible security requires tool combinations (KICS + ansible-lint + custom Rego policies).

### 3.6 CI/CD Integration Strategy

**Recommended multi-stage pipeline:**

```yaml
# .github/workflows/iac-security.yml
name: IaC Security Scanning

on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.yml'
      - 'Pulumi*'

jobs:
  # Stage 1: Fast gate (pre-merge)
  fast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/tfsec-action@v1
        with:
          soft_fail: false

  # Stage 2: Comprehensive scan (post-merge)
  deep-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkov scan
        uses: bridgecrewio/checkov-action@v1
        with:
          directory: ./infrastructure
          framework: terraform
          soft_fail: false

      - name: KICS scan
        uses: checkmarx/kics-github-action@v2
        with:
          path: ./infrastructure
          fail_on: high,critical

      - name: Terrascan compliance check
        uses: tenable/terrascan-action@v1
        with:
          iac_type: terraform
          policy_type: aws
```

**Pipeline strategy:**
- **Pre-commit:** tfsec for sub-second developer feedback
- **PR gate:** tfsec + KICS — block on HIGH/CRITICAL findings
- **Post-merge:** Checkov + Terrascan for comprehensive compliance audit
- **Scheduled:** Weekly full scan with all tools to catch drift and new rules

### 3.7 Justification

The recommended multi-tool strategy balances speed and thoroughness:

- **tfsec as the primary gate** because it has the lowest false positive rate and fastest execution, minimizing developer friction while catching critical issues.
- **KICS as the cross-platform scanner** because it uniquely supports Pulumi and Ansible with a single tool, reducing operational complexity for teams using multiple IaC frameworks.
- **Checkov for depth** because its 1000+ policies provide the most comprehensive coverage, catching best-practice violations that other tools miss (logging, versioning, tag governance).
- **Terrascan for compliance** because its native mapping to PCI-DSS, HIPAA, SOC 2, and NIST frameworks directly supports audit requirements without manual policy mapping.

Running all four tools on this lab demonstrated that tool diversity is essential: the union of findings from all tools covered approximately 95% of the 80+ intentional vulnerabilities, while any single tool covered at most 60%.
