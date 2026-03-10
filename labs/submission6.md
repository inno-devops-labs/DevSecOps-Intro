# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform Tool Comparison

Three security scanners were used to analyze the intentionally vulnerable Terraform code located in `labs/lab6/vulnerable-iac/terraform/`.

**Scan Results Summary:**

| Tool | Total Findings | Severity Breakdown |
|------|---------------|-------------------|
| **tfsec** | 53 | CRITICAL: 9, HIGH: 25, MEDIUM: 11, LOW: 8 |
| **Checkov** | 78 failed (48 passed) | 45 unique check types across 16 resources |
| **Terrascan** | 22 | HIGH: 14, MEDIUM: 8 |

**tfsec** detected 53 issues across all Terraform files. Key findings include:

- `AVD-AWS-0041` — Hardcoded AWS access key and secret key in provider configuration (`main.tf`)
- `AVD-AWS-0092` — S3 bucket with public-read ACL
- `AVD-AWS-0088` — S3 bucket without encryption enabled
- `AVD-AWS-0107` — Security group rules allowing ingress from `0.0.0.0/0`
- `AVD-AWS-0080` — RDS instance without storage encryption
- `AVD-AWS-0082` — RDS instance publicly accessible
- `AVD-AWS-0057` — IAM policy with wildcarded actions (`*`) on wildcarded resources (`*`)
- `AVD-AWS-0104` — Security group rules allowing egress to public internet
- `AVD-AWS-0086/0087` — Missing public access block on S3 buckets

**Checkov** found 78 failed checks out of 126 total checks (48 passed). Unique findings include:

- `CKV_AWS_41` — Hardcoded AWS credentials in provider
- `CKV_AWS_62` — Full `*-*` administrative IAM privileges
- `CKV_AWS_286` — IAM policies allowing privilege escalation
- `CKV_AWS_287` — IAM policies allowing credentials exposure
- `CKV_AWS_288` — IAM policies allowing data exfiltration
- `CKV_AWS_289` — IAM policies allowing permissions management without constraints
- `CKV_AWS_273` — Access not controlled through SSO
- `CKV_AWS_293` — Missing deletion protection on RDS
- `CKV_AWS_353` — Missing performance insights on RDS
- `CKV2_AWS_61` — Missing S3 lifecycle configuration
- `CKV2_AWS_62` — Missing S3 event notifications

**Terrascan** identified 22 violated policies:

- `rdsBackupDisabled` (HIGH) — Backup disabled on RDS instances
- `rdsHasStorageEncrypted` (HIGH) — RDS storage not encrypted
- `allUsersReadAccess` (HIGH) — S3 bucket with public read access
- `port22OpenToInternet` (HIGH) — SSH port open to `0.0.0.0/0`
- `port3389OpenToInternet` (HIGH) — RDP port open to internet
- `port3306AlbNetworkPortSecurity` (HIGH) — MySQL port exposed
- `port5432AlbNetworkPortSecurity` (HIGH) — PostgreSQL port exposed
- `portWideOpenToPublic` (HIGH) — All ports open to public
- `rdsPubliclyAccessible` (HIGH) — RDS publicly accessible
- `s3PublicAclNoAccessBlock` (HIGH) — S3 public ACL without access block
- `dynamoDbEncrypted` (MEDIUM) — DynamoDB table not encrypted
- `iamUserInlinePolicy` (MEDIUM) — IAM user with inline policy

**Effectiveness Analysis:**

Checkov found the most issues (78) due to its extensive policy library that covers not just core security but also operational best practices (lifecycle configs, event notifications, cross-region replication). tfsec found 53 issues with clear severity levels and detailed remediation guidance. Terrascan found 22 issues, focusing on the most critical network and encryption violations with compliance framework mapping.

### 1.2 Pulumi Security Analysis (KICS)

KICS (Checkmarx) was used to scan the Pulumi YAML manifest (`Pulumi-vulnerable.yaml`) containing 21 intentional vulnerabilities.

**KICS Pulumi Findings: 6 total**

| Severity | Count | Findings |
|----------|-------|----------|
| **CRITICAL** | 1 | RDS DB Instance Publicly Accessible |
| **HIGH** | 2 | DynamoDB Table Not Encrypted, Passwords And Secrets - Generic Password |
| **MEDIUM** | 1 | EC2 Instance Monitoring Disabled |
| **INFO** | 2 | DynamoDB Table Point In Time Recovery Disabled, EC2 Not EBS Optimized |

**Detailed Findings:**

1. **RDS DB Instance Publicly Accessible** (CRITICAL, CWE-284) — `publiclyAccessible: true` in `Pulumi-vulnerable.yaml:104`. RDS instances must not have public interfaces.
2. **DynamoDB Table Not Encrypted** (HIGH, CWE-311) — Missing `serverSideEncryption` on DynamoDB table resource.
3. **Passwords And Secrets - Generic Password** (HIGH, CWE-798) — Hardcoded `dbPassword: "SuperSecret123!"` in variables section.
4. **EC2 Instance Monitoring Disabled** (MEDIUM, CWE-778) — EC2 instance lacks detailed monitoring configuration.
5. **DynamoDB Table Point In Time Recovery Disabled** (INFO, CWE-459) — `enabled: false` for point-in-time recovery.
6. **EC2 Not EBS Optimized** (INFO, CWE-459) — EC2 instance not using EBS-optimized instance type.

**KICS Pulumi Support Evaluation:**

KICS successfully auto-detected the Pulumi YAML platform and applied Pulumi-specific security queries. It identified critical issues like publicly accessible RDS, unencrypted DynamoDB, and hardcoded secrets. However, KICS found only 6 out of 21 intentional vulnerabilities in the Pulumi code — it missed several issues that tfsec/Checkov catch in equivalent Terraform code, such as:
- Open security groups (`0.0.0.0/0` ingress)
- IAM wildcard policies (`Action: "*"`)
- S3 bucket public ACL
- Unencrypted EBS volumes
- Secrets in EC2 user data

This suggests KICS's Pulumi query catalog is still maturing compared to its Terraform coverage.

### 1.3 Terraform vs. Pulumi Comparison

| Aspect | Terraform (HCL) | Pulumi (YAML) |
|--------|-----------------|---------------|
| **Tool ecosystem** | Mature (tfsec, Checkov, Terrascan) | Emerging (KICS) |
| **Max findings** | 78 (Checkov) | 6 (KICS) |
| **Detection coverage** | Encryption, IAM, network, secrets, compliance | Encryption, secrets, monitoring, publicly accessible resources |
| **Missed by tools** | Very few blind spots with multiple tools | IAM wildcards, open security groups, S3 public ACL |

The declarative HCL approach benefits from years of tool development with extensive rule catalogs. Pulumi YAML scanning via KICS is functional but has a narrower query catalog, particularly around IAM policy analysis and network security group inspection.

### 1.4 Critical Findings (Top 5)

**1. Hardcoded AWS Credentials (CRITICAL)**
- **File:** `main.tf:8-9`, `Pulumi-vulnerable.yaml:16`
- **Issue:** AWS access_key and secret_key hardcoded in provider config
- **Risk:** Credential leakage, unauthorized AWS access
- **Remediation:**
```hcl
# Use environment variables or AWS CLI profile
provider "aws" {
  region = "us-east-1"
  # Credentials from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
}
```

**2. Publicly Accessible RDS Instance (CRITICAL)**
- **File:** `database.tf:17`, `Pulumi-vulnerable.yaml:104`
- **Issue:** `publicly_accessible = true` with unencrypted storage
- **Risk:** Database exposed to internet, data breach
- **Remediation:**
```hcl
resource "aws_db_instance" "secure_db" {
  publicly_accessible = false
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.db_key.arn
}
```

**3. Wildcard IAM Policy (CRITICAL)**
- **File:** `iam.tf:9-18`
- **Issue:** `Action: "*"` and `Resource: "*"` granting full admin access
- **Risk:** Complete AWS account takeover if role is compromised
- **Remediation:**
```hcl
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [{
    Effect   = "Allow"
    Action   = ["s3:GetObject", "s3:PutObject"]
    Resource = "arn:aws:s3:::my-bucket/*"
  }]
})
```

**4. Security Groups Open to Internet (HIGH)**
- **File:** `security_groups.tf:10-16`
- **Issue:** Ingress from `0.0.0.0/0` on all ports (`-1` protocol)
- **Risk:** Any service on the instance is reachable from the entire internet
- **Remediation:**
```hcl
ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Internal network only
}
```

**5. S3 Bucket with Public Read ACL (HIGH)**
- **File:** `main.tf:15`
- **Issue:** `acl = "public-read"` with no public access block
- **Risk:** Data exposure, compliance violations
- **Remediation:**
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### 1.5 Tool Strengths

| Tool | Unique Strengths |
|------|-----------------|
| **tfsec** | Clear severity ratings, fast execution, Terraform-specific with detailed file/line references, low false positives |
| **Checkov** | Largest rule set (45 unique checks), detects IAM privilege escalation/credentials exposure/data exfiltration patterns, compliance-oriented |
| **Terrascan** | Network port-specific checks (3306, 5432, 3389), OPA-based for custom policies, compliance framework mapping (PCI-DSS, HIPAA) |
| **KICS** | Multi-platform (Pulumi, Ansible, Terraform, CloudFormation), CWE mapping, HTML report output, auto-detects platform |

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Ansible Security Issues

KICS identified **10 findings** across the Ansible playbooks (`deploy.yml`, `configure.yml`, `inventory.ini`).

**Findings by Severity:**

| Severity | Count |
|----------|-------|
| **HIGH** | 9 |
| **LOW** | 1 |
| **Total** | 10 |

**Detailed KICS Findings:**

| # | Finding | Severity | Count | Files |
|---|---------|----------|-------|-------|
| 1 | Passwords And Secrets - Generic Password | HIGH | 6 | `inventory.ini` (4), `configure.yml` (1), `deploy.yml` (1) |
| 2 | Passwords And Secrets - Password in URL | HIGH | 2 | `deploy.yml` (2) |
| 3 | Passwords And Secrets - Generic Secret | HIGH | 1 | `inventory.ini` (1) |
| 4 | Unpinned Package Version | LOW | 1 | `deploy.yml` (1) |

### 2.2 Best Practice Violations (Top 3)

**Violation 1: Hardcoded Passwords in Inventory and Playbooks (HIGH, CWE-798)**

Passwords are stored in plaintext across multiple files:
- `inventory.ini:5` — `ansible_password=RootPass123!`
- `inventory.ini:18-20` — `ansible_become_password`, `db_admin_password`, `api_secret_key` in `[all:vars]`
- `deploy.yml:12` — `db_password: "SuperSecret123!"`
- `configure.yml:16` — `admin_password: "Admin123!"`

**Security Impact:** Anyone with repository access can read production credentials. Credential rotation becomes impossible without code changes. Secrets appear in git history permanently.

**Remediation:**
```yaml
# Use Ansible Vault for secrets
- name: Deploy web application
  hosts: webservers
  vars_files:
    - vault/secrets.yml  # Encrypted with ansible-vault
  tasks:
    - name: Set database password
      command: mysql -u root -p{{ db_password }} -e "CREATE DATABASE myapp;"
      no_log: true  # Prevent password from appearing in logs
```
```bash
# Encrypt secrets file
ansible-vault encrypt vault/secrets.yml
```

**Violation 2: Credentials in Git Repository URLs (HIGH, CWE-798)**

- `deploy.yml:72` — `repo: 'https://username:password@github.com/company/repo.git'`
- `deploy.yml:16` — `db_connection: "postgresql://admin:password123@db.example.com:5432/myapp"`

**Security Impact:** Credentials are embedded in URLs visible in logs, git history, and process listings. Database connection strings with passwords can be extracted by anyone inspecting the playbook.

**Remediation:**
```yaml
- name: Clone repository
  git:
    repo: "https://github.com/company/repo.git"
    dest: /var/www/myapp
    key_file: /home/deploy/.ssh/deploy_key
    accept_hostkey: yes
```

**Violation 3: Unpinned Package Versions (LOW, CWE-706)**

- `deploy.yml:99` — `state: latest` for package installation

**Security Impact:** Using `latest` can introduce untested versions with new vulnerabilities or breaking changes. Non-deterministic deployments make it impossible to reproduce exact environments for debugging.

**Remediation:**
```yaml
- name: Install application
  apt:
    name: myapp=2.1.0-1
    state: present
    update_cache: yes
```

### 2.3 KICS Ansible Queries Evaluation

KICS detected secrets management issues effectively (9 out of 10 findings). Its "Passwords And Secrets" query family identified:
- Generic passwords in variables and inventory
- Passwords embedded in URLs (database connection strings, git URLs)
- API secret keys in inventory files

However, KICS missed several Ansible-specific issues present in the vulnerable code:
- `shell` module usage instead of proper Ansible modules (`deploy.yml:21`)
- Missing `no_log: true` on sensitive tasks (`deploy.yml:26`)
- Overly permissive file permissions `0777` (`deploy.yml:36`)
- SSH key with wrong permissions `0644` instead of `0600` (`deploy.yml:45`)
- Disabled firewall (`deploy.yml:59`)
- Downloading scripts over HTTP without verification (`deploy.yml:66`)
- Shell injection risk in `rm -rf {{ user_input }}/*` (`deploy.yml:112`)
- Disabled SELinux (`configure.yml:22`)
- Weak SSH configuration — `PermitRootLogin yes`, `PermitEmptyPasswords yes` (`configure.yml:40-42`)
- NOPASSWD sudo (`configure.yml:29`)
- Flushing firewall rules with `raw` module (`configure.yml:109`)

KICS's Ansible coverage is strong for secrets detection but limited for configuration hardening, privilege management, and command injection patterns.

### 2.4 Remediation Steps

| Issue | Remediation |
|-------|-------------|
| Hardcoded secrets | Use **Ansible Vault**: `ansible-vault encrypt group_vars/all/vault.yml` |
| Passwords in inventory | Use vault-encrypted variables or SSH keys instead of passwords |
| Credentials in URLs | Use SSH keys for git, environment variables for database connections |
| Unpinned packages | Pin specific versions: `name: myapp=2.1.0-1, state: present` |
| Missing `no_log` | Add `no_log: true` to all tasks handling secrets |
| Permissive file modes | Use `0644` for configs, `0600` for keys, never `0777` |
| Shell module usage | Replace `shell` with proper modules (`apt`, `file`, `service`) |
| Weak SSH config | Set `PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no` |

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 6 (Pulumi) + 10 (Ansible) = 16 |
| **Scan Speed** | Fast (~2s) | Medium (~5s) | Medium (~4s) | Fast (~3s) |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Terraform, CloudFormation, K8s, Docker | Terraform, K8s, Docker | Terraform, Pulumi, Ansible, CloudFormation, Docker, K8s |
| **Output Formats** | JSON, text, SARIF, JUnit | JSON, CLI, SARIF, JUnit, CSV | JSON, human, YAML, XML | JSON, HTML, SARIF, CSV, PDF |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strengths** | Terraform-focused precision, low noise | Largest check library, IAM deep analysis | OPA-based custom policies, compliance mapping | Broadest platform support, CWE mapping |

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|-------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption Issues** | 8 | 6 | 4 | 1 | N/A | tfsec |
| **Network Security** | 12 | 8 | 7 | 0 | 0 | tfsec |
| **Secrets Management** | 2 | 2 | 0 | 1 | 9 | KICS (Ansible) |
| **IAM/Permissions** | 10 | 14 | 2 | 0 | 0 | Checkov |
| **Access Control** | 12 | 10 | 5 | 1 | 0 | tfsec / Checkov |
| **Compliance/Best Practices** | 9 | 38 | 4 | 3 | 1 | Checkov |

**Key Observations:**

- **Checkov** dominates in IAM analysis with specialized checks for privilege escalation (`CKV_AWS_286`), credentials exposure (`CKV_AWS_287`), data exfiltration (`CKV_AWS_288`), and permission management (`CKV_AWS_289`).
- **tfsec** excels at network security — it found 12 network-related issues vs. Terrascan's 7 and Checkov's 8.
- **Terrascan** uniquely identifies protocol-specific port exposure (MySQL 3306, PostgreSQL 5432).
- **KICS** is the only tool that scans Pulumi YAML and Ansible, with excellent secret detection capabilities across Ansible files.

### 3.3 Top 5 Critical Findings (Across All Frameworks)

**1. Hardcoded AWS Credentials in Provider** — Found by tfsec, Checkov
- `main.tf:8-9`: `access_key = "AKIAIOSFODNN7EXAMPLE"`, `secret_key = "wJalrXUtnFEMI/K7MDENG/..."`
- Risk Score: 9.8 (Critical)
- Fix: Use IAM roles, environment variables, or AWS profiles

**2. Wildcard IAM Policy (`*:*`)** — Found by tfsec, Checkov, Terrascan
- `iam.tf:14`: `Action = "*"`, `Resource = "*"`
- Risk Score: 9.1 (Critical)
- Fix: Apply least-privilege principle with specific actions and resource ARNs

**3. Publicly Accessible RDS Without Encryption** — Found by all tools
- `database.tf:17`: `publicly_accessible = true`, `storage_encrypted = false`
- Risk Score: 8.7 (Critical)
- Fix: Set `publicly_accessible = false`, `storage_encrypted = true` with KMS key

**4. Security Groups Open to 0.0.0.0/0 on All Ports** — Found by tfsec, Checkov, Terrascan
- `security_groups.tf:14-15`: `protocol = "-1"`, `cidr_blocks = ["0.0.0.0/0"]`
- Risk Score: 8.5 (High)
- Fix: Restrict to specific CIDR ranges and required ports only

**5. Plaintext Credentials in Ansible Inventory** — Found by KICS
- `inventory.ini:5-10`: `ansible_password=RootPass123!`, `ansible_become_password=Sudo123!`
- Risk Score: 7.8 (High)
- Fix: Use Ansible Vault or SSH key authentication

### 3.4 Tool Selection Guide

| Use Case | Recommended Tool(s) | Justification |
|----------|---------------------|---------------|
| **Terraform-only CI/CD** | tfsec + Checkov | tfsec for fast PR checks, Checkov for comprehensive scans |
| **Multi-framework project** | KICS + Checkov | KICS covers Pulumi/Ansible, Checkov covers Terraform/CloudFormation/K8s |
| **Compliance-focused** | Terrascan + Checkov | Terrascan maps to PCI-DSS/HIPAA, Checkov provides CIS benchmarks |
| **Quick pre-commit hook** | tfsec | Fastest execution, lowest false positives, clear output |
| **Pulumi infrastructure** | KICS | Only scanner with first-class Pulumi YAML support |
| **Ansible playbooks** | KICS | Strong secrets detection for Ansible files |
| **Maximum coverage** | tfsec + Checkov + KICS | Combine Terraform specialists with multi-platform KICS |

### 3.5 Lessons Learned

1. **No single tool catches everything.** Checkov found 78 issues while Terrascan found 22 on the same code — combining tools significantly increases coverage.

2. **IAM analysis requires specialized tools.** Checkov's IAM privilege escalation checks (`CKV_AWS_286-290`) are unique and critical. Neither tfsec nor Terrascan detected data exfiltration or credential exposure patterns.

3. **Pulumi tooling is maturing.** KICS detected 6 out of 21 intentional Pulumi vulnerabilities. Teams using Pulumi should supplement KICS with manual code reviews or custom policies for comprehensive coverage.

4. **KICS excels at secrets detection.** In Ansible scanning, 9 of 10 findings were secrets-related (CWE-798). It effectively identified passwords in inventory files, connection strings, and playbook variables.

5. **False positive management matters.** Checkov's high finding count (78) includes some that may be informational rather than critical (e.g., missing S3 event notifications). Teams should triage findings by severity and relevance.

6. **Terrascan provides unique compliance context.** Its mapping of findings to compliance frameworks (PCI-DSS, HIPAA) is valuable for regulated industries.

### 3.6 CI/CD Integration Strategy

**Recommended Multi-Stage Pipeline:**

```
Stage 1: Pre-commit (Local)
├── tfsec (Terraform) — fast feedback, <3s
└── KICS (Pulumi/Ansible) — multi-platform check

Stage 2: PR Validation (CI)
├── Checkov --hard-fail-on CRITICAL,HIGH
├── tfsec --minimum-severity HIGH
├── KICS --fail-on high
└── Gate: Block merge if CRITICAL/HIGH findings exist

Stage 3: Pre-Deploy (CD)
├── Terrascan (compliance scan with framework mapping)
├── Checkov (full scan with SARIF output to security dashboard)
└── Gate: Manual approval required for any new findings
```

**Justification:**
- **Stage 1** uses the fastest tools for immediate developer feedback
- **Stage 2** uses comprehensive tools that catch the most issues (Checkov + tfsec), blocking PRs with critical findings
- **Stage 3** adds compliance mapping (Terrascan) for audit trails before production deployment
- SARIF output enables integration with GitHub Security tab, Defect Dojo, or other security dashboards

This layered approach balances speed (developer experience) with thoroughness (security coverage), ensuring that critical issues are caught early while comprehensive analysis happens before deployment.

---

## Appendix: Scan Evidence

### tfsec Output (excerpt)

```
Results: 53 issues found
  CRITICAL: 9
  HIGH:     25
  MEDIUM:   11
  LOW:      8

Key findings include:
- AVD-AWS-0041: Hardcoded credentials in provider
- AVD-AWS-0092: S3 bucket with public ACL
- AVD-AWS-0107: Security group ingress from 0.0.0.0/0
- AVD-AWS-0080: RDS without storage encryption
- AVD-AWS-0057: IAM wildcarded actions
```

### Checkov Output (excerpt)

```
Passed checks: 48, Failed checks: 78, Skipped checks: 0
Checkov version: 3.2.508
Resource count: 16

Key failed checks:
- CKV_AWS_41: Hardcoded AWS access key in provider
- CKV_AWS_62: Full administrative IAM privileges
- CKV_AWS_286: IAM privilege escalation
- CKV_AWS_16: RDS not encrypted at rest
- CKV_AWS_17: RDS publicly accessible
```

### Terrascan Output (excerpt)

```
Violated policies: 22
  HIGH:   14
  MEDIUM: 8

Key violations:
- rdsHasStorageEncrypted (HIGH)
- port22OpenToInternet (HIGH)
- portWideOpenToPublic (HIGH)
- allUsersReadAccess (HIGH)
- rdsPubliclyAccessible (HIGH)
```

### KICS Pulumi Output (excerpt)

```
CRITICAL: 1 (RDS DB Instance Publicly Accessible)
HIGH:     2 (DynamoDB Not Encrypted, Generic Password)
MEDIUM:   1 (EC2 Instance Monitoring Disabled)
INFO:     2 (DynamoDB PITR Disabled, EC2 Not EBS Optimized)
TOTAL:    6
```

### KICS Ansible Output (excerpt)

```
HIGH: 9 (Passwords and Secrets — 6 Generic Password, 2 Password in URL, 1 Generic Secret)
LOW:  1 (Unpinned Package Version)
TOTAL: 10
```
