# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform Tool Comparison

Three security scanners were used to analyze intentionally vulnerable Terraform configurations across 5 files (`main.tf`, `security_groups.tf`, `database.tf`, `iam.tf`, `variables.tf`):

| Tool | Total Findings | CRITICAL | HIGH | MEDIUM | LOW |
|------|---------------|----------|------|--------|-----|
| **tfsec** | 53 | 9 | 25 | 11 | 8 |
| **Checkov** | 78 | — | — | — | — |
| **Terrascan** | 22 | 0 | 14 | 8 | 0 |

**Key observations:**

- **Checkov** detected the most findings (78), as it applies a very broad policy catalog (including cross-region replication, lifecycle configurations, event notifications, and SSO enforcement checks that other tools skip).
- **tfsec** found 53 issues with well-categorized severity levels. It was the only tool to flag findings as CRITICAL (9 — all related to public ingress/egress security group rules and publicly accessible RDS).
- **Terrascan** reported the fewest findings (22) with an OPA-based approach focused on compliance-relevant policies. It uniquely detected specific port-level security group violations (SSH port 22, RDP port 3389, PostgreSQL 5432, MySQL 3306).

**Findings overlap and divergence:**

All three tools agreed on core issues:
- Unencrypted RDS storage (`database.tf:5`)
- Publicly accessible RDS instances (`database.tf:17`)
- Security groups open to `0.0.0.0/0` (`security_groups.tf`)
- Missing S3 versioning and encryption (`main.tf`)
- Overly permissive IAM policies (`iam.tf`)

Unique detections:
- **Checkov only**: Hardcoded AWS access keys in provider block (`CKV_AWS_41`), S3 lifecycle configuration (`CKV2_AWS_61`), S3 event notifications (`CKV2_AWS_62`), cross-region replication (`CKV_AWS_144`), IAM privilege escalation (`CKV_AWS_286`), data exfiltration policies (`CKV_AWS_288`), SSO enforcement (`CKV_AWS_273`), full IAM privileges (`CKV2_AWS_40`)
- **tfsec only**: S3 customer-managed encryption keys (`AVD-AWS-0132`), public ACL checks (`AVD-AWS-0092`)
- **Terrascan only**: Specific port-based security group checks (SSH/RDP/PostgreSQL/MySQL), S3 public ACL without access block (`AC_AWS_0496`)

### 1.2 Pulumi Security Analysis (KICS)

KICS v2.1.20 scanned the Pulumi YAML manifest (`Pulumi-vulnerable.yaml`) and detected **6 findings**:

| Severity | Count | Findings |
|----------|-------|----------|
| **CRITICAL** | 1 | RDS DB Instance Publicly Accessible |
| **HIGH** | 2 | DynamoDB Table Not Encrypted, Generic Password in source |
| **MEDIUM** | 1 | EC2 Instance Monitoring Disabled |
| **INFO** | 2 | DynamoDB Point-in-Time Recovery Disabled, EC2 Not EBS Optimized |

**Detailed findings:**

1. **RDS DB Instance Publicly Accessible** (CRITICAL, CWE-284, risk 8.7) — `publiclyAccessible` set to `true` on `unencryptedDb` resource at line 104. This exposes the database to the public internet.
2. **DynamoDB Table Not Encrypted** (HIGH, CWE-311, risk 7.1) — `serverSideEncryption` attribute missing on `unencryptedTable` at line 205.
3. **Hardcoded Password** (HIGH, CWE-798, risk 7.8) — Generic password detected in the Pulumi YAML at line 16, exposing credentials in source code.
4. **EC2 Instance Monitoring Disabled** (MEDIUM, CWE-778, risk 5.1) — `monitoring` attribute missing on `unencryptedInstance` at line 157.
5. **DynamoDB Point-in-Time Recovery Disabled** (INFO) — `pointInTimeRecovery.enabled` set to `false` at line 213.
6. **EC2 Not EBS Optimized** (INFO) — `ebsOptimized` attribute not defined on EC2 instance at line 157.

### 1.3 Terraform vs. Pulumi Comparison

| Aspect | Terraform (HCL) | Pulumi (YAML) |
|--------|-----------------|---------------|
| **Tool ecosystem** | Mature — tfsec, Checkov, Terrascan all support it | Limited — KICS is one of few scanners with Pulumi support |
| **Findings detected** | 53–78 depending on tool | 6 (KICS only) |
| **Detection depth** | Deep — encryption, IAM, networking, compliance | Narrower — focused on resource-level misconfigurations |
| **Secrets detection** | Checkov detected hardcoded AWS keys in provider | KICS detected hardcoded passwords in YAML |
| **Coverage gaps** | Well-covered across multiple tools | Missing checks for security groups, S3 public access, IAM wildcards |

The Terraform ecosystem benefits from years of tool development with overlapping coverage, while Pulumi scanning is still maturing. KICS provides the best available Pulumi support with dedicated queries, but its catalog is smaller compared to Terraform-specific tools.

### 1.4 KICS Pulumi Support Evaluation

KICS applied **21 Pulumi-specific queries** against the manifest and matched 6. Strengths:
- Dedicated Pulumi query catalog covering AWS resources (RDS, DynamoDB, EC2)
- CWE mapping and risk scoring for each finding
- Auto-detection of Pulumi YAML platform
- Multiple output formats (JSON, HTML, console)

Limitations:
- Smaller query catalog (21 queries) compared to Terraform tools (Checkov validates 1000+ policies)
- Did not detect security group misconfigurations or S3 public access issues present in the Pulumi code
- No IAM wildcard permission checks for Pulumi resources

### 1.5 Critical Findings (Top 5 from Terraform & Pulumi)

**1. Security groups allow unrestricted ingress from 0.0.0.0/0** (tfsec CRITICAL — `security_groups.tf`)

All three security groups (`allow_all`, `ssh_open`, `database_exposed`) permit traffic from any IP. This enables attackers to reach internal services directly.

```hcl
# Remediation
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Restrict to internal network
}
```

**2. Publicly accessible RDS with no encryption** (tfsec CRITICAL — `database.tf:5-37`)

The `unencrypted_db` instance has `publicly_accessible = true` and `storage_encrypted = false`, with a hardcoded password.

```hcl
# Remediation
resource "aws_db_instance" "secure_db" {
  publicly_accessible = false
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds.arn
  password            = data.aws_secretsmanager_secret_version.db_pass.secret_string
}
```

**3. IAM policy with full admin privileges (Action: \*, Resource: \*)** (Checkov — `iam.tf:10`)

The `admin_policy` grants unrestricted access to all AWS services and resources, violating least-privilege.

```hcl
# Remediation
statement {
  actions   = ["s3:GetObject", "s3:PutObject"]
  resources = ["arn:aws:s3:::my-bucket/*"]
}
```

**4. Hardcoded AWS credentials in provider block** (Checkov `CKV_AWS_41` — `main.tf`)

AWS access key and secret key hardcoded in the Terraform provider configuration.

```hcl
# Remediation: Use environment variables or AWS profiles
provider "aws" {
  region = "us-east-1"
  # Use AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars
}
```

**5. S3 buckets with public ACL and no access block** (tfsec HIGH — `main.tf:13-21`)

The `public_data` bucket uses `public-read` ACL without encryption, versioning, or logging.

```hcl
# Remediation
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Ansible Security Issues

KICS scanned 3 Ansible files (`deploy.yml`, `configure.yml`, `inventory.ini`) and detected **10 findings**:

| Severity | Count |
|----------|-------|
| **HIGH** | 9 |
| **LOW** | 1 |

**Findings breakdown by query:**

| Query | Severity | Count | Files |
|-------|----------|-------|-------|
| Passwords And Secrets - Generic Password | HIGH | 6 | `inventory.ini` (4), `configure.yml` (1), `deploy.yml` (1) |
| Passwords And Secrets - Password in URL | HIGH | 2 | `deploy.yml` (lines 72, 16) |
| Passwords And Secrets - Generic Secret | HIGH | 1 | `inventory.ini` (line 20) |
| Unpinned Package Version | LOW | 1 | `deploy.yml` (line 99) |

### 2.2 Best Practice Violations

**1. Hardcoded passwords in inventory and playbooks** (HIGH, CWE-798)

Plaintext credentials appear across all three files. `inventory.ini` contains 4 instances of hardcoded passwords for host authentication, `deploy.yml` has database connection strings with embedded passwords, and `configure.yml` stores service credentials directly.

**Security impact:** Anyone with repository access can extract production credentials. Leaked credentials enable unauthorized access to servers, databases, and services.

**Remediation:**
```yaml
# Use Ansible Vault for secrets
ansible-vault encrypt_string 'SuperSecretPassword123!' --name 'db_password'

# Reference vault variables in playbooks
- name: Configure database
  mysql_db:
    login_password: "{{ db_password }}"
  no_log: true
```

**2. Password embedded in URL** (HIGH, CWE-798)

`deploy.yml` contains URLs with credentials (e.g., `postgres://user:password@host/db`), exposing secrets in logs and process listings.

**Security impact:** Passwords in URLs appear in shell history, process tables, and application logs. URL-encoded credentials bypass most secret scanning tools.

**Remediation:**
```yaml
- name: Configure database connection
  template:
    src: db_config.j2
    dest: /etc/app/db.conf
    mode: '0600'
  vars:
    db_url: "postgres://{{ db_user }}:{{ vault_db_password }}@{{ db_host }}/{{ db_name }}"
  no_log: true
```

**3. Unpinned package version** (LOW, CWE-706)

`deploy.yml` uses `state: latest` for package installation, which can introduce untested versions.

**Security impact:** Using `latest` may install packages with known vulnerabilities or breaking changes. Supply chain attacks can exploit unpinned dependencies.

**Remediation:**
```yaml
- name: Install application
  apt:
    name: "myapp=1.2.3-1"
    state: present
    update_cache: yes
```

### 2.3 KICS Ansible Query Evaluation

KICS applied **287 Ansible-specific queries** and matched 4 unique query types. The scanner excels at:
- **Secret detection** — Found 9 out of 10 findings related to hardcoded credentials, passwords in URLs, and generic secrets across all file types (YAML playbooks and INI inventory)
- **Supply chain checks** — Detected unpinned package versions that could introduce vulnerabilities

Limitations observed:
- Did not flag missing `no_log: true` on sensitive tasks (a common Ansible security best practice)
- Did not detect `shell`/`command` module usage where Ansible modules would be safer
- No checks for overly permissive file permissions (e.g., `mode: '0777'`)
- No detection of missing `become` privilege escalation controls

### 2.4 Remediation Steps

1. **Encrypt all secrets with Ansible Vault:** `ansible-vault encrypt inventory.ini vars/secrets.yml`
2. **Add `no_log: true`** to every task that handles passwords, API keys, or tokens
3. **Pin package versions** to specific releases instead of using `state: latest`
4. **Remove credentials from URLs** and use connection parameter files with restricted permissions
5. **Use Ansible modules** instead of `shell`/`command` for idempotent operations
6. **Set file permissions** to `0600` for credential files, `0644` for configs

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (6 Pulumi + 10 Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Fast |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ★★★★ | ★★★★★ | ★★★ | ★★★★ |
| **Ease of Use** | ★★★★★ | ★★★★ | ★★★ | ★★★★ |
| **Documentation** | ★★★★ | ★★★★★ | ★★★ | ★★★★ |
| **Platform Support** | Terraform only | Terraform, CloudFormation, K8s, Docker, Serverless | Terraform, K8s, Docker, CloudFormation | Terraform, Pulumi, Ansible, CloudFormation, Docker, K8s |
| **Output Formats** | JSON, text, SARIF, CSV, JUnit | JSON, CLI, SARIF, JUnit, CSV | JSON, YAML, XML, human | JSON, HTML, SARIF, console |
| **CI/CD Integration** | Easy (GitHub Action, pre-commit) | Easy (GitHub Action, pre-commit, IDE) | Medium (CLI-based) | Easy (GitHub Action, GitLab CI) |
| **Unique Strengths** | Fast, low false positives, Terraform-focused | Broadest policy catalog, auto-fix suggestions | OPA-based compliance mapping | Multi-platform (Pulumi + Ansible), secret detection |

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|-------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption Issues** | 5 | 5 | 2 | 1 | 0 | tfsec/Checkov |
| **Network Security** | 11 | 12 | 5 | 0 | 0 | Checkov |
| **Secrets Management** | 0 | 1 | 0 | 1 | 9 | KICS |
| **IAM/Permissions** | 12 | 15 | 2 | 0 | 0 | Checkov |
| **Access Control** | 14 | 9 | 3 | 1 | 0 | tfsec |
| **Compliance/Best Practices** | 11 | 36 | 10 | 3 | 1 | Checkov |

**Key insights:**
- **Checkov** leads in IAM, network security, and compliance checks due to its 1000+ policy catalog
- **tfsec** excels at access control checks (S3 public access blocks, public bucket restrictions)
- **KICS** is the strongest at secret detection, finding 9 hardcoded credentials in Ansible and 1 in Pulumi
- **Terrascan** provides focused, compliance-relevant findings with lower noise

### 3.3 Top 5 Critical Findings (Cross-Tool)

| # | Finding | Severity | Tool(s) | File | Remediation |
|---|---------|----------|---------|------|-------------|
| 1 | Security group allows all traffic from 0.0.0.0/0 | CRITICAL | tfsec, Checkov, Terrascan | `security_groups.tf:5` | Restrict CIDR blocks to specific IPs |
| 2 | RDS publicly accessible + unencrypted | CRITICAL | All tools | `database.tf:5` | Set `publicly_accessible=false`, `storage_encrypted=true` |
| 3 | IAM policy with `Action: *, Resource: *` | HIGH | tfsec, Checkov | `iam.tf:10` | Apply least-privilege with specific actions/resources |
| 4 | Hardcoded passwords in Ansible inventory | HIGH | KICS | `inventory.ini` | Use Ansible Vault encryption |
| 5 | S3 bucket with public-read ACL | HIGH | tfsec, Checkov, Terrascan | `main.tf:13` | Enable public access block, remove public ACL |

### 3.4 Tool Selection Guide

| Use Case | Recommended Tool(s) | Rationale |
|----------|---------------------|-----------|
| **Terraform-only projects** | tfsec + Checkov | tfsec for fast CI checks, Checkov for comprehensive coverage |
| **Multi-framework IaC** | KICS + Checkov | KICS covers Pulumi/Ansible, Checkov covers Terraform/K8s/Docker |
| **Compliance-driven orgs** | Terrascan + Checkov | OPA policies mapped to PCI-DSS, HIPAA, SOC2 |
| **Pre-commit hooks** | tfsec | Fastest scan time, low false positives |
| **Secret detection in IaC** | KICS | Best secret scanning across file types |
| **Pulumi projects** | KICS | Only tool with first-class Pulumi YAML support |
| **Ansible security** | KICS | Comprehensive Ansible query catalog (287 queries) |

### 3.5 CI/CD Integration Strategy

A multi-stage pipeline is recommended for comprehensive IaC security:

```
Stage 1 (Pre-commit / PR):
  - tfsec (fast, low false positives) → block on CRITICAL/HIGH
  - KICS (Pulumi + Ansible) → block on CRITICAL/HIGH

Stage 2 (CI Pipeline):
  - Checkov (comprehensive) → block on CRITICAL, warn on HIGH
  - Terrascan (compliance) → generate compliance reports

Stage 3 (Scheduled):
  - Full scan with all tools → track trends, update baselines
  - Policy drift detection → alert on new findings
```

**Justification:** Stage 1 uses fast tools to give immediate developer feedback. Stage 2 runs deeper analysis that takes longer. Stage 3 catches drift and provides compliance evidence.

### 3.6 Lessons Learned

1. **No single tool catches everything.** Checkov found 78 issues while Terrascan found 22 on the same code. Running multiple tools provides the most comprehensive coverage.

2. **Tool verbosity varies significantly.** Checkov's 78 findings include many granular compliance checks (cross-region replication, lifecycle policies) that other tools consider out of scope. More findings does not always mean better — some are noise for specific use cases.

3. **Secret detection is a gap in Terraform-focused tools.** tfsec found zero secrets. Only Checkov detected the hardcoded provider credentials (`CKV_AWS_41`). KICS was the strongest secret scanner overall.

4. **Pulumi security tooling is immature.** KICS is effectively the only option for Pulumi scanning, and its 21-query catalog caught only 6 issues. The same infrastructure patterns in Terraform were flagged 53–78 times.

5. **Terrascan's compliance focus adds unique value.** While it found fewer total issues, its OPA-based approach with compliance framework mapping (PCI-DSS, HIPAA) provides audit-ready evidence that other tools lack.

6. **KICS excels as a unified multi-platform scanner.** Using a single tool across Pulumi and Ansible reduces toolchain complexity, though supplementing with framework-specific tools (tfsec/Checkov for Terraform) is still necessary for depth.
