# Lab 6 Submission — IaC Security: Scanning & Policy Enforcement

## Overview

This submission documents security scanning of intentionally vulnerable Infrastructure-as-Code across three frameworks:
- **Terraform** — scanned with tfsec, Checkov, and Terrascan
- **Pulumi** — scanned with KICS (Checkmarx)
- **Ansible** — scanned with KICS (Checkmarx)

All scans were performed using Docker containers on the `labs/lab6/vulnerable-iac/` directory.

---

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Scan Results Summary

#### Terraform — tfsec

```
Tool: aquasec/tfsec:latest
Target: labs/lab6/vulnerable-iac/terraform/
```

**Total findings: 53**

| Severity | Count |
|----------|-------|
| CRITICAL | 9 |
| HIGH | 25 |
| MEDIUM | 11 |
| LOW | 8 |

Sample critical findings from tfsec:
- `database.tf:17` — `publicly_accessible = true` (aws-rds-no-public-db-access)
- `security_groups.tf:15` — `cidr_blocks = ["0.0.0.0/0"]` on all traffic security group (aws-ec2-no-public-ingress-sg)
- `main.tf:8` — Hardcoded AWS access key in provider block (aws-credentials)

#### Terraform — Checkov

```
Tool: bridgecrew/checkov:latest
Target: labs/lab6/vulnerable-iac/terraform/
```

**Total findings: 78 failed checks** (48 passed, 0 skipped)

Checkov's broader policy catalog produced more findings than tfsec. Notable categories detected:
- `CKV_AWS_18` — S3 bucket missing access logging
- `CKV_AWS_19` — S3 bucket not encrypted at rest
- `CKV_AWS_20` — S3 bucket has public ACL
- `CKV_AWS_21` — S3 bucket versioning not enabled
- `CKV_AWS_28` — RDS backup retention period is zero
- `CKV_AWS_17` — RDS storage not encrypted
- `CKV_AWS_23` — RDS instance not multi-AZ
- `CKV_AWS_79` — EC2 metadata service IMDSv2 not enforced
- `CKV_AWS_40` — IAM policy allows `*` actions (wildcard)
- `CKV_AWS_274` — IAM access key exposed in outputs

#### Terraform — Terrascan

```
Tool: tenable/terrascan:latest
Target: labs/lab6/vulnerable-iac/terraform/
```

**Total findings: 22 violated policies** (out of 167 validated)

| Severity | Count |
|----------|-------|
| HIGH | 14 |
| MEDIUM | 8 |
| LOW | 0 |

Terrascan focuses on compliance-mapped policies. Key HIGH findings:
- `AWS.SG.Network.High.0095` — Security group allows unrestricted access on all ports
- `AWS.RDS.DataSecurity.High.0414` — RDS storage encryption disabled
- `AWS.IAM.IAMPolicies.High.0391` — IAM policy with wildcard permissions
- `AWS.S3.NetworkSecurity.High.0414` — S3 bucket ACL is public

### 1.2 Terraform Tool Comparison

| Criterion | tfsec | Checkov | Terrascan |
|-----------|-------|---------|-----------|
| **Total Findings** | 53 | 78 | 22 |
| **Scan Speed** | Fast (~5s) | Medium (~30s) | Medium (~20s) |
| **False Positives** | Low | Low-Medium | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform only | Multi-framework | Multi-framework |
| **Output Formats** | JSON, text, SARIF, JUnit, CSV | JSON, CLI, SARIF, JUnit, CycloneDX | JSON, YAML, XML, human |
| **CI/CD Integration** | Easy | Easy | Medium |
| **Unique Strengths** | Speed, low noise | Widest coverage, 1000+ policies | Compliance mapping (PCI, HIPAA, NIST) |

**Analysis:** Checkov produced the most findings (78) due to its extensive policy catalog covering governance, access logging, and compliance. tfsec found 53 findings with excellent signal-to-noise ratio, making it ideal for developer-facing CI. Terrascan found fewest raw findings (22) but provides superior compliance framework mapping.

### 1.3 Pulumi Security Scanning with KICS

```
Tool: checkmarx/kics:v2.1.20
Target: labs/lab6/vulnerable-iac/pulumi/ (Pulumi-vulnerable.yaml)
```

**Total findings: 6**

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

**Detailed KICS Pulumi Findings:**

| # | Severity | Finding | File:Line |
|---|----------|---------|-----------|
| 1 | CRITICAL | RDS DB Instance Publicly Accessible (`publiclyAccessible: true`) | Pulumi-vulnerable.yaml:104 |
| 2 | HIGH | Passwords And Secrets — Generic Password (`dbPassword` hardcoded) | Pulumi-vulnerable.yaml:16 |
| 3 | HIGH | DynamoDB Table Not Encrypted (no `serverSideEncryption`) | Pulumi-vulnerable.yaml:205 |
| 4 | MEDIUM | EC2 Instance Monitoring Disabled (detailed monitoring off) | Pulumi-vulnerable.yaml:157 |
| 5 | INFO | DynamoDB Table Point In Time Recovery Disabled | Pulumi-vulnerable.yaml:213 |
| 6 | INFO | EC2 Not EBS Optimized | Pulumi-vulnerable.yaml:157 |

**Note:** KICS detected 6 findings on the Pulumi YAML manifest. The relatively lower count compared to the 21 documented vulnerabilities in the file reflects that KICS's Pulumi query catalog is still maturing — it covers the highest-impact issues (publicly accessible RDS, hardcoded secrets, unencrypted DynamoDB) but does not yet have full parity with Terraform-specific checks for IAM wildcards, EKS public access, EBS encryption, or CloudWatch log retention.

### 1.4 Terraform vs. Pulumi Security Comparison

| Issue Category | Terraform (all tools) | Pulumi (KICS) |
|---------------|----------------------|---------------|
| Publicly accessible RDS | ✅ Detected | ✅ Detected (CRITICAL) |
| Hardcoded secrets | ✅ Detected | ✅ Detected (HIGH) |
| Open security groups (0.0.0.0/0) | ✅ Detected | ❌ Not detected by KICS |
| IAM wildcard permissions | ✅ Detected | ❌ Not detected by KICS |
| S3 public ACL | ✅ Detected | ❌ Not detected by KICS |
| Unencrypted DynamoDB | ✅ Detected | ✅ Detected (HIGH) |
| EBS volume encryption | ✅ Detected | ❌ Not detected by KICS |
| EC2 monitoring | ⚠️ Partial | ✅ Detected (MEDIUM) |

**Conclusion:** HCL (Terraform) is better supported across all three tools. Pulumi YAML support in KICS is functional but covers fewer query categories. For Pulumi Python (`__main__.py`), KICS does not scan it — only the YAML manifest is analyzed.

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Scan Results

```
Tool: checkmarx/kics:v2.1.20
Target: labs/lab6/vulnerable-iac/ansible/
Files: deploy.yml, configure.yml, inventory.ini
```

**Total findings: 10**

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |

**Detailed KICS Ansible Findings:**

| # | Severity | Query | Location |
|---|----------|-------|----------|
| 1 | HIGH | Passwords & Secrets — Generic Password (`db_password`) | deploy.yml:12 |
| 2 | HIGH | Passwords & Secrets — Generic Password (`admin_password`) | configure.yml:16 |
| 3 | HIGH | Passwords & Secrets — Generic Password (inventory host password) | inventory.ini:5 |
| 4 | HIGH | Passwords & Secrets — Generic Password (`ansible_become_password`) | inventory.ini:18 |
| 5 | HIGH | Passwords & Secrets — Generic Password (`db_admin_password`) | inventory.ini:19 |
| 6 | HIGH | Passwords & Secrets — Generic Password (host password) | inventory.ini:10 |
| 7 | HIGH | Passwords & Secrets — Password in URL (DB connection string) | deploy.yml:16 |
| 8 | HIGH | Passwords & Secrets — Password in URL (Git repo URL with credentials) | deploy.yml:72 |
| 9 | HIGH | Passwords & Secrets — Generic Secret (`api_secret_key`) | inventory.ini:20 |
| 10 | LOW | Unpinned Package Version (`state: latest`) | deploy.yml:99 |

### 2.2 Ansible Security Issues Analysis

KICS identified 10 findings across 3 files, dominated by secrets management failures (9 HIGH). Three key best practice violations:

#### Violation 1: Hardcoded Credentials Throughout Playbooks and Inventory

**Files:** `deploy.yml`, `configure.yml`, `inventory.ini`

```yaml
# deploy.yml - INSECURE
vars:
  db_password: "<REDACTED - hardcoded secret>"
  api_key: "<REDACTED - hardcoded secret>"
  db_connection: "postgresql://admin:<REDACTED>@db.example.com:5432/myapp"

# inventory.ini - INSECURE
web1.example.com ansible_user=root ansible_password=<REDACTED>
```

**Security Impact:** Credentials stored in plaintext in version control are accessible to anyone with repository access. Compromised credentials allow attackers direct database and system access.

**Remediation:**
```yaml
# Use Ansible Vault for all sensitive values
# ansible-vault encrypt_string 'SuperSecret123!' --name 'db_password'
vars:
  db_password: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    ...encrypted...
```

#### Violation 2: Credentials Embedded in URLs

**File:** `deploy.yml:72`

```yaml
# INSECURE
git:
  repo: 'https://username:<REDACTED>@github.com/company/repo.git'
  dest: /var/www/myapp
```

**Security Impact:** Credentials in URLs are logged by git, shell history, process lists, and HTTP access logs — creating multiple exposure vectors.

**Remediation:**
```yaml
# Use SSH keys or Git credential store
git:
  repo: 'git@github.com:company/repo.git'
  dest: /var/www/myapp
  key_file: /path/to/deploy_key
  accept_hostkey: yes
```

#### Violation 3: Unpinned Package Versions

**File:** `deploy.yml:99`

```yaml
# INSECURE
apt:
  name: myapp
  state: latest  # Non-deterministic!
```

**Security Impact:** `state: latest` introduces supply-chain risk — a malicious or breaking update could be automatically installed during playbook execution, breaking production systems or introducing vulnerabilities.

**Remediation:**
```yaml
apt:
  name: myapp=2.4.1
  state: present  # Pin to known-good version
```

### 2.3 Additional Security Issues Not Detected by KICS

KICS focused on secrets and package management. The following issues in the Ansible code were **not** flagged by KICS but represent significant security problems:

- `configure.yml:21` — Disabling SELinux (`state: disabled`) removes mandatory access control
- `configure.yml:29` — Passwordless sudo for all commands (`NOPASSWD: ALL`)
- `configure.yml:40-43` — SSH configured to allow root login and empty passwords
- `deploy.yml:57-62` — Firewall (ufw) explicitly disabled
- `deploy.yml:66` — Curl-pipe-bash pattern (`curl http://example.com/setup.sh | bash`) with HTTP (no TLS)
- `deploy.yml:45` — SSH private key deployed with `mode: 0644` (should be 0600)
- `deploy.yml:36` — Config file with secrets at `mode: 0777` (world-readable)
- `deploy.yml:91` — `ignore_errors: yes` on database migration (critical task)
- Tasks handling passwords lack `no_log: true`

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Comprehensive Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 (TF) | 78 (TF) | 22 (TF) | 16 (Pulumi 6 + Ansible 10) |
| **Scan Speed** | Fast | Medium | Medium | Medium-Slow |
| **False Positives** | Low | Low-Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | TF, CF, K8s, Docker, ARM | TF, CF, K8s, Helm | TF, CF, K8s, Pulumi, Ansible, Docker |
| **Output Formats** | JSON, text, SARIF, JUnit, CSV | JSON, CLI, SARIF, JUnit, CycloneDX | JSON, YAML, XML, human | JSON, HTML, SARIF, JUnit, ASFF |
| **CI/CD Integration** | Easy | Easy | Medium | Medium |
| **Compliance Mapping** | Limited | CIS, SOC2 | PCI-DSS, HIPAA, NIST, CIS | OWASP, CIS, NIST |
| **Unique Strengths** | Speed, low noise, TF-native | Widest IaC coverage, 1000+ policies | Compliance frameworks | Multi-IaC unified scanning (Pulumi, Ansible) |

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|----------|
| **Encryption Issues** | ✅ High | ✅ High | ✅ Medium | ✅ Partial | N/A | Checkov |
| **Network Security** | ✅ High | ✅ High | ✅ Medium | ❌ Low | N/A | tfsec / Checkov |
| **Secrets Management** | ✅ Medium | ✅ High | ❌ Low | ✅ High | ✅ High | Checkov / KICS |
| **IAM/Permissions** | ✅ High | ✅ High | ✅ Medium | ❌ Low | N/A | Checkov |
| **Access Control** | ✅ High | ✅ High | ✅ Medium | ✅ Partial | ✅ Partial | Checkov |
| **Compliance/Best Practices** | ✅ Medium | ✅ High | ✅ High | ❌ Low | ✅ Medium | Checkov / Terrascan |
| **Ansible-specific** | N/A | N/A | N/A | N/A | ✅ Medium | KICS |

### 3.3 Top 5 Critical Security Findings

#### Finding 1: Hardcoded AWS Credentials in Provider Block
**Severity:** CRITICAL | **Tool:** tfsec | **File:** `terraform/main.tf:8-9`

```hcl
# VULNERABLE
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

**Risk:** Static credentials in code are exposed in version history permanently. AWS account compromise allows resource creation, data exfiltration, or ransomware.

**Remediation:**
```hcl
# SECURE - Use environment variables or instance profiles
provider "aws" {
  region = var.aws_region
  # Credentials from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
  # or EC2 instance profile / ECS task role
}
```

#### Finding 2: RDS Instance Publicly Accessible with No Encryption
**Severity:** CRITICAL | **Tools:** tfsec, Checkov, Terrascan, KICS (Pulumi) | **File:** `terraform/database.tf:15-17`

```hcl
# VULNERABLE
resource "aws_db_instance" "unencrypted_db" {
  storage_encrypted   = false  # Data at rest unprotected
  publicly_accessible = true   # Exposed to internet
  password            = "<REDACTED - hardcoded secret>"
  backup_retention_period = 0  # No backups
}
```

**Risk:** Database directly reachable from internet, unencrypted data, no recovery point. Regulatory violation (GDPR, HIPAA, PCI-DSS).

**Remediation:**
```hcl
resource "aws_db_instance" "secure_db" {
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  publicly_accessible     = false
  password                = var.db_password  # From secrets manager
  backup_retention_period = 7
  multi_az                = true
  deletion_protection     = true
}
```

#### Finding 3: Security Group Allowing All Traffic from 0.0.0.0/0
**Severity:** CRITICAL | **Tools:** tfsec, Checkov, Terrascan | **File:** `terraform/security_groups.tf:5-28`

```hcl
# VULNERABLE
ingress {
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]  # All internet traffic!
}
```

**Risk:** Zero network segmentation. Any internet host can reach all ports on associated EC2 instances.

**Remediation:**
```hcl
ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Internal only
}
```

#### Finding 4: IAM Policy with Wildcard Actions and Resources
**Severity:** HIGH | **Tools:** tfsec, Checkov | **File:** `terraform/iam.tf:14-15`

```hcl
# VULNERABLE
Statement = [{
  Effect   = "Allow"
  Action   = "*"    # All AWS actions
  Resource = "*"    # All resources
}]
```

**Risk:** Violates least-privilege principle. Any compromised workload with this policy is equivalent to root access — can create users, exfiltrate data, destroy infrastructure.

**Remediation:**
```hcl
Statement = [{
  Effect = "Allow"
  Action = [
    "s3:GetObject",
    "s3:PutObject"
  ]
  Resource = "arn:aws:s3:::my-specific-bucket/*"
}]
```

#### Finding 5: Hardcoded Credentials in Ansible Inventory and Playbooks
**Severity:** HIGH | **Tool:** KICS | **Files:** `ansible/inventory.ini`, `ansible/deploy.yml`

```ini
# VULNERABLE - inventory.ini
web1.example.com ansible_user=root ansible_password=WebPass123!
db1.example.com  ansible_user=root ansible_password=DBPass456!

[all:vars]
ansible_become_password=BecomePass789!
db_admin_password=DbAdmin321!
```

**Risk:** Version-controlled inventory with plaintext passwords exposes all managed systems to anyone with repository access.

**Remediation:**
```bash
# Encrypt the inventory variables with Ansible Vault
ansible-vault encrypt_string 'WebPass123!' --name 'ansible_password'
# Use vault ID for multi-environment key management
ansible-playbook site.yml --vault-id prod@~/.vault_pass_prod
```

### 3.4 Tool Selection Guide

| Use Case | Recommended Tool | Rationale |
|----------|-----------------|-----------|
| Fast PR gate checks for Terraform | **tfsec** | Fastest scan, low false positives, direct fix links |
| Comprehensive policy enforcement (Terraform) | **Checkov** | 1000+ policies, widest issue coverage, multi-framework |
| Compliance-regulated environments (PCI, HIPAA) | **Terrascan** | Built-in compliance framework mapping |
| Pulumi YAML scanning | **KICS** | Only tool with native Pulumi support |
| Ansible playbook scanning | **KICS** | Comprehensive Ansible query catalog |
| Unified multi-IaC platform | **KICS** | Single tool for Terraform, Pulumi, Ansible, K8s |
| Custom organizational policies | **Conftest (OPA)** | Write custom Rego policies for any IaC |

### 3.5 CI/CD Integration Strategy

Recommended multi-stage pipeline for comprehensive IaC security:

```yaml
# .github/workflows/iac-security.yml
stages:
  # Stage 1: Fast developer feedback (pre-commit hook / PR check)
  - name: tfsec
    tool: aquasec/tfsec
    trigger: on every push
    fail_on: CRITICAL, HIGH
    purpose: Rapid feedback, lowest friction

  # Stage 2: Comprehensive check (PR merge gate)
  - name: checkov
    tool: bridgecrew/checkov
    trigger: on PR to main
    fail_on: CRITICAL, HIGH
    purpose: Full policy coverage, compliance checks

  # Stage 3: Multi-framework scan (weekly or on release)
  - name: kics
    tool: checkmarx/kics
    trigger: on PR to main (for Pulumi/Ansible repos)
    fail_on: CRITICAL, HIGH
    purpose: Pulumi YAML and Ansible playbook scanning

  # Stage 4: Compliance validation (release gate)
  - name: terrascan
    tool: tenable/terrascan
    trigger: on release branch
    fail_on: HIGH violations of mapped compliance controls
    purpose: PCI-DSS / HIPAA compliance evidence
```

**Rationale:** Running all tools on every commit is too slow. The layered approach balances speed (tfsec in seconds) with completeness (Checkov's 1000+ policies) and compliance evidence (Terrascan's framework mapping).

### 3.6 Lessons Learned

1. **No single tool catches everything.** tfsec missed 25 findings that Checkov found (governance, logging, access logging). Checkov missed compliance framework context that Terrascan provides.

2. **KICS Pulumi support is partial.** 21 vulnerabilities were documented in `Pulumi-vulnerable.yaml` but KICS only detected 6. Issues like open security groups (`0.0.0.0/0`), IAM wildcards, EBS encryption, and EKS public access were missed. KICS's Pulumi query catalog is growing but not yet complete.

3. **KICS Ansible coverage focuses on secrets.** All 9 HIGH findings were secret-related. Structural issues (disabled firewalls, passwordless sudo, SSH misconfiguration, curl-pipe-bash) were not detected — these require Ansible-specific linters like `ansible-lint`.

4. **Terrascan has the fewest raw findings but highest compliance value.** 22 findings vs. 78 for Checkov seems like less coverage, but Terrascan maps each to PCI-DSS/HIPAA controls — valuable for audit evidence.

5. **False positive rate matters.** tfsec's low false positive rate makes it the best choice for developer-facing feedback. Checkov's broader coverage comes with more rules that may need `checkov:skip` suppressions in mature codebases.

6. **Secrets in IaC are pervasive.** Across all frameworks, hardcoded secrets were the most common and consistently detected vulnerability class — emphasizing the need for vault solutions (AWS Secrets Manager, HashiCorp Vault, Ansible Vault) from day one.

---

## Scan Evidence

All scan result files are in `labs/lab6/analysis/`:

| File | Tool | Format |
|------|------|--------|
| `tfsec-results.json` | tfsec | JSON (53 findings) |
| `tfsec-report.txt` | tfsec | Human-readable |
| `checkov-terraform-results.json` | Checkov | JSON (78 findings) |
| `checkov-terraform-report.txt` | Checkov | Human-readable |
| `terrascan-results.json` | Terrascan | JSON (22 findings) |
| `terrascan-report.txt` | Terrascan | Human-readable |
| `kics-pulumi-results.json` | KICS | JSON (6 findings) |
| `kics-pulumi-report.html` | KICS | HTML |
| `kics-pulumi-report.txt` | KICS | Minimal UI text |
| `kics-ansible-results.json` | KICS | JSON (10 findings) |
| `kics-ansible-report.html` | KICS | HTML |
| `kics-ansible-report.txt` | KICS | Minimal UI text |
| `tool-comparison.txt` | Summary | Text |
| `terraform-comparison.txt` | Summary | Text |
| `pulumi-analysis.txt` | Summary | Text |
| `ansible-analysis.txt` | Summary | Text |
