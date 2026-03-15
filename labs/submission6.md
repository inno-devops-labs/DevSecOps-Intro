# Lab 6 Submission — IaC Security Scanning and Comparative Analysis

**Student:** Maria Nikolashina  
**Date:** March 15, 2026

**Evidence used:** `labs/lab6/analysis/tfsec-results.json`, `labs/lab6/analysis/checkov-terraform-results.json`, `labs/lab6/analysis/terrascan-results.json`, `labs/lab6/analysis/kics-pulumi-results.json`, `labs/lab6/analysis/kics-ansible-results.json`, and the vulnerable IaC catalog in `labs/lab6/vulnerable-iac/README.md`.

---

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform Security Analysis

| Tool | Findings | Severity / Summary |
|------|----------|--------------------|
| **tfsec** | **53** | 9 Critical, 25 High, 11 Medium, 8 Low |
| **Checkov** | **78** failed checks | 48 passed, 0 skipped, 16 resources scanned |
| **Terrascan** | **22** policy violations | 14 High, 8 Medium |

**Key observations**

- **tfsec** produced the clearest Terraform-native results. It strongly highlighted public exposure, encryption gaps, weak IAM policies, and S3 access-block problems.
- **Checkov** had the broadest Terraform coverage. It found issues that tfsec did not flag in this run, including hardcoded AWS provider credentials, multiple IAM privilege-escalation paths, and more detailed governance checks.
- **Terrascan** returned fewer findings, but the output was high-signal and policy-oriented. It was especially effective for network exposure, RDS protection, and IAM/access-governance checks.

**Important Terraform issues detected across the three tools**

- Publicly accessible S3 bucket and disabled public access block
- Unencrypted S3, DynamoDB, and RDS resources
- Wide-open security groups (`0.0.0.0/0`, SSH/RDP/database ports open)
- RDS backup, monitoring, and deletion-protection gaps
- IAM wildcard permissions and excessive inline/user-attached permissions
- Hardcoded credentials and exposed programmatic IAM access

**Terraform tool comparison**

- **Best raw coverage:** Checkov
- **Best severity labeling and Terraform signal:** tfsec
- **Best policy/compliance perspective:** Terrascan

### 1.2 Pulumi Security Analysis (KICS)

**KICS Pulumi results**

- **Total findings:** 6
- **Severity:** 1 Critical, 2 High, 1 Medium, 2 Info

**Findings detected**

1. RDS DB instance publicly accessible
2. DynamoDB table not encrypted
3. Hardcoded password / secret in Pulumi YAML
4. EC2 detailed monitoring disabled
5. DynamoDB point-in-time recovery disabled
6. EC2 not EBS optimized

**Assessment**

KICS successfully scanned the Pulumi YAML and detected several real issues, especially around encryption, secret management, and exposed databases. However, compared with the vulnerability catalog in `labs/lab6/vulnerable-iac/README.md`, coverage was partial. The vulnerable Pulumi manifest contains 21+ intentional issues, while KICS reported 6 findings in this run. The main reason is that KICS analyzed the YAML representation only, and its Pulumi query pack is narrower than the combined Terraform coverage produced by tfsec + Checkov + Terrascan.

**Pulumi remediation priorities**

- Remove hardcoded secrets from YAML and store them in Pulumi secrets or an external secret manager
- Disable `publiclyAccessible` on RDS
- Enable DynamoDB encryption and point-in-time recovery
- Enable EC2 monitoring and use hardened instance/storage defaults

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Ansible Security Analysis

**KICS Ansible results**

- **Total findings:** 10
- **Severity:** 9 High, 1 Low

**What KICS detected well**

- Hardcoded passwords and secret values in playbooks and inventory
- Passwords embedded in URLs
- Plaintext credentials in inventory variables
- Unpinned package version (`state: latest`)

**Best practice violations and security impact**

1. **Hardcoded secrets in playbooks and inventory**
   - Examples: `db_password`, `api_key`, `ansible_password`, `ansible_become_password`
   - **Impact:** Anyone with repo access can recover credentials and reuse them in other environments.

2. **Credentials embedded in URLs**
   - Example: Git repo URL with username/password
   - **Impact:** Secrets leak through logs, shell history, CI output, and proxy logs.

3. **Unpinned package versions**
   - Example: `state: latest`
   - **Impact:** Deployments become non-deterministic and can pull unreviewed package updates.

**KICS Ansible query assessment**

- **Strong areas:** secret discovery, plaintext credentials, obvious supply-chain hygiene issues
- **Weak areas in this run:** SSH hardening, SELinux disabling, overly permissive file modes, raw/shell misuse, and firewall misconfiguration

This means KICS is useful for Ansible baseline scanning, but it should not be the only control for operational hardening. Additional linting and custom policy checks are still needed.

**Recommended remediation**

- Move all credentials into Ansible Vault or an external secret manager
- Replace credential-bearing URLs with token-based or SSH-based access
- Pin package versions explicitly
- Add `no_log: true` to secret-handling tasks
- Add separate lint/policy controls for SSH, file permissions, firewall rules, and dangerous module usage

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Comparison Matrix

The ratings below are based on this lab run and the generated artifacts, not on vendor marketing claims. Because the codebase is intentionally vulnerable, the **false positive** column reflects relative noise and overlap rather than absolute validation.

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 total (6 Pulumi + 10 Ansible) |
| **Scan Speed** | Fast | Medium | Fast | Medium |
| **False Positives** | Low | Medium | Low-Medium | Medium |
| **Report Quality** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform only | Multiple IaC types | Multiple IaC types | Multiple IaC types |
| **Output Formats Observed in This Lab** | JSON, text | JSON, CLI text | JSON, text | JSON, HTML, text |
| **CI/CD Integration** | Easy | Easy | Medium | Medium |
| **Unique Strengths** | Fast Terraform-native misconfiguration detection with good severity labels | Broadest rule coverage, especially IAM and governance | Policy-oriented compliance view with concise output | Best cross-IaC option here for Pulumi and Ansible, especially secret detection |

**Overall conclusion**

- If the repository is mostly **Terraform**, the strongest pairing is **tfsec + Checkov**.
- If the repository is **mixed IaC**, KICS becomes necessary for **Pulumi** and **Ansible** coverage.
- Terrascan adds value as a secondary governance/policy lens, but it was not the primary coverage driver in this lab.

### 3.2 Vulnerability Category Analysis

To make the tools comparable, I normalized each finding into one best-fit domain:

- **Encryption Issues**
- **Network Security**
- **Secrets Management**
- **IAM / Permissions**
- **Access Control**
- **Compliance / Best Practices**

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|------:|--------:|----------:|--------------:|---------------:|-----------|
| **Encryption Issues** | 7 | 4 | 2 | 1 | 0 | **tfsec** |
| **Network Security** | 10 | 10 | 6 | 1 | 0 | **Checkov** |
| **Secrets Management** | 0 | 1 | 1 | 1 | 9 | **KICS (Ansible)** |
| **IAM / Permissions** | 10 | 23 | 1 | 0 | 0 | **Checkov** |
| **Access Control** | 10 | 7 | 2 | 0 | 0 | **tfsec** |
| **Compliance / Best Practices** | 16 | 33 | 10 | 3 | 1 | **Checkov** |

**Category insights**

- **Encryption:** tfsec was strongest for Terraform encryption misconfigurations across S3, DynamoDB, and RDS. It clearly highlighted both missing encryption and weaker KMS posture.
- **Network Security:** tfsec and Checkov both caught public exposure, but Checkov was slightly better for detailed rule granularity because it separated SSH, RDP, HTTP, all-port ingress, and unrestricted egress checks.
- **Secrets Management:** KICS clearly dominated secret detection in Ansible. It caught hardcoded passwords, generic secrets, and passwords in URLs that the Terraform-focused scanners do not handle well.
- **IAM / Permissions:** Checkov was the strongest tool by a large margin. It detected wildcard actions/resources, privilege escalation, credentials exposure, write access without constraints, data exfiltration potential, and SSO-related governance issues.
- **Access Control:** tfsec gave the cleanest signal around public buckets and public-access-block failures.
- **Compliance / Best Practices:** Checkov had the broadest governance coverage, including logging, lifecycle, replication, monitoring, backup, versioning, and configuration hygiene.

**Unique findings seen by only one tool family in this lab**

- **tfsec:** customer-managed-key recommendations and several S3 public access block issues with strong severity labeling
- **Checkov:** hardcoded AWS provider credentials and more detailed IAM abuse-path checks
- **Terrascan:** exposed programmatic IAM access key creation and concise OPA-style policy output
- **KICS (Pulumi):** Pulumi YAML-specific checks such as EC2 monitoring and EBS optimization guidance
- **KICS (Ansible):** plaintext passwords, generic secrets, and password-in-URL detections across inventory and playbooks

### 3.3 Top 5 Critical Findings with Remediation Examples

#### 1. Publicly Accessible RDS and Public Database Ports

**Why it matters:** The combination of `publicly_accessible = true` and security groups open on `3306`/`5432` exposes the database directly to the internet.

**Safer Terraform example**

```hcl
resource "aws_security_group" "db_private" {
  name        = "db-private"
  description = "Allow database access only from the app tier"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Postgres from app security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "secure_db" {
  publicly_accessible   = false
  vpc_security_group_ids = [aws_security_group.db_private.id]
}
```

#### 2. Wildcard IAM Permissions

**Why it matters:** Policies with `Action = "*"` and `Resource = "*"` violate least privilege and enable privilege escalation or full account takeover.

**Safer Terraform example**

```hcl
resource "aws_iam_policy" "app_readonly_s3" {
  name = "app-readonly-s3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.private_data.arn,
          "${aws_s3_bucket.private_data.arn}/*"
        ]
      }
    ]
  })
}
```

#### 3. Hardcoded Cloud and Database Credentials

**Why it matters:** Hardcoded secrets are reusable credentials. Once committed, they must be treated as compromised.

**Safer Terraform example**

```hcl
provider "aws" {
  region = var.aws_region
}

resource "aws_db_instance" "secure_db" {
  username = var.db_username
  password = var.db_password
}

variable "db_password" {
  type      = string
  sensitive = true
}
```

**Safer Ansible example**

```yaml
- name: Create config file securely
  copy:
    dest: /etc/myapp/config.env
    owner: root
    group: root
    mode: "0600"
    content: |
      DB_PASSWORD={{ vault_db_password }}
      API_KEY={{ vault_api_key }}
  no_log: true
```

#### 4. Public S3 Bucket Without Access Block

**Why it matters:** Public-read ACLs and disabled public access block settings create immediate data exposure risk.

**Safer Terraform example**

```hcl
resource "aws_s3_bucket" "private_data" {
  bucket = "my-private-bucket-lab6"
}

resource "aws_s3_bucket_public_access_block" "private_data" {
  bucket = aws_s3_bucket.private_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_data" {
  bucket = aws_s3_bucket.private_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

#### 5. Missing Backups, Logging, and Recovery Controls

**Why it matters:** Lack of backups, PITR, CloudWatch logging, and deletion protection turns a security incident into an availability and recovery incident.

**Safer Terraform example**

```hcl
resource "aws_db_instance" "resilient_db" {
  backup_retention_period         = 7
  deletion_protection            = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
  auto_minor_version_upgrade     = true
  performance_insights_enabled   = true
}

resource "aws_dynamodb_table" "secure_table" {
  name         = "my-secure-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}
```

### 3.4 Tool Selection Guide

**Recommended combinations by use case**

1. **Terraform-heavy repository**
   - Use **tfsec + Checkov**
   - Reason: best balance of speed, clear severity, and broad Terraform policy coverage

2. **Mixed IaC repository (Terraform + Pulumi + Ansible)**
   - Use **Checkov + KICS**, optionally add **tfsec** for Terraform PR gating
   - Reason: KICS covered Pulumi and Ansible, while Checkov remained strongest on Terraform governance

3. **Compliance-driven environment**
   - Use **Checkov + Terrascan**
   - Reason: both are policy-oriented; Terrascan is useful as a second opinion for governance controls

4. **Secret-heavy configuration repos**
   - Use **KICS** as a required control
   - Reason: it was the best detector for plaintext credentials in playbooks and inventory

### 3.5 Lessons Learned

- No single scanner found all intentionally vulnerable cases.
- Higher finding count does not automatically mean better quality; rule overlap and granularity matter.
- tfsec provided the cleanest Terraform developer experience.
- Checkov had the broadest Terraform coverage, especially for IAM and governance.
- Terrascan was narrower, but its policy model still added useful defense-in-depth.
- KICS was necessary for Pulumi and Ansible, but coverage was much stronger for secrets than for system-hardening issues.
- Comparing tools by normalized security domains is more informative than comparing totals alone.

### 3.6 CI/CD Integration Strategy

**Recommended pipeline**

1. **Pre-commit / local developer checks**
   - `tfsec` on changed Terraform files
   - `checkov` on changed Terraform directories
   - `kics` on changed Pulumi and Ansible files

2. **Pull request gate**
   - Block merge on:
     - public exposure findings
     - wildcard IAM permissions
     - hardcoded secrets
     - encryption disabled on persistent storage

3. **Nightly full scan**
   - Run all scanners on the entire repo
   - Keep JSON/HTML artifacts for comparison and trend analysis

4. **Policy stage**
   - Add custom OPA/Conftest policies for organization-specific requirements such as:
     - mandatory tags
     - required KMS keys
     - approved regions only
     - banned CIDR ranges

**Justification**

This staged approach keeps PR feedback fast while still preserving deeper nightly governance checks. It also avoids relying on a single scanner for all IaC types.

---

## Acceptance Criteria Check

**Satisfied in the current workspace**

- [x] Branch `feature/lab6` exists
- [x] Terraform scanned with tfsec, Checkov, and Terrascan
- [x] Pulumi scanned with KICS
- [x] Ansible playbooks scanned with KICS
- [x] Comparative analysis completed with tool evaluation matrices
- [x] `labs/submission6.md` now contains required Task 1-3 analysis

**Not yet satisfied from the current repo state**

- [ ] All scan results and analysis outputs are committed
- [ ] PR from `feature/lab6` to the course repo main branch is open
- [ ] PR link submitted via Moodle

**Current git state during this check**

- Current branch: `feature/lab6`
- `labs/lab6/analysis/` is still untracked

To fully satisfy the submission requirements, the next git steps should be:

```bash
git add labs/submission6.md labs/lab6/analysis/
git commit -m "docs: add lab6 submission - IaC security scanning and comparative analysis"
git push -u origin feature/lab6
```

After that, open the PR and submit the PR URL in Moodle.
