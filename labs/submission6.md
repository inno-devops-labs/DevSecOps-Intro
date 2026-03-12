# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Executive Summary
I scanned the intentionally vulnerable IaC codebase using tfsec, Checkov, Terrascan (Terraform) and KICS (Pulumi + Ansible). The results show a large number of critical/high misconfigurations in Terraform (public network exposure, missing encryption, and overly permissive IAM), fewer but severe findings in Pulumi YAML, and high-severity secrets issues in Ansible playbooks. The strongest coverage for Terraform came from Checkov (breadth) and tfsec (precision), while KICS provided the only first-class Pulumi and Ansible coverage. The most critical risks are public RDS exposure, open security groups, public S3 access, wildcard IAM policies, and hardcoded secrets.

## Environment & Evidence Sources
Scan outputs are stored in `labs/lab6/analysis/`.

Files used as evidence:
- `tfsec-results.json`, `tfsec-report.txt`
- `checkov-terraform-results.json`, `checkov-terraform-report.txt`
- `terrascan-results.json`, `terrascan-report.txt`
- `kics-pulumi-results.json`, `kics-pulumi-report.html`, `kics-pulumi-report.txt`
- `kics-ansible-results.json`, `kics-ansible-report.html`, `kics-ansible-report.txt`
- `tool-comparison.txt`, `terraform-comparison.txt`, `pulumi-analysis.txt`, `ansible-analysis.txt`

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Tool Comparison
- tfsec: 53 findings (CRITICAL 9, HIGH 25, MEDIUM 11, LOW 8)
- Checkov: 78 failed checks
- Terrascan: 22 violated policies (HIGH 14, MEDIUM 8)

Effectiveness summary:
- **Checkov:** best breadth and governance coverage (encryption, backups, logging, monitoring, tagging).
- **tfsec:** best precision and Terraform-native checks (public S3, SG exposure, IAM wildcards) with low noise.
- **Terrascan:** strongest compliance-style findings and high-severity exposure rules with fewer total results.

Key evidence examples:
- tfsec CRITICAL: `aws-ec2-no-public-egress-sgr` in `security_groups.tf` (public egress) and HIGH: `aws-s3-block-public-acls` in `main.tf`.
- Checkov: `CKV_AWS_41` (hardcoded AWS access key/secret in provider), `CKV_AWS_17` (RDS publicly accessible), `CKV_AWS_16` (RDS encryption missing).
- Terrascan: `AC_AWS_0496` (S3 public ACL + public access block), `AC_AWS_0253` (open MySQL 3306), `AC_AWS_0058` (RDS encryption missing).

Evidence snippets (extracted from JSON outputs):
```text
tfsec: rule_id=AVD-AWS-0104, long_id=aws-ec2-no-public-egress-sgr, severity=CRITICAL, file=/src/security_groups.tf
checkov: check_id=CKV_AWS_41, check_name=Ensure no hard coded AWS access key and secret key exists in provider, file=/main.tf
kics: query_name=RDS DB Instance Publicly Accessible, severity=CRITICAL, file=Pulumi-vulnerable.yaml
```

### Pulumi Security Analysis
- Total findings: 6
- Severity: CRITICAL 1, HIGH 2, MEDIUM 1, INFO 2

Key evidence examples:
- `RDS DB Instance Publicly Accessible` (CRITICAL)
- `DynamoDB Table Not Encrypted` (HIGH)
- `Passwords And Secrets - Generic Password` (HIGH)
- `EC2 Instance Monitoring Disabled` (MEDIUM)

### Terraform vs. Pulumi
- **Overlap:** Both Terraform and Pulumi have the same core risks (public S3, open security groups, unencrypted databases, wildcard IAM, hardcoded secrets). This shows these misconfigurations are tool-agnostic and must be enforced by policy.
- **Depth:** Terraform tools surfaced many more checks (53/78/22) across encryption, logging, backups, monitoring, and IAM. Pulumi YAML (KICS) produced fewer findings (6), but they include a CRITICAL public RDS exposure, indicating that fewer findings do not mean lower risk.
- **Format impact:** HCL is declarative and gets broad tool coverage. Pulumi YAML is declarative but has a smaller query catalog today; Pulumi Python would be harder for static scanners than YAML, so YAML scanning is the best current option.

### KICS Pulumi Support
KICS correctly detected Pulumi YAML resources and matched critical AWS queries (public RDS, unencrypted DynamoDB, secrets, EC2 monitoring). Its Pulumi coverage is strong for core AWS services but smaller in total findings than Terraform tools. This makes KICS the correct choice for Pulumi YAML scanning, but it should be paired with additional controls (policy-as-code or runtime guardrails) in production.

### Critical Findings
At least five significant issues confirmed by Terraform and Pulumi scans:
1. **Publicly accessible RDS** (Terraform `database.tf`, Pulumi `Pulumi-vulnerable.yaml`) — direct DB exposure.
2. **Public S3 access / public ACLs** (Terraform `main.tf`) — data exposure risk.
3. **Open security groups to 0.0.0.0/0** (Terraform `security_groups.tf`, Pulumi security groups) — remote attack surface.
4. **Unencrypted databases (RDS/DynamoDB)** (Terraform `database.tf`, Pulumi DynamoDB) — data-at-rest exposure.
5. **Wildcard IAM policies** (Terraform `iam.tf`, Pulumi IAM policy) — privilege escalation risk.
6. **Hardcoded credentials/secrets** (Terraform provider, Pulumi variables) — credential leakage.

### Tool Strengths
- **tfsec:** Strong at Terraform-native misconfigurations with low false positives.
- **Checkov:** Best overall coverage and policy breadth across governance controls.
- **Terrascan:** Best for compliance-style controls and high-severity exposure checks.
- **KICS (Pulumi):** First-class Pulumi YAML support and strong detection for public RDS, unencrypted DynamoDB, and secrets.

## Task 2 — Ansible Security Scanning with KICS

### Ansible Security Issues
- Total findings: 10
- Severity: HIGH 9, LOW 1

Key evidence examples:
- `Passwords And Secrets - Generic Password` (HIGH) found in `deploy.yml`, `configure.yml`, and `inventory.ini`
- `Passwords And Secrets - Password in URL` (HIGH) for repository URL in `deploy.yml`
- `Unpinned Package Version` (LOW) for package installs in `deploy.yml`

### Best Practice Violations
1. **Hardcoded secrets in playbooks and inventory.** Impact: credential exposure in repo history, logs, and CI artifacts.
2. **Missing `no_log: true` for sensitive tasks.** Impact: passwords appear in task output and logs, leaking secrets to operators or CI systems.
3. **Overly permissive file permissions (e.g., `0777` for config files).** Impact: local privilege escalation and secret disclosure on hosts.
4. **Insecure command execution and downloads (e.g., `curl http://... | bash`).** Impact: remote code execution and supply-chain compromise.

### KICS Ansible Queries
KICS focuses heavily on secrets management and insecure operational patterns for Ansible. In this run it flagged generic passwords/secrets, credentials in URLs, and weak package pinning. This aligns with real-world Ansible risks where secrets leak via playbooks, logs, or inventory files. The query set is strong for detecting secret exposure and basic hygiene, but does not deeply analyze runtime privilege escalation logic beyond the available patterns.

### Remediation Steps
- Use Ansible Vault for all secrets and reference vaulted vars.
- Add `no_log: true` to tasks handling secrets.
- Replace `shell`/`command` with Ansible modules where possible.
- Enforce secure permissions (e.g., `0600` for keys, `0640` for secrets).
- Use HTTPS and checksum validation for downloads.

## Task 3 — Comparative Tool Analysis & Security Insights

### Tool Comparison Matrix
| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (Pulumi + Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Medium |
| **False Positives** | Low | Medium | Low/Medium | Medium |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Multiple | Multiple | Multiple |
| **Output Formats** | JSON, text, SARIF | JSON, CLI, SARIF, JUnit | JSON, human | JSON, HTML, SARIF |
| **CI/CD Integration** | Easy | Easy | Medium | Medium |
| **Unique Strengths** | Fast + low noise | Large policy catalog | Compliance mapping | Pulumi + Ansible support |

### Category Analysis
| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|----------|
| **Encryption Issues** | 7 | 4 | 2 | 1 | 0 | tfsec |
| **Network Security** | 16 | 15 | 5 | 1 | 0 | tfsec |
| **Secrets Management** | 0 | 3 | 1 | 1 | 9 | KICS (Ansible) |
| **IAM/Permissions** | 14 | 25 | 3 | 0 | 0 | Checkov |
| **Access Control** | 9 | 5 | 1 | 0 | 0 | tfsec |
| **Compliance/Best Practices** | 7 | 26 | 10 | 3 | 1 | Checkov |

### Top 5 Critical Findings

1. **Publicly accessible RDS instances**  
   Evidence: KICS `RDS DB Instance Publicly Accessible` (CRITICAL) and Checkov `CKV_AWS_17`.  
   Risk: direct internet exposure of databases.

   Remediation (Terraform):
     ```hcl
     resource "aws_db_instance" "secure_db" {
       identifier           = "mydb-secure"
       engine               = "postgres"
       instance_class       = "db.t3.micro"
       storage_encrypted    = true
       publicly_accessible  = false
       backup_retention_period = 7
       deletion_protection  = true
     }
     ```
   Remediation (Pulumi YAML):
     ```yaml
     resources:
       secureDb:
         type: aws:rds:Instance
         properties:
           storageEncrypted: true
           publiclyAccessible: false
           backupRetentionPeriod: 7
           deletionProtection: true
     ```

2. **Public S3 bucket / public access block disabled**  
   Evidence: tfsec `aws-s3-block-public-acls`, `aws-s3-block-public-policy`, and Terrascan `AC_AWS_0496`.  
   Risk: data exfiltration and accidental public disclosure.

   Remediation (Terraform):
     ```hcl
     resource "aws_s3_bucket" "private_data" {
       bucket = "my-private-bucket"
       acl    = "private"
       server_side_encryption_configuration {
         rule {
           apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
         }
       }
       versioning { enabled = true }
     }

     resource "aws_s3_bucket_public_access_block" "private" {
       bucket = aws_s3_bucket.private_data.id
       block_public_acls       = true
       block_public_policy     = true
       ignore_public_acls      = true
       restrict_public_buckets = true
     }
     ```

3. **Open security groups to 0.0.0.0/0**  
   Evidence: tfsec `aws-ec2-no-public-egress-sgr` (CRITICAL) and Terrascan `AC_AWS_0253` (MySQL 3306 open).  
   Risk: external scanning and exploitation of exposed services.

   Remediation (Terraform):
     ```hcl
     resource "aws_security_group" "app_sg" {
       ingress {
         from_port   = 22
         to_port     = 22
         protocol    = "tcp"
         cidr_blocks = ["10.0.0.0/16"]
       }
       egress {
         from_port   = 0
         to_port     = 0
         protocol    = "-1"
         cidr_blocks = ["10.0.0.0/16"]
       }
     }
     ```

4. **Wildcard IAM permissions**  
   Evidence: tfsec `aws-iam-no-policy-wildcards` and Checkov `CKV_AWS_287`.  
   Risk: privilege escalation and full account compromise.

   Remediation (Terraform):
     ```hcl
     resource "aws_iam_policy" "least_priv" {
       policy = jsonencode({
         Version = "2012-10-17"
         Statement = [{
           Effect   = "Allow"
           Action   = ["s3:GetObject", "s3:PutObject"]
           Resource = ["arn:aws:s3:::my-private-bucket/*"]
         }]
       })
     }
     ```

5. **Hardcoded credentials and secrets**  
   Evidence: Checkov `CKV_AWS_41` (Terraform provider credentials) and KICS `Passwords And Secrets - Generic Password` (Pulumi/Ansible).  
   Risk: credential leakage in source control and CI logs.

   Remediation (Ansible example):
     ```yaml
     - name: Set database password safely
       command: mysql -u root -p"{{ db_password }}" -e "CREATE DATABASE myapp;"
       no_log: true

     # Store db_password in Ansible Vault instead of plain text.
     ```

### Tool Selection Guide
- **Terraform-only repos:** tfsec + Checkov. Add Terrascan if compliance mapping is required.
- **Mixed IaC (Terraform + Ansible):** Checkov + KICS. tfsec remains useful for fast pre-commit checks.
- **Pulumi YAML:** KICS is required for first-class coverage; pair with policy-as-code (OPA/Conftest) for organization-specific rules.

### Lessons Learned
- Multiple scanners are required to maximize coverage; each tool surfaces different classes of issues.
- Terraform tooling ecosystem is more mature and yields richer findings than Pulumi YAML today.
- KICS provides essential coverage for Ansible and Pulumi, especially for secrets detection.
- Policy enforcement should be automated early (pre-commit and PR) to prevent insecure IaC from reaching production.

### CI/CD Integration Strategy
1. **Pre-commit / local:** tfsec (fast Terraform lint) + KICS (quick secrets scan for Pulumi/Ansible).
2. **Pull Request stage:** Checkov (broad policy set) + Terrascan (compliance-focused).
3. **Main branch / nightly:** full scans with all tools, plus SARIF upload to code scanning dashboards.
4. **Gating:** fail on CRITICAL/HIGH in protected branches; allow MEDIUM/LOW with ticket creation and SLA.

### Justification
The tool choices above balance breadth and precision. tfsec provides fast, low-noise Terraform checks, Checkov contributes a large policy catalog and multi-framework coverage, Terrascan adds compliance-focused rules, and KICS is essential for Pulumi YAML and Ansible scanning where other tools lack first-class support.
