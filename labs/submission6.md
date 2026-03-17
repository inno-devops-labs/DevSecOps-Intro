# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

**Date:** March 17, 2026  
**Branch:** `feature/lab6`

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Tool Comparison (tfsec vs Checkov vs Terrascan)

Terraform target: `labs/lab6/vulnerable-iac/terraform/`

- `tfsec`: **53** findings (`CRITICAL: 9`, `HIGH: 25`, `MEDIUM: 11`, `LOW: 8`)
- `Checkov`: **78** failed checks (`48` passed)
- `Terrascan`: **22** violated policies (`HIGH: 14`, `MEDIUM: 8`)

Why counts differ:
- `Checkov` has broader policy breadth and emits many granular IAM/compliance checks.
- `tfsec` is Terraform-focused and produced high signal on network exposure and AWS misconfigurations.
- `Terrascan` reported fewer findings but mapped well to policy/compliance-oriented controls.

### Pulumi Security Analysis (KICS)

Pulumi target: `labs/lab6/vulnerable-iac/pulumi/Pulumi-vulnerable.yaml`

- `KICS total findings`: **6**
- Severity split: `CRITICAL: 1`, `HIGH: 2`, `MEDIUM: 1`, `INFO: 2`

Key Pulumi findings from KICS:
- `RDS DB Instance Publicly Accessible` (CRITICAL) at `Pulumi-vulnerable.yaml:104`
- `DynamoDB Table Not Encrypted` (HIGH) at `Pulumi-vulnerable.yaml:205`
- `Passwords And Secrets - Generic Password` (HIGH) at `Pulumi-vulnerable.yaml:16`
- `EC2 Instance Monitoring Disabled` (MEDIUM) at `Pulumi-vulnerable.yaml:157`

### Terraform vs Pulumi Security Patterns (HCL vs YAML)

Common issues detected in both:
- Public exposure (`0.0.0.0/0`, public DB access)
- Missing encryption (RDS/DynamoDB/S3 related)
- Secrets in IaC source
- Overly permissive IAM-style permissions

Observed difference:
- Terraform scans produced much higher count density because three scanners were used with overlapping policy sets.
- Pulumi (scanned here with KICS) had lower finding count, but still identified critical cloud misconfiguration and secret-management risks.

### KICS Pulumi Support Evaluation

Strengths observed:
- Correct Pulumi YAML parsing and Pulumi-platform query matching.
- Useful AWS-focused Pulumi checks (RDS public access, DynamoDB encryption, monitoring).
- Practical secret-detection query surfaced hardcoded credentials.

Limitations observed:
- In this lab run, KICS reported fewer findings than Terraform scanners on equivalent risk themes.
- Some Pulumi issues remain outside the active matched query subset, so KICS is best used with complementary controls where possible.

### Critical Findings (at least 5)

1. `main.tf:8-9` hardcoded AWS provider credentials (Checkov `CKV_AWS_41`).
2. `security_groups.tf:15/41/49/75/83` inbound access from `0.0.0.0/0` (tfsec `AVD-AWS-0107`).
3. `database.tf:17` publicly accessible RDS instance (tfsec `AVD-AWS-0082`, Checkov `CKV_AWS_17`).
4. `database.tf:15` disabled storage encryption for RDS (Checkov `CKV_AWS_16`).
5. `iam.tf:14-16` wildcard `Action="*"` and `Resource="*"` IAM policy (Checkov `CKV_AWS_63` / `CKV_AWS_62`).

### Tool Strengths

- `tfsec`: strongest fast feedback for Terraform-specific misconfiguration.
- `Checkov`: strongest policy breadth and multi-domain IaC coverage (especially IAM/compliance style checks).
- `Terrascan`: strongest compliance/policy interpretation with concise violation output.
- `KICS`: strongest unification across non-HCL IaC in this lab (Pulumi YAML + Ansible).

## Task 2 — Ansible Security Scanning with KICS

### Ansible Security Issues (KICS)

Ansible target: `labs/lab6/vulnerable-iac/ansible/`

- `KICS total findings`: **10**
- Severity split: `HIGH: 9`, `LOW: 1`

Most significant Ansible findings:
- Secrets in inventory/playbooks (multiple `Generic Password` / `Generic Secret` findings)
- Credentials in URL (`deploy.yml:16`, `deploy.yml:72`)
- Non-deterministic package install (`state: latest`) at `deploy.yml:99`

### Best Practice Violations and Security Impact

1. Hardcoded secrets in files (`deploy.yml`, `configure.yml`, `inventory.ini`): secrets leak via git history, logs, backups.
2. Credentials embedded in repository URLs (`deploy.yml:72`): token/password disclosure and credential reuse risk.
3. Unpinned package versions (`deploy.yml:99`): non-reproducible deployments and supply-chain drift.

### KICS Ansible Query Coverage

KICS query families seen in this run:
- `Passwords And Secrets - Generic Password` (6 matches)
- `Passwords And Secrets - Generic Secret` (1 match)
- `Passwords And Secrets - Password in URL` (2 matches)
- `Unpinned Package Version` (1 match)

Assessment:
- Very effective for secrets hygiene and credential exposure patterns.
- Basic operational hardening issues are also detected (package pinning), but secrets coverage is the standout.

### Remediation Steps

- Move secrets to Ansible Vault / external secret manager and remove hardcoded credentials from YAML/INI.
- Replace authenticated Git URLs with deploy keys or token injection from CI secrets.
- Pin package versions and explicitly manage upgrade windows.
- Add `no_log: true` to secret-handling tasks and avoid printing sensitive vars in task names/debug.

## Task 3 — Comparative Tool Analysis & Security Insights

### Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|---|---|---|---|---|
| **Total Findings** | 53 | 78 | 22 | 16 (Pulumi 6 + Ansible 10) |
| **Scan Speed** | Fast | Medium | Medium-Slow | Medium |
| **False Positives** | Low | Medium | Medium | Medium |
| **Report Quality** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform-focused | Multi-framework | Multi-framework | Multi-framework (incl. Pulumi/Ansible) |
| **Output Formats** | JSON, text, SARIF | JSON, CLI, SARIF, CycloneDX | JSON, YAML, XML, human | JSON, HTML, SARIF |
| **CI/CD Integration** | Easy | Easy-Medium | Medium | Easy-Medium |
| **Unique Strengths** | Fast Terraform misconfig checks | Broad policy catalog, detailed IAM checks | Compliance-oriented policy mapping | Unified Pulumi + Ansible scanning |

### Vulnerability Category Analysis

Method: keyword-based categorization over scanner result descriptions/check names (approximate, because categories can overlap).

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|---|---:|---:|---:|---:|---:|---|
| **Encryption Issues** | 7 | 4 | 2 | 1 | 0 | tfsec |
| **Network Security** | 11 | 15 | 5 | 0 | 0 | Checkov |
| **Secrets Management** | 0 | 3 | 1 | 1 | 9 | KICS (Ansible) |
| **IAM/Permissions** | 12 | 27 | 6 | 0 | 0 | Checkov |
| **Access Control** | 20 | 16 | 5 | 1 | 0 | tfsec |
| **Compliance/Best Practices** | 9 | 13 | 7 | 1 | 0 | Checkov |

### Top 5 Critical Findings with Remediation Code Examples

1. **Hardcoded AWS credentials** (`terraform/main.tf:8-9`)

```hcl
# Vulnerable
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Remediation
provider "aws" {
  region = var.aws_region
}
# Use IAM role/OIDC/env vars, never commit static keys
```

2. **RDS publicly exposed and unencrypted** (`terraform/database.tf:15-17`)

```hcl
# Vulnerable
storage_encrypted   = false
publicly_accessible = true

# Remediation
storage_encrypted   = true
publicly_accessible = false
kms_key_id          = aws_kms_key.db.arn
```

3. **Security groups open to internet** (`terraform/security_groups.tf:41`, `:49`, `:75`, `:83`)

```hcl
# Vulnerable
cidr_blocks = ["0.0.0.0/0"]

# Remediation
cidr_blocks = [var.allowed_admin_cidr]
# Prefer private SG-to-SG references for DB access
```

4. **Wildcard IAM admin policy** (`terraform/iam.tf:14-16`)

```hcl
# Vulnerable
Action   = "*"
Resource = "*"

# Remediation
Action = [
  "s3:GetObject",
  "s3:PutObject"
]
Resource = [
  "arn:aws:s3:::my-app-bucket/*"
]
```

5. **Ansible secret exposure in playbooks/inventory** (`ansible/deploy.yml:12`, `ansible/inventory.ini:5`)

```yaml
# Vulnerable
vars:
  db_password: "SuperSecret123!"

# Remediation
vars:
  db_password: "{{ vault_db_password }}"

tasks:
  - name: Use DB password safely
    command: /usr/local/bin/configure-db
    no_log: true
```

### Tool Selection Guide

- Use `tfsec` for fast Terraform PR gating.
- Use `Checkov` for broad policy enforcement and deeper IAM/compliance coverage.
- Use `Terrascan` when compliance mapping is a priority.
- Use `KICS` to cover Pulumi and Ansible in one scanner family.
- Use layered scanning (`tfsec + Checkov + KICS`) to reduce blind spots.

### Lessons Learned

- Scanner overlap is real; the same root issue appears as multiple policy violations.
- A higher finding count does not always mean better prioritization quality.
- Secrets management and public exposure remain the highest-impact IaC risks.
- Multi-tool strategy is necessary when codebases use mixed IaC technologies.

### CI/CD Integration Strategy

1. `Pre-commit / PR fast stage`: run `tfsec` for immediate Terraform feedback.
2. `PR policy stage`: run `Checkov` with fail thresholds for high/critical findings.
3. `Framework parity stage`: run `KICS` on Pulumi and Ansible directories.
4. `Nightly compliance stage`: run `Terrascan` and trend violations over time.
5. Publish JSON/HTML artifacts for audit, and block merges on unresolved critical findings.

### Justification of Final Tooling Strategy

Chosen baseline stack:
- `tfsec` for speed and low-friction Terraform checks.
- `Checkov` for broad policy depth and strongest IAM/compliance detection in Terraform.
- `KICS` for Pulumi and Ansible coverage with one consistent workflow.
- `Terrascan` as a compliance-focused supplement.

This combination balances speed, depth, and framework coverage while keeping CI maintainable.

## Evidence Files

- `labs/lab6/analysis/tfsec-results.json`
- `labs/lab6/analysis/tfsec-report.txt`
- `labs/lab6/analysis/checkov-terraform-results.json`
- `labs/lab6/analysis/checkov-terraform-report.txt`
- `labs/lab6/analysis/terrascan-results.json`
- `labs/lab6/analysis/terrascan-report.txt`
- `labs/lab6/analysis/kics-pulumi-results.json`
- `labs/lab6/analysis/kics-pulumi-report.html`
- `labs/lab6/analysis/kics-pulumi-report.txt`
- `labs/lab6/analysis/kics-ansible-results.json`
- `labs/lab6/analysis/kics-ansible-report.html`
- `labs/lab6/analysis/kics-ansible-report.txt`
- `labs/lab6/analysis/terraform-comparison.txt`
- `labs/lab6/analysis/pulumi-analysis.txt`
- `labs/lab6/analysis/ansible-analysis.txt`
- `labs/lab6/analysis/tool-comparison.txt`
