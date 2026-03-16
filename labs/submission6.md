# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Scope

This lab analyzes intentionally vulnerable Infrastructure-as-Code in:
- Terraform
- Pulumi
- Ansible

Tools used:
- tfsec
- Checkov
- Terrascan
- KICS

---

# Task 1 — Terraform & Pulumi Security Scanning

## Terraform Tool Comparison

Terraform was scanned with three tools.

| Tool | Findings |
|-----|------|
| tfsec | 53 |
| Checkov | 78 |
| Terrascan | 22 |

Observations:

- **tfsec** performs fast Terraform-specific checks with low configuration overhead.
- **Checkov** detects the largest number of issues due to its large policy library.
- **Terrascan** focuses more on compliance-style policy validation.

Checkov detected the highest number of misconfigurations due to its extensive ruleset.

---

## Pulumi Security Analysis

Pulumi infrastructure was scanned using **KICS**.

Results:

| Severity | Findings |
|--------|--------|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Info | 2 |
| **Total** | **6** |

Example vulnerabilities detected:

1. Public RDS database instance  
2. DynamoDB table without encryption  
3. Hardcoded password in configuration  
4. EC2 monitoring disabled  
5. DynamoDB point-in-time recovery disabled

These findings show common infrastructure misconfiguration issues such as missing encryption, exposed resources, and insecure credentials.

---

## Terraform vs Pulumi

Both Terraform and Pulumi configurations contained similar security risks:

- publicly accessible cloud resources
- missing encryption
- weak network restrictions
- insecure credentials

Terraform scanning tools provided deeper HCL-specific analysis, while KICS provided unified scanning across multiple IaC frameworks.

---

## Critical Findings

Top 5 critical infrastructure security problems identified:

1. Public RDS database instance
2. Public S3 bucket exposure
3. Security groups allowing `0.0.0.0/0`
4. Unencrypted storage resources
5. Hardcoded credentials

Recommended remediation:

- enable encryption for storage and databases
- restrict network access
- remove hardcoded secrets
- enforce least-privilege IAM policies

---

# Task 2 — Ansible Security Scanning

Ansible playbooks were scanned using **KICS**.

Results:

| Severity | Findings |
|--------|--------|
| High | 9 |
| Medium | 0 |
| Low | 1 |
| **Total** | **10** |

Common security issues detected:

- hardcoded credentials
- insecure command execution
- missing log protection for sensitive operations

Best practice violations:

1. Hardcoded passwords in configuration
2. Missing `no_log: true` in sensitive tasks
3. Insecure shell command usage

Remediation:

- store secrets using **Ansible Vault**
- protect sensitive tasks with `no_log`
- use Ansible modules instead of raw shell commands

---

# Task 3 — Comparative Tool Analysis

## Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| Total Findings | 53 | 78 | 22 | 16 |
| Scan Speed | Fast | Medium | Medium | Medium |
| Ease of Use | Easy | Easy | Medium | Medium |
| Documentation | Good | Excellent | Good | Good |
| Platform Support | Terraform | Multi-IaC | Multi-IaC | Multi-IaC |
| CI/CD Integration | Easy | Easy | Medium | Easy |

---

## Category Analysis

| Security Category | Best Tool |
|------------------|-----------|
| Encryption issues | Checkov |
| Network security | tfsec |
| Secrets detection | KICS |
| IAM / permissions | Checkov |
| Compliance checks | Terrascan |

---

## Lessons Learned

Running multiple IaC security scanners improves coverage and reduces blind spots.  

Terraform-specific tools provide deep infrastructure validation, while multi-framework scanners such as KICS enable consistent security checks across Pulumi and Ansible configurations.

---

## CI/CD Integration Strategy

Recommended pipeline:

1. **PR checks** — tfsec + Checkov  
2. **Nightly scans** — Terrascan compliance validation  
3. **Multi-IaC scanning** — KICS for Pulumi and Ansible  

This layered approach provides fast feedback and comprehensive infrastructure security validation.
