# Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Terraform & Pulumi Security Scanning

### Terraform Tool Comparison

The vulnerable Terraform code was scanned with three different tools. The number of findings reported by each tool is summarised below:

| Tool | Findings Count |
|------------|----------|
| tfsec | 53 |
| Checkov | 78 |
| Terrascan | 22 |

**Observations:**
- **tfsec** detected 53 issues, focusing mainly on infrastructure misconfiguration (unencrypted S3 buckets, overly permissive security groups, etc).
- **Checkov** covered a wider range of policy checks, including missing backup policies, logging configurations, IAM privilege escalation, and encryption settings. It also flagged issues that tfsec missed (e.g., DynamoDB point‑in‑time recovery, RDS deletion protection).
- **Terrascan** focused on compliance‑oriented rules and produced fewer false positives, but also missed some of the more detailed IAM checks.

**Effectiveness:**
- **tfsec** is fast, has low false positives, and is excellent for quick CI/CD integration.
- **Checkov** is highly configurable, making it suitable for deep security audits.
- **Terrascan** is valuable when compliance mapping is required, but may need to be complemented by another tool for broader coverage.

### Pulumi Security Analysis (KICS)

KICS (Checkmarx) was used to scan the Pulumi code (both YAML and Python). The results are summarised below:

| Severity | Count |
|------------|-----|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **TOTAL** | **6** |

| Severity | Issue | File | Remediation |
|------------|-----|--------------------------|-------------|
| CRITICAL | RDS DB instance publicly accessible (`publiclyAccessible = true`) | `Pulumi-vulnerable.yaml` | Set `publiclyAccessible = false` |
| HIGH | DynamoDB table not encrypted at rest (no `serverSideEncryption`) | `Pulumi-vulnerable.yaml` | Enable server‑side encryption with a KMS key |
| HIGH | Hardcoded secret (generic password) | `Pulumi-vulnerable.yaml` | Use a secure secret store (e.g., AWS Secrets Manager) |
| MEDIUM | EC2 instance monitoring disabled (`monitoring` not set to `true`)  | `Pulumi-vulnerable.yaml` | Enable detailed monitoring |
| INFO | DynamoDB point‑in‑time recovery disabled (`pointInTimeRecovery` off) | `Pulumi-vulnerable.yaml` | Enable PITR for data protection |
| INFO | EC2 instance not EBS‑optimised | `Pulumi-vulnerable.yaml` | Set `ebsOptimized = true` |

KICS successfully identified security issues specific to AWS resources defined in Pulumi. Its support for Pulumi YAML is first‑class, and the query catalog covers the most common misconfigurations.

### Terraform vs. Pulumi

- **Terraform** (HCL) issues are predominantly related to resource configuration (e.g., encryption, networking, IAM policies). The three tools (tfsec, Checkov, Terrascan) provide overlapping but complementary checks.
- **Pulumi** (YAML/Python) shows similar classes of problems, however, because Pulumi allows programming logic, it could introduce additional risks (e.g., dynamic generation of security groups), though the scanned examples did not exploit that.
- KICS handled both Pulumi YAML and Python code well, making it a unified choice for organisations using multiple IaC frameworks.

## Ansible Security Scanning with KICS

### Ansible Security Issues

KICS detected **10** security issues in the Ansible playbooks, distributed as follows:

| Severity   | Count |
|------------|-------|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| **TOTAL**  | **10**|

The findings fall into two main categories:

- **Secrets management** (9 HIGH): hardcoded passwords, secret keys, and passwords embedded in URLs.
- **Supply‑chain / best practices** (1 LOW): use of `state: latest` in package installation (unpinned version).

| File | Line | Issue | Remediation |
|------|------|-------|-------------|
| `inventory.ini`  | 5,10,18,19 | Hardcoded password / secret in plain text | Use Ansible Vault or environment variables |
| `deploy.yml` | 12 | Hardcoded password in task | Ansible Vault |
| `deploy.yml` | 16,72| Password in URL (e.g., `https://user:pass@host`) | Remove credentials from URLs |
| `configure.yml` | 16 | Hardcoded secret | Ansible Vault |
| `deploy.yml`| 99 | Package version not pinned (`state: latest`) | Pin to a specific version |

### Best Practice Violations and Remediation

1. **Hardcoded credentials** – sensitive data is directly embedded in playbooks and inventory files.  
   *Fix:* Use Ansible Vault (`ansible-vault encrypt`) to encrypt secret variables, and reference them via `{{ vault_var }}`. Alternatively, retrieve secrets from a secrets manager (HashiCorp Vault, AWS Secrets Manager) during runtime.

2. **Password in URL** – credentials appear in a URL string, which could be exposed in logs or version control.  
   *Fix:* Never include credentials in URLs; use secure authentication mechanisms (e.g., API tokens passed via headers, SSH keys).

3. **Unpinned package versions** – using `state: latest` can lead to unexpected updates and potential breakage or introduction of vulnerable versions.  
   *Fix:* Specify exact version numbers (e.g., `version: '1.2.3'`) or use a version lock file.

4. **Missing `no_log`** (not detected by KICS in this run, but a common issue) – tasks that output sensitive data should have `no_log: true` to prevent secrets from appearing in logs.


## Comparative Tool Analysis & Security Insights

### Comprehensive Tool Comparison Matrix

| Criterion                | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) |
|--------------------------|-------|---------|-----------|---------------|----------------|
| **Total Findings**       | 53    | 78      | 22        | 6             | 10             |
| **Scan Speed**           | Fast  | Medium  | Medium    | Medium        | Medium         |
| **False Positives**      | Low   | Medium  | Low       | Low           | Low            |
| **Report Quality (1-5)** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐  | ⭐⭐⭐      | ⭐⭐⭐⭐        | ⭐⭐⭐⭐         |
| **Ease of Use**          | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐  | ⭐⭐⭐      | ⭐⭐⭐⭐        | ⭐⭐⭐⭐         |
| **Platform Support**     | Terraform only | Multi (Terraform, CloudFormation, K8s, etc.) | Multi | Pulumi, Ansible, K8s, CloudFormation, Docker | Ansible, plus others |
| **Output Formats**       | JSON, SARIF, JUnit, etc. | JSON, CLI, SARIF, CSV | JSON, YAML, human | JSON, HTML, SARIF, CSV | JSON, HTML, SARIF, CSV |
| **Unique Strengths**     | Speed, simplicity | Broad policy set, custom policies | Compliance mapping (PCI, HIPAA) | First‑class Pulumi support | Comprehensive Ansible queries |

### Category Analysis

Based on the detailed reports, estimated count of findings fall into common security domains:

| Security Category        | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|--------------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption Issues**    | ~8    | ~12     | ~4        | 1 (DynamoDB)  | 0              | Checkov   |
| **Network Security**     | ~12   | ~10     | ~6        | 1 (RDS public)| 0              | tfsec     |
| **Secrets Management**   | ~0    | ~2      | 0         | 1             | 9              | KICS (Ansible) |
| **IAM / Permissions**    | ~15   | ~25     | ~5        | 0             | 0              | Checkov   |
| **Logging & Monitoring** | ~2    | ~8      | ~2        | 1 (EC2 monitoring) | 0          | Checkov   |
| **Best Practices**       | ~16   | ~21     | ~5        | 2 (PITR, EBS) | 1 (unpinned)   | Checkov   |


### Top 5 Critical Findings

| # | Tool(s)   | Resource / File          | Issue                                                                 | Impact                                                                 | Remediation |
|---|-----------|--------------------------|-----------------------------------------------------------------------|------------------------------------------------------------------------|-------------|
| 1 | Checkov, tfsec, Terrascan, KICS Pulumi | `aws_db_instance.unencrypted_db` (Terraform) / `Pulumi-vulnerable.yaml` (Pulumi) | RDS instance publicly accessible and not encrypted at rest. | Direct exposure of database to the internet; data at rest can be read if breached. | Set `publicly_accessible = false` and `storage_encrypted = true`. |
| 2 | Checkov, tfsec | `aws_iam_policy.admin_policy` (Terraform) | IAM policy with `Action: "*"` and `Resource: "*"`. | Complete administrative access – any user/role with this policy can perform any AWS action. | Restrict actions and resources to the minimum required. |
| 3 | tfsec, Checkov | `aws_s3_bucket.public_data` (Terraform) | S3 bucket with public ACL (`public-read`). | Anyone on the internet can list/read objects in the bucket, leading to data leakage. | Remove the public ACL and enable public access block. |
| 4 | KICS Ansible | `inventory.ini`, `deploy.yml`, `configure.yml` | Hardcoded passwords and secrets in plain text. | Credentials can be stolen by anyone with access to the repository or playbook files. | Use Ansible Vault or a secrets manager. |
| 5 | Checkov, tfsec | `aws_s3_bucket.unencrypted_data` (Terraform) | S3 bucket without server‑side encryption. | Data at rest is not encrypted; if the bucket is compromised, data is exposed. | Enable default encryption (SSE‑S3 or KMS). |

### Tool Selection Guide

- **Use tfsec** for fast, Terraform‑only scans in early CI stages (e.g., pre‑commit, pull request checks). It is excellent for catching low‑hanging fruit like open security groups and unencrypted resources.
- **Use Checkov** for comprehensive multi‑framework scanning and when you need to enforce organisational policies. Its extensive rule set and custom policy support make it a strong candidate for a central security gate.
- **Use Terrascan** when compliance with standards (PCI‑DSS, HIPAA, CIS) is a primary requirement. Its OPA‑based engine allows fine‑grained control, but it may need to be supplemented by other tools for full coverage.
- **Use KICS** for Pulumi and Ansible, and as a unified scanner that also covers Kubernetes, Docker, and CloudFormation. It is particularly strong at detecting secrets and best‑practice violations in configuration management code.

### Insights about tool effectiveness

- **No single tool catches everything.** The overlap in findings across tools is often limited – for example, tfsec, Checkov, and Terrascan each missed issues that the others found. Combining multiple scanners gives the best coverage.
- **False positives are common**, especially in tools with very broad rule sets. Teams must invest time in tuning (ignoring irrelevant rules, adjusting thresholds) to avoid alert fatigue. Checkov, with its extensive policy set, produced the most false positives, while tfsec and Terrascan were cleaner.
- **KICS proves to be a powerful unified scanner** for non‑Terraform IaC, handling both Pulumi and Ansible well. Its detection of hardcoded secrets is particularly valuable, and its support for Pulumi YAML is mature.
- **Severity matters.** Critical issues like publicly accessible databases or wildcard IAM policies require immediate fixes, while informational or low‑severity findings can be addressed gradually. The top‑5 list highlights the most urgent problems.
- **Integration strategy should be layered.** Fast tools (tfsec) catch obvious mistakes early, while comprehensive scanners (Checkov) run in CI to enforce deeper policies. Nightly scans with all tools provide a safety net.

### Justification of Tool Choices

- **tfsec** was chosen for its speed and low false‑positive rate, making it ideal for developer‑focused pre‑commit hooks and rapid feedback loops.
- **Checkov** was selected for its breadth of policies and ability to scan multiple frameworks. Its detailed reports and custom‑policy capability make it the backbone of a central security gate.
- **Terrascan** was included because of its focus on compliance standards. When mapping to frameworks like PCI‑DSS or HIPAA is required, Terrascan’s OPA‑based engine provides precise control.
- **KICS** was used for Pulumi and Ansible because it offers first‑class support for those platforms, unlike the Terraform‑centric tools. Its unified approach reduces toolchain complexity and ensures consistent scanning across all IaC types.

### CI/CD Integration Strategy

A practical multi‑stage pipeline could be:

1. **Developer workstation / pre‑commit hook** – run **tfsec** (for Terraform) and **KICS** (for Pulumi/Ansible) to provide immediate feedback on obvious mistakes.
2. **Pull request pipeline** – run **Checkov** and **Terrascan** on all changed IaC files, fail the build on high‑ or critical‑severity findings.
3. **Nightly deep scan** – run all tools with full rule sets, generate reports (JSON/HTML), and store them for audit purposes. This helps catch issues that might have been missed earlier and provides a historical baseline.