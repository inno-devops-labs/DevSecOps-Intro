# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Overview

This lab analyzed intentionally vulnerable Infrastructure-as-Code (IaC) configurations using several security scanning tools. The goal was to identify security misconfigurations across Terraform, Pulumi, and Ansible infrastructure definitions and evaluate the effectiveness of different scanning tools.

Tools used:
- tfsec
- Checkov
- Terrascan
- KICS (Checkmarx)

---

# Task 1 — Terraform & Pulumi Security Scanning

## Terraform Tool Comparison

| Tool | Findings |
|-----|-----|
| tfsec | 53 |
| Checkov | 78 |
| Terrascan | 22 |

### Observations

**Checkov** detected the highest number of issues (78), which suggests it has the broadest policy set among the tested Terraform scanners.

**tfsec** detected 53 issues and produced concise, Terraform‑focused findings with relatively low noise. It appears optimized specifically for Terraform security best practices.

**Terrascan** detected 22 issues, significantly fewer than the other tools. However, Terrascan focuses heavily on compliance and policy-based scanning rather than pure vulnerability enumeration.

### Tool Strengths

**tfsec**
- Very fast scanning
- Terraform‑specific rule set
- Clear and readable reports
- Low false positive rate

**Checkov**
- Largest number of security policies
- Supports multiple IaC frameworks
- Deep security checks including IAM, encryption, and compliance rules

**Terrascan**
- Uses OPA policy engine
- Strong compliance mapping
- Good for organizational policy enforcement

---

## Pulumi Security Analysis (KICS)

Pulumi infrastructure was scanned using **KICS**, which supports Pulumi YAML manifests.

### Scan Results

| Severity | Findings |
|--------|--------|
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| **Total** | **6** |

### Observed Issues

Typical issues detected include:

- Public cloud storage resources
- Open network access configurations
- Missing encryption for storage resources
- Weak infrastructure configuration defaults

### KICS Pulumi Support

KICS successfully detected Pulumi misconfigurations using its IaC query catalog. The scanner was able to automatically detect Pulumi YAML manifests and apply cloud security policies without requiring manual configuration.

Advantages:

- Native Pulumi YAML detection
- Multi‑cloud rule support
- JSON and HTML reporting formats
- Large open‑source query catalog

---

## Terraform vs Pulumi Security Issues

Both Terraform and Pulumi infrastructure definitions suffered from similar classes of security issues:

Common issues across both platforms:

- Publicly accessible resources
- Missing encryption for storage and databases
- Overly permissive network rules
- Weak identity and access management policies

Differences:

Terraform configurations typically exposed more issues because:

- The Terraform configuration contained more resources
- Terraform scanners have mature rule sets
- Multiple scanning tools were used

Pulumi findings were fewer due to scanning with only one tool (KICS) and a smaller configuration set.

---

## Critical Security Findings

### 1. Public S3 Buckets

**Issue:** Storage buckets configured for public access.

**Risk:** Sensitive data exposure and potential data leakage.

**Remediation:**

Example Terraform fix:

```hcl
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.example.id

  block_public_acls   = true
  block_public_policy = true
}
```

---

### 2. Unencrypted Databases

**Issue:** Database storage encryption disabled.

**Risk:** Data theft if storage media is compromised.

**Remediation:**

```hcl
resource "aws_db_instance" "db" {
  storage_encrypted = true
}
```

---

### 3. Security Groups Allowing 0.0.0.0/0

**Issue:** Security groups allow unrestricted inbound access.

**Risk:** Attackers can access exposed services from the internet.

**Remediation:**

Restrict access to specific CIDR blocks.

```hcl
cidr_blocks = ["10.0.0.0/16"]
```

---

### 4. Overly Permissive IAM Policies

**Issue:** IAM policies granting wildcard permissions.

**Risk:** Privilege escalation and unauthorized actions.

**Remediation:**

Replace:

```json
"Action": "*"
```

With least‑privilege permissions.

---

### 5. Hardcoded Credentials

**Issue:** Credentials embedded directly in configuration files.

**Risk:** Secret leakage through source control.

**Remediation:**

Use secret management systems:

- AWS Secrets Manager
- Parameter Store
- Environment variables

---

# Task 2 — Ansible Security Scanning (KICS)

## Scan Results

| Severity | Findings |
|--------|--------|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| **Total** | **10** |

### Key Security Issues

#### 1. Hardcoded Secrets

Passwords and credentials stored directly inside playbooks or inventory files.

**Impact:** Credentials can be leaked through version control.

**Fix:** Use **Ansible Vault** for encrypted secrets.

```
ansible-vault encrypt vars.yml
```

---

#### 2. Missing `no_log` on Sensitive Tasks

Tasks handling credentials did not use `no_log: true`.

**Impact:** Secrets may appear in logs.

**Fix:**

```yaml
- name: Configure database
  command: setup_db
  no_log: true
```

---

#### 3. Insecure Command Execution

Use of `shell` or `command` modules where specialized Ansible modules should be used.

**Impact:** Potential command injection and lower idempotency.

**Fix:** Use official modules whenever possible.

---

### KICS Ansible Query Capabilities

KICS performs checks in several areas:

- Secrets detection
- Command execution risks
- File permissions
- Authentication issues
- Security misconfigurations

This makes KICS useful as a unified scanner for configuration management systems.

---

# Task 3 — Comparative Tool Analysis

## Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|------|------|------|------|
| Total Findings | 53 | 78 | 22 | 16 |
| Scan Speed | Fast | Medium | Medium | Medium |
| False Positives | Low | Medium | Low | Medium |
| Report Quality | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Ease of Use | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Documentation | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Platform Support | Terraform | Multi‑IaC | Multi‑IaC | Multi‑IaC |
| Output Formats | JSON, SARIF, text | JSON, CLI, SARIF | JSON, human | JSON, HTML |
| CI/CD Integration | Easy | Easy | Medium | Easy |
| Unique Strengths | Fast Terraform scanning | Largest rule set | Compliance policies | Pulumi & Ansible support |

---

# Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|------|------|------|------|------|------|
| Encryption Issues | ✓ | ✓ | ✓ | ✓ | N/A | Checkov |
| Network Security | ✓ | ✓ | ✓ | ✓ | ✓ | tfsec |
| Secrets Management | ✓ | ✓ | ✗ | ✓ | ✓ | KICS |
| IAM / Permissions | ✓ | ✓ | ✓ | ✓ | ✗ | Checkov |
| Access Control | ✓ | ✓ | ✓ | ✓ | ✓ | Checkov |
| Compliance / Best Practices | ✓ | ✓ | ✓ | ✓ | ✓ | Terrascan |

---

# Tool Selection Guide

### Use tfsec when

- Fast Terraform scans are required
- Running security checks in pre‑commit hooks
- Developers need quick feedback

### Use Checkov when

- Multi‑cloud and multi‑framework scanning is required
- Comprehensive rule coverage is desired
- Security and compliance policies must be enforced

### Use Terrascan when

- Policy-as-code enforcement is required
- Compliance frameworks (PCI, HIPAA, etc.) must be validated

### Use KICS when

- Scanning Pulumi and Ansible
- A single scanner for multiple IaC frameworks is needed
- Detailed IaC query catalog is required

---

# CI/CD Integration Strategy

A practical DevSecOps pipeline may include:

1. **Pre‑commit stage**
   - Run tfsec locally to detect Terraform issues quickly.

2. **CI pipeline security stage**
   - Run Checkov and Terrascan for comprehensive IaC scanning.

3. **Configuration management scanning**
   - Run KICS for Pulumi and Ansible validation.

4. **Reporting stage**
   - Export SARIF/JSON results to security dashboards.

This layered approach ensures early detection and strong coverage.

---

# Lessons Learned

Several important insights emerged during the lab:

- No single tool detects all security issues.
- Running multiple scanners significantly improves detection coverage.
- Tools vary in focus: some emphasize speed (tfsec), others completeness (Checkov).
- KICS provides strong multi‑framework support but produced fewer findings for Pulumi due to smaller configuration size.
- Security scanning should be integrated early in development to prevent insecure infrastructure deployment.

---

# Conclusion

This lab demonstrated the importance of Infrastructure‑as‑Code security scanning in modern DevSecOps pipelines.

Key takeaways:

- Terraform scanners such as tfsec and Checkov are highly effective for detecting infrastructure misconfigurations.
- KICS provides valuable cross‑framework scanning capabilities for Pulumi and Ansible.
- Combining multiple security scanners leads to significantly improved vulnerability detection coverage.
- Automated scanning integrated into CI/CD pipelines is essential for maintaining secure cloud infrastructure.
