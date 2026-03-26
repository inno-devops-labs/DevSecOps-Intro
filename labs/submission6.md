# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## 1. Terraform Tool Comparison

### Findings Summary
- tfsec: 53 findings (9 critical, 25 high, 11 medium, 8 low)
- Checkov: 78 findings (highest coverage)
- Terrascan: 22 findings (14 high, 8 medium)

### Analysis
Checkov detected the highest number of issues, indicating broader rule coverage and deeper policy checks. It identified multiple categories such as IAM misconfigurations, S3 security issues, RDS vulnerabilities, and hardcoded credentials.

tfsec provided a balanced result with a good severity breakdown and low false positives, making it suitable for fast CI/CD scans.

Terrascan detected fewer issues but focused on high-impact vulnerabilities such as:
- Open security groups
- Unencrypted databases
- Publicly accessible RDS instances

### Strengths
- tfsec: Fast, low noise, Terraform-focused
- Checkov: Comprehensive, multi-framework, detailed policies
- Terrascan: Strong compliance and high-risk issue detection

---

## 2. Pulumi Security Analysis (KICS)

### Findings Summary
- Total: 6 findings
- Critical: 1
- High: 2
- Medium: 1
- Low: 0

### Analysis
KICS successfully detected security issues in Pulumi configurations. The presence of a critical vulnerability indicates serious misconfigurations in infrastructure.

Common issues include:
- Public exposure of resources
- Missing encryption
- Weak configuration defaults

### KICS Strengths for Pulumi
- Native support for Pulumi YAML
- Good severity classification
- Unified scanning across IaC frameworks

---

## 3. Ansible Security Analysis (KICS)

### Findings Summary
- Total: 10 findings
- High: 9
- Medium: 0
- Low: 1

### Key Issues
1. Hardcoded secrets in playbooks
   - Security risk: credential leakage
   - Fix: use Ansible Vault

2. Missing no_log in sensitive tasks
   - Security risk: secrets exposed in logs
   - Fix: add `no_log: true`

3. Insecure configurations and permissions
   - Security risk: unauthorized access
   - Fix: apply least privilege and secure defaults

### KICS Ansible Capabilities
- Detects secrets exposure
- Identifies insecure command usage
- Checks best practice violations

---

## 4. Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|----------|------|---------|-----------|------|
| Total Findings | 53 | 78 | 22 | 16 |
| Scan Speed | Fast | Medium | Medium | Medium |
| False Positives | Low | Medium | Low | Medium |
| Report Quality | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Ease of Use | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Documentation | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Platform Support | Terraform | Multi | Multi | Multi |
| Output Formats | JSON, text | JSON, CLI | JSON, text | JSON, HTML |
| CI/CD Integration | Easy | Easy | Medium | Medium |
| Unique Strength | Speed | Coverage | Compliance | Multi-IaC |

---

## 5. Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|------|---------|-----------|---------------|----------------|----------|
| Encryption Issues | ✔ | ✔✔ | ✔ | ✔ | N/A | Checkov |
| Network Security | ✔✔ | ✔✔ | ✔✔ | ✔ | ✔ | tfsec |
| Secrets Management | ✔ | ✔✔ | ✔ | ✔ | ✔✔ | Checkov |
| IAM/Permissions | ✔ | ✔✔ | ✔ | ✔ | ✔ | Checkov |
| Access Control | ✔ | ✔✔ | ✔ | ✔ | ✔ | Checkov |
| Best Practices | ✔ | ✔✔ | ✔✔ | ✔ | ✔ | Checkov |

---

## 6. Top 5 Critical Findings

### 1. Public S3 Buckets
- Risk: Data exposure
- Fix:
```hcl
block_public_acls   = true
block_public_policy = true
```

### 2. Open Security Groups (0.0.0.0/0)
- Risk: Unauthorized access
- Fix:
```hcl
cidr_blocks = ["10.0.0.0/16"]
```

### 3. Unencrypted RDS Databases
- Risk: Data breach
- Fix:
```hcl
storage_encrypted = true
```

### 4. Hardcoded AWS Credentials
- Risk: Credential leakage
- Fix: Use environment variables or AWS Secrets Manager

### 5. Overly Permissive IAM Policies ("*")
- Risk: Privilege escalation
- Fix: Apply least privilege principle

---

## 7. Tool Selection Guide

- tfsec: Best for fast Terraform scanning in CI/CD
- Checkov: Best for comprehensive multi-framework security analysis
- Terrascan: Best for compliance-focused scanning
- KICS: Best for Pulumi and Ansible unified scanning

---

## 8. CI/CD Integration Strategy

1. Pre-commit: tfsec
2. CI pipeline:
   - Checkov for deep analysis
   - KICS for Pulumi and Ansible
3. Compliance stage: Terrascan

---

## 9. Lessons Learned

- No single tool detects all vulnerabilities
- Combining tools increases coverage
- Checkov provides the most comprehensive results
- tfsec is ideal for fast feedback
- KICS is effective for non-Terraform IaC

---

## 10. Conclusion

This lab demonstrated the importance of using multiple IaC security tools to identify vulnerabilities across different frameworks. A multi-tool approach provides better coverage, reduces risks, and improves overall infrastructure security.
