# Lab 6 Submission — IaC Security Scanning & Comparative Analysis

**Student:** Sarmat  
**Date:** March 15, 2026

---

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Tool Comparison

All three tools scanned the same vulnerable Terraform code in `labs/lab6/vulnerable-iac/terraform/`.

**Results Summary:**

| Tool | Total Findings | Critical | High | Medium | Low |
|------|---------------|----------|------|--------|-----|
| tfsec | 53 | 9 | 25 | 11 | 8 |
| Checkov | 78 | — | — | — | — |
| Terrascan | 22 | — | — | — | — |

**tfsec** found the most actionable findings with clear severity breakdown. **Checkov** had the highest total count due to its broader policy catalog. **Terrascan** was the most conservative with 22 violations.

### Pulumi Security Analysis (KICS)

KICS scanned `labs/lab6/vulnerable-iac/pulumi/Pulumi-vulnerable.yaml` and found **6 findings**:

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |
| **TOTAL** | **6** |

Key findings:
- **RDS DB Instance Publicly Accessible** (CRITICAL) — database exposed to internet
- **DynamoDB Table Not Encrypted** (HIGH) — data at rest not encrypted
- **Passwords And Secrets - Generic Password** (HIGH) — hardcoded credentials in YAML

### Terraform vs Pulumi Comparison

| Aspect | Terraform (HCL) | Pulumi (YAML) |
|--------|----------------|---------------|
| Findings | 53 (tfsec) | 6 (KICS) |
| Scanner | tfsec/Checkov/Terrascan | KICS only |
| Tooling maturity | Very mature | Growing |
| Issue types | Encryption, IAM, network, secrets | Encryption, secrets, access |

Terraform has more mature tooling with multiple specialized scanners. Pulumi YAML support in KICS is functional but the ecosystem is smaller. The lower finding count for Pulumi reflects KICS's more focused query catalog for Pulumi, not necessarily fewer vulnerabilities in the code.

### KICS Pulumi Support Evaluation

KICS auto-detects Pulumi YAML files and applies Pulumi-specific queries for AWS, Azure, GCP, and Kubernetes resources. It correctly identified the `Pulumi-vulnerable.yaml` file and found critical issues like public RDS access and hardcoded secrets. The query catalog is smaller than Terraform-specific tools but covers the most impactful security categories.

### Critical Findings (Top 5)

1. **Hardcoded AWS Credentials in Terraform**
   - File: `variables.tf`
   - Severity: CRITICAL
   - Tool: tfsec (AVD-AWS-0007)
   - Impact: Full AWS account compromise if code is leaked

2. **Security Group Open to 0.0.0.0/0**
   - File: `security_groups.tf`
   - Severity: CRITICAL
   - Tool: tfsec, Checkov, Terrascan
   - Impact: All ports exposed to the internet

3. **RDS Instance Publicly Accessible**
   - File: `database.tf` / `Pulumi-vulnerable.yaml`
   - Severity: CRITICAL
   - Tool: tfsec, KICS
   - Impact: Database directly reachable from internet

4. **Wildcard IAM Permissions (`*`)**
   - File: `iam.tf`
   - Severity: HIGH
   - Tool: tfsec, Checkov
   - Impact: Privilege escalation, full AWS access

5. **S3 Bucket Without Encryption**
   - File: `main.tf`
   - Severity: HIGH
   - Tool: tfsec, Checkov, Terrascan
   - Impact: Data at rest unprotected

### Tool Strengths

- **tfsec**: Fast, Terraform-specific, excellent severity classification, low false positives
- **Checkov**: Broadest policy catalog (1000+ checks), multi-framework support, compliance mapping
- **Terrascan**: OPA-based, compliance-focused (PCI-DSS, HIPAA), conservative findings
- **KICS**: Best for Pulumi and Ansible, unified tool across multiple IaC frameworks

---

## Task 2 — Ansible Security Scanning with KICS

### KICS Ansible Results

KICS scanned `labs/lab6/vulnerable-iac/ansible/` and found **10 findings**:

| Severity | Count |
|----------|-------|
| HIGH | 9 |
| LOW | 1 |
| **TOTAL** | **10** |

### Key Security Issues Found

1. **Passwords And Secrets - Generic Password** (HIGH)
   - Files: `deploy.yml`, `configure.yml`, `inventory.ini`
   - Hardcoded passwords in plaintext across multiple files
   - Impact: Credential exposure if repository is accessed

2. **Passwords And Secrets - Generic Secret** (HIGH)
   - Files: `deploy.yml`, `inventory.ini`
   - API keys and secret tokens stored in plaintext
   - Impact: Service account compromise

3. **Passwords And Secrets - Password in URL** (HIGH)
   - File: `inventory.ini`
   - Database connection strings with embedded credentials
   - Impact: Database access credentials exposed

4. **Unpinned Package Version** (LOW)
   - File: `deploy.yml`
   - Packages installed without version pinning
   - Impact: Supply chain risk, unpredictable deployments

### Best Practice Violations

1. **No `no_log: true` on sensitive tasks**
   - Tasks handling passwords log output by default
   - Fix: Add `no_log: true` to any task using secrets

2. **Credentials in inventory.ini**
   - `ansible_become_password`, `db_admin_password`, `api_secret_key` in plaintext
   - Fix: Use Ansible Vault — `ansible-vault encrypt_string 'secret' --name 'var_name'`

3. **Hardcoded secrets in playbooks instead of Vault**
   - `deploy.yml` contains `db_password: "SuperSecret123!"` directly
   - Fix: Store in encrypted vault file and reference with `{{ vault_db_password }}`

### Remediation Steps

```yaml
# Before (insecure)
- name: Configure database
  vars:
    db_password: "SuperSecret123!"

# After (secure)
- name: Configure database
  vars:
    db_password: "{{ vault_db_password }}"
  no_log: true
```

```ini
# Before (insecure inventory.ini)
db_admin_password=SuperSecret123!

# After — use vault or environment variables
db_admin_password={{ lookup('env', 'DB_ADMIN_PASSWORD') }}
```

---

## Task 3 — Comparative Tool Analysis & Security Insights

### Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings (Terraform)** | 53 | 78 | 22 | N/A |
| **Pulumi Support** | No | No | No | Yes (6 findings) |
| **Ansible Support** | No | No | No | Yes (10 findings) |
| **Scan Speed** | Fast | Medium | Medium | Medium |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Multi-framework | Terraform, K8s | Multi-framework |
| **Output Formats** | JSON, SARIF, text | JSON, SARIF, CLI | JSON, human | JSON, HTML, SARIF |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strength** | Speed + accuracy | Broadest coverage | Compliance mapping | Pulumi + Ansible |

### Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption Issues** | ✅ High | ✅ High | ✅ Medium | ✅ High | N/A | Checkov |
| **Network Security** | ✅ High | ✅ High | ✅ High | ✅ Medium | N/A | tfsec/Checkov |
| **Secrets Management** | ✅ High | ✅ High | ❌ Low | ✅ High | ✅ High | KICS |
| **IAM/Permissions** | ✅ High | ✅ High | ✅ Medium | ❌ Low | N/A | Checkov |
| **Access Control** | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | All |
| **Compliance** | ❌ Low | ✅ Medium | ✅ High | ❌ Low | ❌ Low | Terrascan |

### Tool Selection Guide

- **tfsec** — Best for Terraform-only projects needing fast CI/CD feedback with low noise
- **Checkov** — Best for teams using multiple IaC frameworks (Terraform + CloudFormation + K8s)
- **Terrascan** — Best when compliance mapping (PCI-DSS, HIPAA, SOC2) is required
- **KICS** — Best for Pulumi and Ansible, or when a single tool needs to cover multiple frameworks

### CI/CD Integration Strategy

Recommended multi-stage pipeline:

```
Stage 1 (Pre-commit): tfsec — fast feedback, blocks obvious issues
Stage 2 (PR check):   Checkov — comprehensive policy enforcement
Stage 3 (Staging):    Terrascan — compliance validation before production
Stage 4 (Ansible):    KICS — playbook security before deployment
```

### Lessons Learned

1. **No single tool catches everything** — tfsec found 53, Checkov 78, Terrascan only 22 on the same code. Running multiple tools is essential.

2. **Checkov has the broadest coverage** but generates more noise. Good for thorough audits, less ideal for blocking CI/CD pipelines.

3. **tfsec is the best developer experience** — fast, clear output, actionable messages with remediation links.

4. **KICS fills a critical gap** — it's the only tool here with first-class Pulumi and Ansible support, making it essential for polyglot IaC environments.

5. **Secrets detection is inconsistent** — Terrascan missed hardcoded credentials that tfsec and KICS caught. Always include a dedicated secrets scanner (e.g., truffleHog, gitleaks) in addition to IaC scanners.

6. **Shift-left matters** — all 80+ vulnerabilities in this lab would have been deployed to production without IaC scanning. Catching them at code review stage costs near zero compared to post-deployment remediation.
