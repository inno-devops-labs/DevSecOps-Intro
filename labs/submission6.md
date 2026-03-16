# Lab 6 Submission — Infrastructure-as-Code Security

## Task 1: Terraform & Pulumi Security Scanning

### Terraform Tool Comparison

| Tool | Findings Count | Speed | Strengths |
|---|---|---|---|
| **tfsec** | 53 | Fast | Highly specific to Terraform, very low false positives, clear remediation. |
| **Checkov** | 78 | Medium | Comprehensive rule set, multi-framework support, detects complex attribute relations. |
| **Terrascan** | 22 | Fast | Policy-as-Code (OPA) based, focus on compliance standards. |

**Analysis:**
Checkov identified the most findings due to its extensive policy catalog. tfsec was the fastest and provided the most actionable Terraform-specific advice. Terrascan found fewer issues but focused on higher-level compliance misconfigurations.

### Pulumi Security Analysis (KICS)

**Vulnerability Breakdown:**
- HIGH severity: 2
- MEDIUM severity: 1
- LOW severity: 0
- INFO severity: 3
- **TOTAL findings: 6**

**Analysis:**
KICS effectively identified RDS and S3 misconfigurations in the Pulumi YAML manifests. It showed first-class support for Pulumi-specific resource types.

### Critical Findings (Terraform & Pulumi)

1. **Publicly Accessible RDS Instance**
   - **Framework:** Terraform & Pulumi
   - **Severity:** CRITICAL
   - **Description:** RDS instances are exposed to the public internet (`publicly_accessible = true`).
   - **Remediation Code (Terraform):**
     ```hcl
     resource "aws_db_instance" "vulnerable" {
       # ...
       publicly_accessible = false  # Fix: Change from true to false
       skip_final_snapshot = true
     }
     ```

2. **S3 Buckets without Public Access Block**
   - **Framework:** Terraform & Pulumi
   - **Severity:** HIGH
   - **Description:** S3 buckets lack strict public access prevention.
   - **Remediation Code (Terraform):**
     ```hcl
     resource "aws_s3_bucket_public_access_block" "example" {
       bucket = aws_s3_bucket.vulnerable.id
       block_public_acls       = true
       block_public_policy     = true
       ignore_public_acls      = true
       restrict_public_buckets = true
     }
     ```

3. **Hardcoded AWS Credentials**
   - **Framework:** Terraform (variables.tf)
   - **Severity:** CRITICAL
   - **Description:** AWS Access and Secret Keys are hardcoded in plain text.
   - **Remediation Strategy:** Remove defaults and use environment variables or `~/.aws/credentials`.

4. **Security Group Allowing SSH (Port 22) from 0.0.0.0/0**
   - **Framework:** Terraform
   - **Severity:** HIGH
   - **Description:** Ingress rule allows any IP to attempt SSH connection.
   - **Remediation Code (Terraform):**
     ```hcl
     resource "aws_security_group_rule" "ssh" {
       type        = "ingress"
       from_port   = 22
       to_port     = 22
       protocol    = "tcp"
       cidr_blocks = ["10.0.0.0/8"] # Fix: Use specific internal range
     }
     ```

5. **IAM Policies with Wildcard Resource Access**
   - **Framework:** Terraform (iam.tf)
   - **Severity:** HIGH
   - **Description:** Using `Resource = "*"` grants permissions to all resources in account.
   - **Remediation Code (Terraform):**
     ```hcl
     resource "aws_iam_policy" "fixed" {
       policy = jsonencode({
         Statement = [{
           Action   = ["s3:GetObject"]
           Resource = ["arn:aws:s3:::specific-bucket-name/*"] # Fix: Specify ARN
           Effect   = "Allow"
         }]
       })
     }
     ```

---

## Task 2: Ansible Security Scanning with KICS

**Vulnerability Breakdown:**
- HIGH severity: 9
- MEDIUM severity: 0
- LOW severity: 1
- **TOTAL findings: 10**

### Ansible Security Analysis
KICS identifies critical secrets management issues. In `deploy.yml`, hardcoded passwords were found in tasks.
**Best Practice Violation 1:** Hardcoded Secrets. Avoid plaintext passwords in playbooks.
**Best Practice Violation 2:** Missing `no_log`. Sensitive tasks must hide output.
**Best Practice Violation 3:** Weak SSH configuration (found in `configure.yml`).

**Remediation Code (Ansible):**
```yaml
- name: Secure task example
  user:
    name: admin
    password: "{{ vault_password }}" 
  no_log: true 
```

### KICS Ansible Query Evaluation
KICS provides a robust catalog of Ansible-specific queries covering `become` escalation, `module` parameters security, and task-level permissions.

---

## Task 3: Comparative Tool Analysis & Security Insights

### Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|---|---|---|---|---|
| **Total Findings (TF)** | 53 | 78 | 22 | N/A |
| **Scan Speed** | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform | Multi | Multi | Multi |
| **Output Formats** | JSON, Text | JSON, CLI | JSON, Human | JSON, HTML |

### Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|---|---|---|---|---|---|---|
| **Encryption** | 12 | 15 | 8 | 2 | 0 | Checkov |
| **Network Security** | 10 | 14 | 6 | 2 | 2 | Checkov |
| **Secrets Management**| 5 | 8 | 2 | 1 | 8 | KICS |
| **IAM/Permissions** | 8 | 12 | 4 | 1 | 0 | Checkov |

### Security Insights & Recommendations

#### Terraform (HCL) vs. Pulumi (YAML/Python) Comparison
Terraform's declarative HCL allows scanners to easily build dependency graphs and identify misconfigurations across resources. Pulumi's programmatic approach (even in YAML) introduces dynamic complexity. While HCL scanning is more mature and provides more granular findings (tfsec/Checkov), KICS proves that scanning high-level manifests (YAML/programmatic representations) is effective for catching high-impact misconfigurations like open ports or unencrypted databases.

#### KICS Evaluation (Pulumi Support)
KICS version v1.6+ introduced a dedicated Pulumi query catalog. It excels at mapping Pulumi's high-level resource definitions to underlying cloud providers (AWS, Azure, GCP).

#### Tool Selection & CI/CD Strategy
- **Pre-commit:** Use `tfsec` due to its high speed and minimal dependencies.
- **CI/CD Pipeline:** Use **Checkov** or **KICS** as they provide unified compliance scanning across Terraform, Ansible, and Kubernetes manifests.

### Lessons Learned
Multi-tool scanning is vital. **Checkov** finds the most issues but can be slow. **tfsec** is excellent for Terraform-only workflows. **KICS** is the go-to for Ansible and Pulumi consistency.

