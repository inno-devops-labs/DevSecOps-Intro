# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

*Severity not available in JSON without Bridgecrew API key (all null).*

### Top 5 rule IDs (by frequency)

| Rule ID       | Count | What it checks |
|---------------|------:|----------------|
| CKV_AWS_355   | 4     | No IAM policy allows "*" resource for restrictable actions |
| CKV_AWS_289   | 4     | IAM policies must not allow permissions management without constraints |
| CKV_AWS_382   | 3     | Security groups must not allow egress from 0.0.0.0:0 to port -1 |
| CKV_AWS_290   | 3     | IAM policies must not allow write access without constraints |
| CKV_AWS_288   | 3     | IAM policies must not allow data exfiltration |

### Module-leverage analysis
Fixing the **IAM policy module** (restricting `Resource` to specific ARNs and limiting `Action`) would eliminate CKV_AWS_355, 289, 290, and 288 — **14 findings** (~18% of all failures). Adding a secure default for security group egress (CKV_AWS_382) would cover ~22% of failures from just two module changes.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible
- Scanned: 3 files, 309 lines
- Queries: 287
- Findings: 10

| Severity | Count |
|----------|------:|
| HIGH     | 9     |
| LOW      | 1     |

**Top queries:**
- Passwords And Secrets - Generic Password (HIGH, 6)
- Passwords And Secrets - Password in URL (HIGH, 2)
- Passwords And Secrets - Generic Secret (HIGH, 1)
- Unpinned Package Version (LOW, 1)

### Pulumi
- Scanned: 1 file, 280 lines
- Queries: 21
- Findings: 6

| Severity | Count |
|----------|------:|
| CRITICAL | 1     |
| HIGH     | 2     |
| MEDIUM   | 1     |
| INFO     | 2     |

**Findings:**
- RDS DB Instance Publicly Accessible (CRITICAL)
- DynamoDB Table Not Encrypted (HIGH)
- Generic Password (HIGH)
- EC2 Instance Monitoring Disabled (MEDIUM)
- DynamoDB Table Point In Time Recovery Disabled (INFO)
- EC2 Not EBS Optimized (INFO)

### Checkov vs KICS
- **Checkov (Terraform):** broader coverage (2,500+ policies), graph-based checks, caught IAM, S3, RDS, security group issues.
- **KICS (Ansible):** natively parses Ansible playbooks/inventory, found hardcoded secrets and unpinned versions that Checkov would miss.
- **Unique finding:** KICS detected “DynamoDB Table Not Encrypted” (missing encryption) in Pulumi; Checkov’s Terraform equivalent (CKV_AWS_119) only checks key type (KMS vs. AWS managed), not absence of encryption.
