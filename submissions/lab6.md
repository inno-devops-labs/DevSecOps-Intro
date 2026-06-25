# Lab 6 — IaC Security: Checkov + KICS + a Custom Policy

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Not provided by Checkov | 78 |

> **Note:** Checkov did not provide severity metadata for these findings in the generated JSON report, therefore findings were grouped as "Not provided".

### Top 5 rule IDs (by frequency among failed checks)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | IAM policies should not allow permissions management or resource exposure without constraints |
| `CKV_AWS_355` | 4 | IAM policies should not allow `*` as a statement's resource for restrictable actions |
| `CKV_AWS_288` | 3 | IAM policies should not allow data exfiltration |
| `CKV_AWS_290` | 3 | IAM policies should not allow write access without constraints |
| `CKV_AWS_23`  | 3 | Every security group and rule must have a description |

### Pulumi scan

Pulumi source was reviewed using Checkov secret scanning.
The full infrastructure configuration scan was performed with KICS in Task 2 because Checkov v3.3.2 does not directly scan Pulumi source files as Terraform HCL.

- Total checks: 1
- Failed: 1
- Passed: 0


| Severity | Count |
|----------|------:|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |
| Not provided by Checkov | 1 |

**Failed check:**  
- `CKV_SECRET_6` (Base64 High Entropy String) – found in `Pulumi-vulnerable.yaml` (line 19) containing a high-entropy string that appears to be a secret key.

> **Note:** No severity levels were provided for this check.

### Module-leverage analysis (Lecture 6 slide 17)

The most effective single fix would be to create a reusable template for IAM policies that gives only the minimum permissions needed by default.

If we use this template instead of writing custom policies for each resource, we can fix the 4 most common violations (`CKV_AWS_289`, `355`, `288`, and `290`). This would eliminate at least 14 errors out of 78 (almost one-fifth of all problems). Most AWS access issues would be solved with one change.

## Task 2: KICS on Ansible

### Severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| Total | 10 |

### Top 5 KICS queries (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

> **Note:** Only 4 queries were displayed because KICS found only 4 unique query types in the Ansible scan results, so there was no fifth query to include.

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- **One thing Checkov did better for the Terraform sample:**  
Checkov worked well with Terraform files and provided many Terraform-specific security checks, for example checking AWS IAM permissions, security groups, and storage settings. It was useful for finding infrastructure configuration problems.

- **One thing KICS did better for the Ansible sample:**  
KICS was better for scanning Ansible because it understands different Infrastructure-as-Code formats and can find problems inside playbooks, such as hardcoded passwords, insecure commands, and bad configuration practices.

- **Example of a finding only ONE of them caught:**  
KICS found Ansible-specific issues like passwords stored in playbooks and unsafe shell usage, while Checkov would not detect these because it is mainly focused on Terraform and cloud infrastructure configuration.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure RDS instances have storage encryption enabled"
  category: "ENCRYPTION"
  severity: HIGH

definition:
  cond_type: attribute
  resource_types:
    - aws_db_instance
  attribute: "storage_encrypted"
  operator: equals
  value: true
```
Output: Passed checks: 50, Failed checks: 79, Skipped checks: 0

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances have storage encryption enabled",
  "check_result": {
    "result": "FAILED",
    "evaluated_keys": [
      "storage_encrypted"
    ]
  },
  "file_path": "\\database.tf",
  "resource": "aws_db_instance.unencrypted_db",
  "file_line_range": [
    5,
    37
  ]
}
```

### Why this rule matters
Database encryption protects sensitive data at rest and reduces the risk of data exposure if database storage, snapshots, or backups are compromised. This custom policy enforces AWS security best practices by requiring encryption for RDS instances.