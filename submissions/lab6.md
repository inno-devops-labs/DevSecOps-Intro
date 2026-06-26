# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Tool: Checkov 3.3.2
- Target: `labs/lab6/vulnerable-iac/terraform`
- Total checks: **127**
- Passed: **49**
- Failed: **78**
- Skipped: **0**

| Severity | Count |
|----------|------:|
| Unspecified / null | 78 |

Note: In this local Checkov OSS JSON output, all failed Terraform checks had `severity: null`. I report them as `Unspecified / null` instead of inventing Critical/High/Medium/Low values, so the severity table matches the actual JSON output.

### Top 5 rule IDs by frequency

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |
| `CKV_AWS_355` | 4 | Ensure no IAM policy documents allow `*` as a statement resource for restrictable actions |
| `CKV_AWS_23` | 3 | Ensure every security group and rule has a description |
| `CKV_AWS_288` | 3 | Ensure IAM policies do not allow data exfiltration |
| `CKV_AWS_290` | 3 | Ensure IAM policies do not allow write access without constraints |

### Pulumi scan

Pulumi source was scanned with KICS, which natively recognized the Pulumi sample. This follows the lab note that Checkov 3.x does not scan Pulumi source directly in the same way as Terraform; it expects rendered Pulumi state or a different framework.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

Top Pulumi KICS findings:

| Query | Severity | Findings |
|-------|----------|---------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Module-leverage analysis

The highest-leverage Terraform fix is to improve the shared IAM policy/module pattern. The top two rules, `CKV_AWS_289` and `CKV_AWS_355`, each fired 4 times and both point to over-permissive IAM policy documents. If the IAM module generated least-privilege policies by default and avoided unconstrained `Action`/`Resource` patterns, one module-level change could remove multiple findings across the Terraform sample.

A second useful module-level improvement would be adding required descriptions to security group and security group rule modules. That would address the repeated `CKV_AWS_23` findings across multiple security group resources.

---

## Task 2: KICS on Ansible + Checkov-vs-KICS Comparison

### KICS on Ansible

- Tool: KICS
- Target: `labs/lab6/vulnerable-iac/ansible`
- Total findings: **10**

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Top KICS queries by frequency

| Query | Severity | Findings |
|-------|----------|---------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which?

Checkov did better for the Terraform sample because it produced many AWS-specific Terraform findings and grouped them by CKV rule IDs such as IAM policy constraints and security group hygiene. This made it easier to reason about module-level fixes, especially when multiple findings were caused by the same underlying Terraform pattern.

KICS did better for the Ansible sample because it natively understood the Ansible playbook and inventory files and surfaced concrete secret-management issues, such as hardcoded passwords, secrets in inventory variables, and credentials embedded in URLs. These are common IaC security issues outside Terraform, and KICS handled that format directly.

For Pulumi, KICS was also useful because it recognized the Pulumi sample and reported cloud-resource issues such as public RDS access, missing DynamoDB encryption, disabled EC2 monitoring, and disabled point-in-time recovery. This shows that the tools have different strengths: Checkov was stronger for Terraform policy analysis in this lab, while KICS covered broader IaC formats like Ansible and Pulumi source.

---

## Bonus: Custom Checkov Policy

### Policy file

File: `labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure RDS instances use IAM database authentication"
  category: "IAM"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "iam_database_authentication_enabled"
  operator: "equals"
  value: true
```

### Rule fires

Output of:

```bash
jq '
  .[0].results.failed_checks[]
  | select(.check_id | startswith("CKV2_CUSTOM_"))
  | {
      check_id,
      check_name,
      severity,
      file_path,
      resource
    }
' labs/lab6/results/checkov-custom/results_json.json
```

Result:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances use IAM database authentication",
  "severity": "HIGH",
  "file_path": "/database.tf",
  "resource": "aws_db_instance.unencrypted_db"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances use IAM database authentication",
  "severity": "HIGH",
  "file_path": "/database.tf",
  "resource": "aws_db_instance.weak_db"
}
```

The custom policy fired on **2** Terraform RDS resources.

### Why this rule matters

Requiring IAM database authentication for RDS helps reduce reliance on long-lived static database passwords. Static database credentials are often leaked through code, configuration files, CI logs, or local developer environments. IAM authentication supports centralized identity controls and short-lived authentication tokens, which better aligns with least-privilege access and credential-rotation practices.

This rule also maps to common compliance and hardening expectations around centralized identity management and controlled authentication. For example, NIST SP 800-53 controls such as IA-2 (Identification and Authentication) and AC-2 (Account Management) emphasize managed identities, account control, and reducing unmanaged credential exposure. In practical cloud security terms, this policy helps enforce the same direction: avoid static database secrets where a cloud-native identity-based authentication mechanism is available.

---

## Reproducibility notes

Generated scanner artifacts were intentionally excluded from the commit:

- `labs/lab6/results/`
- `.venv-checkov/`

The committed evidence is the analysis in `submissions/lab6.md` and the custom policy file in `labs/lab6/policies/my-custom-policy.yaml`.
