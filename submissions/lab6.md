# Lab 6 — IaC Security Scanning with Checkov and KICS

## Task 1 — Checkov Terraform Scan

### Scan summary

Checkov 3.3.20 was used to scan the Terraform configuration.

| Framework | Passed | Failed |
|---|---:|---:|
| Terraform | 49 | 78 |
| Secrets | 0 | 2 |

The Terraform scan produced 78 failed checks, while the secrets scanner detected 2 findings.

### Top 5 failed rules

| Rule | Count | Description |
|---|---:|---|
| `CKV_AWS_289` | 4 | IAM policies should not allow permissions management or resource exposure without constraints. |
| `CKV_AWS_355` | 4 | IAM policies should not use `*` as the resource for restrictable actions. |
| `CKV_AWS_23` | 3 | Every security group and rule should have a description. |
| `CKV_AWS_288` | 3 | IAM policies should not allow data exfiltration. |
| `CKV_AWS_290` | 3 | IAM policies should not allow write access without constraints. |

### Secrets findings

The secrets framework reported two findings:

- `CKV_SECRET_6` — Base64 High Entropy String in `database.tf`.
- `CKV_SECRET_2` — AWS Access Key in `main.tf`.

### Highest-leverage change

The resource with the largest number of findings was:

- File: `iam.tf`
- Resource: `aws_iam_policy.admin_policy`
- Findings: 23

The policy contains:

```hcl
Action   = "*"
Resource = "*"