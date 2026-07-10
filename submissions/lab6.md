# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Unknown | 78 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow permissions management or resource exposure without constraints. |
| CKV_AWS_355 | 4 | IAM policy documents must not allow `*` as the resource for restrictable actions. |
| CKV_AWS_23 | 3 | Security groups and security group rules should have descriptions. |
| CKV_AWS_288 | 3 | IAM policies must not allow data exfiltration. |
| CKV_AWS_290 | 3 | IAM policies must not allow unconstrained write access. |

### Pulumi scan
| Severity | Count |
|----------|------:|
| Not run | 0 |

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage fix is to change the IAM policy module/pattern so it does not generate wildcard permissions such as `Action = "*"`, broad service wildcards like `s3:*`, or `Resource = "*"`.

This would reduce the most frequent findings: `CKV_AWS_289` and `CKV_AWS_355` both appear 4 times, and the same IAM issue also contributes to `CKV_AWS_288` and `CKV_AWS_290`.

## Task 2: KICS on Ansible

### Ansible Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 1 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |


### Pulumi Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- Checkov did better for the Terraform sample because it produced many Terraform-specific AWS findings with clear CKV rule IDs. It was especially useful for grouping repeated IAM policy problems, such as wildcard actions/resources and unconstrained permissions, which makes module-level triage easier.

- KICS did better for the Ansible sample because it understands Ansible playbooks directly and found issues in tasks and variables, including generic passwords, secrets, passwords in URLs, and unpinned packages. This is a better fit than using a Terraform-focused scanner for configuration-management code.

- One example of tool-specific coverage is the Ansible secret findings: KICS reported `Passwords And Secrets - Generic Password`, `Passwords And Secrets - Password in URL`, and `Passwords And Secrets - Generic Secret` in the Ansible scan. Those findings are outside the Terraform Checkov scan scope, while Checkov gave deeper Terraform/IAM policy checks like `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290`.
