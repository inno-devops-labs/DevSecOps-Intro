# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| N/A (no BC API key) | 78 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management/resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure IAM policies do not allow Star Resource on sensitive IAM actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration without constraints |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints |

### Pulumi scan
| Severity | Count |
|----------|------:|
| N/A (scanned via KICS — see Task 2) | — |

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage fix would target the IAM module: rules CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, and CKV_AWS_290 together produce 14 failed checks, all caused by wildcard `Action: *` and `Resource: *` in policies defined in `iam.tf`. If the shared IAM module enforced explicit, scoped actions and resources by default — rejecting any policy with `"Action": "*"` or `"Resource": "*"` — all 14 findings would be closed with a single module-level change.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **Checkov did better for Terraform:** Checkov found 78 failed checks across IAM, S3, RDS, and Security Groups using its deep Terraform-aware policy catalog, catching resource-level misconfigurations like missing encryption, public access blocks, and IAM wildcard permissions with precise rule IDs and remediation links.
- **KICS did better for Ansible:** KICS natively understands Ansible playbook and inventory file structure, detecting 9 HIGH severity findings including hardcoded credentials spread across `deploy.yml`, `configure.yml`, and `inventory.ini` — Checkov has no Ansible framework and would produce zero results on these files.
- **Finding only one tool caught:** KICS caught hardcoded passwords in `inventory.ini` (a plain INI file), while Checkov's secret scanning only flagged credentials inside Terraform `.tf` files — same credential pattern, different file format, only KICS caught it.
