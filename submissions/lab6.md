# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security groups rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)
Every IAM policy in `iqm.tf` sets `Resource = "*"`. `admin_policy`, `s3_full_access`, `service_policy` and `privilege_escalation` together trigger 16 findings across `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290`. Dropping that wildcard would fix all four of them.