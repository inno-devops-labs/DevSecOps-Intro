# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | N/A |
| High | N/A |
| Medium | N/A |
| Low | N/A |
*Open-source Checkov does not show severity in JSON output (it's a paid Prism Cloud feature).*

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies allow permissions management or resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policies use "*" as resource for restrictable actions (overly permissive) |
| CKV_AWS_23 | 3 | Security group rules missing descriptions |
| CKV_AWS_288 | 3 | IAM policy may allow excessive write permissions |
| CKV_AWS_290 | 3 | IAM policies allow write access without constraints |

### Module-leverage analysis
Looking at the top 5 Terraform rules, the most impactful fix would be to address rule CKV_AWS_289, which appear 4 times. Since these are likely related to specific resource types (e.g., S3 buckets or IAM roles), fixing the module that defines these resources would eliminate multiple findings at once. For example, if CKV_AWS_289 checks for missing encryption, adding `encryption = true` at the module level would fix all 4 occurrences.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Count |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS
- **Checkov was better for Terraform** because it has deep AWS-specific rules (e.g., CKV_AWS_* rules) and graph-based checks that understand relationships between resources.

- **KICS was better for Ansible** because Checkov's Ansible support is basic, while KICS has dedicated Rego queries for Linux hardening and secret detection in playbooks and inventory files.

- **One finding only KICS caught**: The Password in URL and Generic Secret findings in `deploy.yml` and `inventory.ini` were caught by KICS but likely would have been missed by Checkov due to its limited Ansible coverage.