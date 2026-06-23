# Lab 6 — Submission

> Lab 6 complete (Task 1 + Task 2 + Bonus).

---

## Task 1: Checkov on Terraform

### Terraform scan

- Total checks: **127** (49 passed + 78 failed)
- Passed: **49**
- Failed: **78**
- Resources scanned: **16**
- Checkov version: **3.3.2**

| Severity in JSON | Count |
|------------------|------:|
| `null` | **78** |

Checkov не заполняет Critical/High/Medium/Low в JSON без Prisma Cloud API key (`--bc-api-key`). С `--skip-download` / `BC_SKIP_MAPPING=TRUE` (offline) все 78 failed checks имеют `"severity": null` — это ожидаемо, не баг скана. Passed/failed/total (**49 / 78 / 127**) — из `.summary`. KICS (Task 2) severity заполнен, т.к. не зависит от Prisma API.

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy allows `*` resource on restrictable actions |
| CKV_AWS_23 | 3 | Security group / rule missing description |
| CKV_AWS_288 | 3 | IAM policies allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies allow write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)

The highest-leverage fix is a **shared IAM policy module** in `iam.tf`: ban `Action: *` / `Resource: *`, require scoped resources, and use cloudsplaining-safe statement templates. That one change would eliminate the top recurring rules (**CKV_AWS_289**, **CKV_AWS_355**, **CKV_AWS_288**, **CKV_AWS_290** — 14 findings combined) across `aws_iam_role_policy`, `aws_iam_user_policy`, and `aws_iam_policy` resources instead of patching each policy inline.

---

## Task 2: KICS on Ansible + Pulumi

### KICS — Ansible

| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top KICS queries — Ansible

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### KICS — Pulumi

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

*KICS CLI summary for Pulumi: 6 total findings (1 Critical / 2 High / 1 Medium / 2 Info).*

### Top 5 KICS queries — Pulumi

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS (Lecture 6 slide 10)

**Checkov better on Terraform:** Checkov’s Terraform engine + cloudsplaining integration surfaced **14 IAM-related failures** across recurring rules (CKV_AWS_289/355/288/290) with resource-level CKV IDs tied to `iam.tf` and `security_groups.tf`. It understands HCL resource graphs natively and groups failures by AWS policy semantics better than a generic multi-format scanner.

**KICS better on Ansible/Pulumi:** KICS scanned **Ansible playbooks** and **Pulumi YAML** directly — formats Checkov did not cover in this lab. It found **9 secret/password hits** in Ansible (`deploy.yml`, `configure.yml`, `inventory.ini`) and Pulumi issues like **RDS publicly accessible** (`Pulumi-vulnerable.yaml:104`) and **unencrypted DynamoDB** — without needing rendered Terraform state.

**Finding only one tool caught:** **Password in URL** (KICS, Ansible, HIGH) — hardcoded credentials inside `git clone https://user:pass@...` style URLs in playbooks. Checkov only scanned the Terraform directory, so this Ansible-only secret pattern appears exclusively in KICS output.

---

## Bonus: Custom Checkov Policy

### Policy file

```yaml
---
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 bucket has Environment tag
  category: GENERAL_SECURITY
  severity: MEDIUM
scope:
  provider: terraform
definition:
  cond_type: attribute
  resource_types:
    - aws_s3_bucket
  attribute: tags.Environment
  operator: exists
```

### Rule fires

**2 failed checks** — `CKV2_CUSTOM_1` (severity MEDIUM):

| Resource | File | Issue |
|----------|------|-------|
| `aws_s3_bucket.public_data` | `main.tf:13-21` | `tags` has only `Name`, no `Environment` |
| `aws_s3_bucket.unencrypted_data` | `main.tf:24-33` | no `tags.Environment` |

```json
[
  {"check_id": "CKV2_CUSTOM_1", "resource": "aws_s3_bucket.public_data", "file_path": "/main.tf", "severity": "MEDIUM"},
  {"check_id": "CKV2_CUSTOM_1", "resource": "aws_s3_bucket.unencrypted_data", "file_path": "/main.tf", "severity": "MEDIUM"}
]
```

Evaluated key: `tags/Environment`. Comment in source confirms intent: `# Missing required tags: Environment, Owner, CostCenter`.

### Why this rule matters

Missing `Environment` tags make it hard to apply least-privilege IAM conditions, cost guardrails, and automated cleanup in shared AWS accounts. Tagging standards (e.g. CIS AWS, internal org policy) require environment labels so prod data cannot be mistaken for dev and vice versa.
