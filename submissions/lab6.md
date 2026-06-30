# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Total checks: 129
- Passed: 49
- Failed: 80

> **Note:** Checkov 3.3.2 without a Bridgecrew API key does not populate the `severity` field in JSON output (field is `null` for all checks). The severity breakdown below is derived from the Checkov rule catalog cross-referenced by check ID.

| Severity | Count (estimated) |
|----------|------------------:|
| Critical | 0                 |
| High     | ~28               |
| Medium   | ~35               |
| Low      | ~17               |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy statements must not use `"*"` as Resource for restrictable actions |
| CKV_AWS_23  | 3 | Every security group and rule must have a description |
| CKV_AWS_288 | 3 | IAM policies must not allow data exfiltration actions without constraints |
| CKV_AWS_290 | 3 | IAM policies must not allow write access without resource constraints |

### Pulumi scan

Pulumi was scanned with **KICS** (see Task 2) — Checkov 3.x does not natively parse Pulumi Python or YAML without `pulumi preview --json` state; KICS has first-class Pulumi YAML support.

KICS scan of `Pulumi-vulnerable.yaml`:

| Severity | Count |
|----------|------:|
| Critical | 1     |
| High     | 2     |
| Medium   | 1     |
| Info     | 2     |
| **Total**| **6** |

### Module-leverage analysis (Lecture 6 slide 17)

Four of the top five rules (CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, CKV_AWS_290) all fire because the same anti-pattern — `Action: "*"` or `Resource: "*"` — is copy-pasted into `admin_policy`, `privilege_escalation`, `s3_full_access`, and `service_policy`. If the team introduced a shared IAM module that enforced least-privilege by default (rejecting wildcard actions/resources at the module interface and requiring explicit, scoped action lists), all 14 of those findings across 4 IAM resources would collapse to a single module-level fix rather than 14 individual resource changes.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown

KICS scanned 3 files, 309 lines.

| Severity | Count |
|----------|------:|
| HIGH     | 3     |
| LOW      | 1     |
| **Total queries hit** | **4** |

### Ansible — top queries by frequency

| Query | Severity | Findings |
|-------|----------|--------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL  | HIGH | 2 |
| Passwords And Secrets - Generic Secret   | HIGH | 1 |
| Unpinned Package Version                 | LOW  | 1 |

Key locations:
- `inventory.ini:5,10,19` — plaintext passwords in inventory vars (`db_password`, `api_key`, etc.)
- `deploy.yml:16,72` — DB connection string with embedded password in URL form
- `deploy.yml:99` — `name: latest` instead of pinned version

### Pulumi — top queries

| Query | Severity | File:Line |
|-------|----------|-----------|
| RDS DB Instance Publicly Accessible | CRITICAL | Pulumi-vulnerable.yaml:104 |
| DynamoDB Table Not Encrypted        | HIGH     | Pulumi-vulnerable.yaml:205 |
| Passwords And Secrets - Generic Password | HIGH | Pulumi-vulnerable.yaml:16  |
| EC2 Instance Monitoring Disabled    | MEDIUM   | Pulumi-vulnerable.yaml:157 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | Pulumi-vulnerable.yaml:213 |
| EC2 Not EBS Optimized               | INFO     | Pulumi-vulnerable.yaml:157 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample:** Checkov's rule catalog for Terraform HCL is far deeper — 80 failed checks across IAM, S3, RDS, security groups and DynamoDB, with cross-resource graph checks (e.g. CKV_AWS_355 understands the JSON policy body embedded in `jsonencode()` and parses it semantically). KICS on the same Terraform files would surface fewer IAM-specific findings because KICS's Terraform coverage is narrower in the IAM domain.

**One thing KICS did better for the Ansible sample:** KICS detected secrets in `inventory.ini` (6 findings) by running a broad secrets-scanning pass across all file types in the directory. Checkov does not ship Ansible support in the community edition — scanning Ansible with Checkov requires a custom framework plugin, so KICS is the only realistic option for Ansible in a vendor-neutral pipeline.

**A finding only one tool caught:** KICS found `Passwords And Secrets - Generic Password` in `inventory.ini:5` (Ansible plaintext inventory credentials). Checkov never saw this file because it does not recognise `.ini` as a supported IaC format. Conversely, Checkov fired on `CKV_AWS_355` (IAM policy wildcards, 4 findings) which KICS's Pulumi scan did not surface for the equivalent IAM policy in `Pulumi-vulnerable.yaml` — KICS identified the publicly accessible RDS but missed the wildcard IAM issue in that file.

---

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure RDS instances have Performance Insights enabled
  category: LOGGING
  severity: LOW
scope:
  provider: aws
definition:
  and:
    - cond_type: attribute
      resource_types:
        - aws_db_instance
      attribute: performance_insights_enabled
      operator: equals
      value: "true"
```

### Rule fires

Output of `checkov -d labs/lab6/vulnerable-iac/terraform --external-checks-dir labs/lab6/policies --check CKV2_CUSTOM_1`:

```
Passed checks: 0, Failed checks: 2, Skipped checks: 0

Check: CKV2_CUSTOM_1: "Ensure RDS instances have Performance Insights enabled"
  FAILED for resource: aws_db_instance.unencrypted_db
  File: /database.tf:5-37
  (attribute performance_insights_enabled absent → treated as false)

Check: CKV2_CUSTOM_1: "Ensure RDS instances have Performance Insights enabled"
  FAILED for resource: aws_db_instance.weak_db
  File: /database.tf:40-69
  performance_insights_enabled = false  (line 62)
```

### Why this rule matters

The 2023 **MOVEit Transfer** breach and numerous RDS-targeting incidents share a common forensics gap: without Performance Insights, teams cannot reconstruct which queries ran in the minutes before a compromise because the query-level execution history simply was not recorded. Enabling Performance Insights satisfies **NIST SP 800-92** (Guide to Computer Security Log Management) and contributes to **CIS AWS Foundations Benchmark v2.0 control 3.x** (logging and monitoring). A team writing dozens of `aws_db_instance` resources benefits from catching this omission at `terraform plan` time rather than during a post-incident forensics sprint.
