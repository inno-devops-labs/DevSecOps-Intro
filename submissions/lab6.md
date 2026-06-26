# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 129 (49 passed + 80 failed)
- Passed: 49
- Failed: 80
- Resources scanned: 18

Checkov's free tier (no API key) does not populate the `severity` field in JSON output — all 80 failed checks return `severity: null`. The findings below are therefore grouped by rule frequency rather than severity, which is the more useful triage axis anyway (Lecture 6 slide 17).

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policies must not use `"*"` as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and rule must have a description |
| CKV_AWS_288 | 3 | IAM policies must not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies must not allow write access without constraints |

### Notable individual findings
- **CKV_AWS_41** — hardcoded AWS access key + secret key in provider block
- **CKV_SECRET_2** — AWS Access Key detected by secret scanner
- **CKV_AWS_20** — S3 bucket with public-read ACL
- **CKV_AWS_24 / CKV_AWS_25** — SSH (22) and RDP (3389) open to 0.0.0.0/0
- **CKV_AWS_16** — RDS storage not encrypted at rest
- **CKV_AWS_17** — RDS instance publicly accessible
- **CKV_AWS_62 / CKV_AWS_63** — IAM policies granting full `*:*` admin privileges

### Pulumi scan (via KICS — see note)
Checkov 3.x has no native `pulumi` framework (Pulumi is real Python; Checkov expects rendered state or its SAST-Python framework). Per the lab instructions, Pulumi was scanned with **KICS**, which has first-class Pulumi YAML support. Results in Task 2 below.

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage single fix is on the **IAM policy module**. The top two rules — CKV_AWS_289 (4×) and CKV_AWS_355 (4×) — plus CKV_AWS_288 (3×) and CKV_AWS_290 (3×) all stem from the same root cause: IAM policy documents using wildcard `Action: "*"` and `Resource: "*"`. All 14 of these findings trace back to a handful of overly-broad policy documents in `iam.tf`. Replacing the wildcards with scoped actions and explicit resource ARNs at the policy-definition level would clear roughly 14 findings at once — far more leverage than fixing any single S3 or RDS resource, which each only resolve 1-2 findings.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible severity breakdown
- Total findings: 9 (8 HIGH, 1 LOW)

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 8 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top KICS queries — Ansible
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Unpinned Package Version | LOW | 1 |

### Pulumi severity breakdown (KICS)
- Total findings: 6 (1 CRITICAL, 2 HIGH, 1 MEDIUM, 2 INFO)

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |
| EC2 Not EBS Optimized | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for Terraform:** Checkov found 80 failed checks across 49 distinct rules on the Terraform sample, including deep IAM policy analysis (data exfiltration, privilege escalation, permissions-management paths via CKV_AWS_288/286/289). Its Terraform/HCL coverage is far denser than KICS's — it understands graph relationships between resources (CKV2_* cross-resource checks like "security group attached to a resource") that a single-file scanner misses.

**One thing KICS did better for Ansible:** KICS natively understands Ansible playbook semantics and caught 9 findings where Checkov's `--framework ansible` found only 1. KICS's secret-detection queries ("Generic Password" across 6 files, "Password in URL" across 2) correctly parsed the playbook variable structure and connection strings, while Checkov barely recognized the format.

**A finding only one tool caught (same resource type — RDS):** For the RDS instances, Checkov caught `CKV_AWS_16` (storage not encrypted) and `CKV_AWS_17` (publicly accessible) on the Terraform RDS, while KICS independently flagged "RDS DB Instance Publicly Accessible" as CRITICAL on the Pulumi RDS. The public-accessibility issue was caught by both tools across the two formats, but Checkov's encryption-at-rest check (CKV_AWS_16) had no KICS equivalent firing on the same Terraform resource — KICS only surfaced encryption issues on the DynamoDB table, not the RDS instance, demonstrating divergent rule coverage even for the same vulnerability class.

---

## Bonus: Custom Checkov Policy

### Policy file (labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure RDS instances have IAM database authentication enabled"
  category: "IAM"
  severity: "HIGH"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      value:
        - "aws_db_instance"
      operator: "within"
    - cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "iam_database_authentication_enabled"
      operator: "equals"
      value: true
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
{
  "check_id": "CKV2_CUSTOM_1",
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "resource": "aws_db_instance.weak_db",
  "file_path": "/database.tf"
}
```
The policy fires on both RDS instances in the sample — neither sets `iam_database_authentication_enabled`, so both fail the check.

### Why this rule matters
IAM database authentication eliminates long-lived database passwords by issuing short-lived (15-minute) auth tokens tied to AWS IAM identities, so credentials can't be leaked, committed to git, or reused after an employee leaves. This directly addresses **CIS AWS Foundations Benchmark control 2.3.1** (ensure encryption and access control on RDS) and the credential-management failures behind real breaches like the 2019 Capital One incident, where over-permissioned access to AWS resources exposed 100M+ records. Checkov ships no built-in rule requiring IAM DB auth specifically, making this a legitimate organization-specific policy: a company mandating passwordless RDS access across all accounts would enforce exactly this check in CI to block any Terraform that provisions a database with traditional password auth.