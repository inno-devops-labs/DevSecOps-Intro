# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: <127>
- Passed: <49>
- Failed: <78>

| Severity | Count |
|----------|------:|
| Critical | <-> |
| High | <-> |
| Medium | <-> |
| Low | <-> |

In Checkov 3.3.1 OSS, `severity` is `null` for all 78 failed checks — `jq '[.[] | select(.check_type=="terraform") | .results.failed_checks[].severity] | group_by(.) | ...'` returns `[{"severity": null, "count": 78}]`. Severity values are only populated when running Checkov against a Prisma Cloud API key -> I can not fill the table

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| <CKV_AWS_289> | <4> | <Ensure IAM policies does not allow permissions management> |
| <CKV_AWS_355> | <4> | <Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions> |
| <CKV_AWS_23> | <3> | <Ensure every security group and rule has a description> |
| <CKV_AWS_288> | <3> | <Ensure IAM policies does not allow data exfiltration> |
| <CKV_AWS_290> | <3> | <Ensure IAM policies does not allow write access without constraints> |

### Pulumi scan
| Severity | Count |
|----------|------:|
| ... |
- Total checks: 1 passed + 1 failed (`secrets` framework only)
- The Python source (`__main__.py`) was not analyzed as IaC: as the assignment notes, "Checkov 3.x does not have a pulumi framework directly". Only `Pulumi-vulnerable.yaml` was matched by the secrets scanner.
- The single Pulumi finding was `CKV_SECRET_6: Base64 High Entropy String` on `Pulumi-vulnerable.yaml:19-20` (hardcoded `apiKey: "sk_liv********"`).

### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the S3 module had `block_public_acls = true` as default,
the 8 findings of CKV_AWS_56 would all go away.")
If aws_iam_policy.admin_policy in iam.tf had explicit Action and Resource lists instead of "*", 9 findings would all go away at once (CKV_AWS_288, CKV_AWS_290, CKV_AWS_287, CKV_AWS_63, CKV_AWS_289, CKV_AWS_62, CKV_AWS_355, CKV_AWS_286, CKV2_AWS_40 — verified via `jq '[.[] | select(.check_type=="terraform") | .results.failed_checks[] | select(.resource=="aws_iam_policy.admin_policy") | .check_id]'`). That single fix closes 4 of the 5 top rules in the table above and ~12% of the Terraform findings — the slide-17 module-leverage pattern.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | <9> |
| MEDIUM | <0> |
| LOW | <1> |
| INFO | <0> |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| <Passwords And Secrets - Generic Password> | <HIGH> | <6> |
| <Passwords And Secrets - Password in URL> | <HIGH> | <2> |
| <Passwords And Secrets - Generic Secret> | <HIGH> | <1> |
| <Unpinned Package Version> | <LOW> | <1> |
There is no 5th query for this sample

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample
Checkov produced 78 distinct Terraform findings on 16 resources, including 4 graph-based CKV_AWS_3xx rules in the top 5 (IAM policy semantics — data exfiltration, write-without-constraints, permissions-management without constraints) that span policy-document fields rather than single attributes.
- One thing KICS did **better** for the Ansible sample
KICS scanned ansible/ natively and surfaced 10 findings, including 9 HIGH-severity secret patterns across the 3 files in ansible/ (Generic Password, Password in URL, Generic Secret) without any extra configuration, because Ansible is a first-class input format for KICS rather than an add-on.
- (Optional) An example of a finding only ONE of them caught for the same resource type
KICS on the same file caught 6 findings, including 1 CRITICAL (RDS DB Instance Publicly Accessible) and 1 HIGH (DynamoDB Table Not Encrypted) — i.e. the "wider language coverage" point from slide 10 in practice: KICS parsed the Pulumi YAML as an IaC document

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
<metadata:
  id: CKV2_CUSTOM_1
  name: "RDS: IAM auth required"
  category: IAM
  severity: HIGH
definition:
  cond_type: attribute
  resource_types:
    - aws_db_instance
  attribute: iam_database_authentication_enabled
  operator: equals
  value: true>
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```
<(adapted to the array-shape JSON of Checkov 3.3.1, as documented in Task 1, the working command is `jq '.[] | select(.check_type=="terraform") | .results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`):
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "RDS: IAM auth required",
  "check_result": { "result": "FAILED", "evaluated_keys": ["iam_database_authentication_enabled"] },
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "file_line_range": [5, 37],
  "severity": "HIGH"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "RDS: IAM auth required",
  "check_result": { "result": "FAILED", "evaluated_keys": ["iam_database_authentication_enabled"] },
  "resource": "aws_db_instance.weak_db",
  "file_path": "/database.tf",
  "file_line_range": [40, 69],
  "severity": "HIGH"
}>
```

### Why this rule matters
2-3 sentences: what real-world incident or compliance requirement does your custom policy address?
(References to specific incidents or NIST/CIS controls strengthen the answer.)
RDS IAM database authentication replaces static passwords with short-lived IAM-issued tokens, which removes the class of incidents where a leaked database password becomes a long-term breach (Capital One 2019 is the canonical example of credentials-in-config failure). This rule maps directly to AWS Foundational Security Best Practices control RDS.12 ("IAM authentication should be configured for RDS clusters") and to NIST SP 800-53 IA-2 (Identification and Authentication of Organizational Users). For our fork, which already ships hardcoded passwords in `database.tf` (`SuperSecretPassword123!`, `password123`), this rule is a project-specific guardrail against repeating the same pattern.