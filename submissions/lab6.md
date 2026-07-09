# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 34 | 57 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policy allows permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy document allows `"*"` as the resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group / rule should have a description |
| CKV_AWS_288 | 3 | IAM policy allows data exfiltration |
| CKV_AWS_290 | 3 | IAM policy allows write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)
All four of the top-5 IAM rules (CKV_AWS_289/355/288/290) fire on the exact same root cause across
four different resources in `iam.tf` — `aws_iam_policy.admin_policy`, `aws_iam_role_policy.s3_full_access`,
`aws_iam_user_policy.service_policy`, and `aws_iam_policy.privilege_escalation` — because every one of them
attaches a policy document with `Action: "*"` / `Resource: "*"`. If the shared IAM policy module dropped the
wildcard and scoped `Action`/`Resource` to what each principal actually needs, CKV_AWS_289, 355, 288, and 290
would collapse from 14 findings across 4 resources into a single fix applied once at the module level.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **Checkov did better on the Terraform sample.** It ran 10 distinct, narrowly-scoped RDS checks against
  `aws_db_instance.unencrypted_db` alone (encryption, public access, backups, deletion protection, Multi-AZ,
  IAM auth, monitoring, minor-version upgrades, performance insights, logging) — a level of granularity that
  makes triage-by-rule-frequency genuinely useful.
- **KICS did better on the Ansible sample**, for the simple reason that Checkov has no Ansible framework at
  all — KICS was the only tool of the two that could scan the playbooks, catching hardcoded passwords, a
  password embedded in a URL, and an unpinned package version.
- **Same resource type, different depth:** both the Terraform and Pulumi samples define an unencrypted,
  publicly-accessible RDS instance. Checkov (Terraform) flagged both `storage_encrypted = false`
  (CKV_AWS_16) and `publicly_accessible = true` (CKV_AWS_17) as two separate findings. KICS (Pulumi) only
  fired one query for the equivalent resource — "RDS DB Instance Publicly Accessible" (CRITICAL) — with no
  corresponding query for the unencrypted storage, even though the Pulumi YAML sets `storageEncrypted: false`
  right next to it. That's a concrete case of Checkov's Terraform catalog being deeper than KICS's Pulumi
  catalog for the same resource type.

---

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure S3 buckets are tagged with Environment, Owner, and CostCenter for cost allocation and incident ownership"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      value:
        - "aws_s3_bucket"
      operator: "within"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.Environment"
      operator: "exists"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.Owner"
      operator: "exists"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "tags.CostCenter"
      operator: "exists"
```

### Rule fires
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-custom/

jq '[.[].results.failed_checks[]?]
    | map(select(.check_id | startswith("CKV2_CUSTOM_")))' \
  labs/lab6/results/checkov-custom/results_json.json
```

Output (trimmed to the essentials):
```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets are tagged with Environment, Owner, and CostCenter for cost allocation and incident ownership",
    "check_result": { "result": "FAILED" },
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf",
    "severity": "MEDIUM"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets are tagged with Environment, Owner, and CostCenter for cost allocation and incident ownership",
    "check_result": { "result": "FAILED" },
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf",
    "severity": "MEDIUM"
  }
]
```

Both `aws_s3_bucket.public_data` and `aws_s3_bucket.unencrypted_data` fail because neither sets
`Environment`, `Owner`, or `CostCenter` tags — `main.tf` even leaves a comment on the first bucket saying
exactly that ("Missing required tags: Environment, Owner, CostCenter").

### Why this rule matters
Untagged cloud resources are a recurring root cause in real incident retrospectives and cost audits:
without an `Owner` tag, nobody gets paged when a resource is misconfigured or breached; without a
`CostCenter` tag, orphaned/forgotten resources (like this sample's public S3 bucket) rack up cost and
attack surface with no accountable team. This maps to the tagging/asset-inventory expectations in the
CIS AWS Foundations Benchmark and is the kind of organization-specific governance rule that Checkov's
generic catalog doesn't ship — it only makes sense once a company decides on its own mandatory tag
schema, which is exactly what custom Policy-as-Code is for.
