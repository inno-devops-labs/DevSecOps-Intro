# Lab 6 — Submission

## Scan environment

| Item | Value |
|---|---|
| Checkov | 3.3.5 |
| KICS | 2.1.20 (`checkmarx/kics:v2.1.20`) |
| Python | 3.13.14 |
| Docker | 26.1.3 |
| Git commit scanned | `7f777bf2b97dee0362254be52e4d9aba16948893` |
| Scan timestamp | 2026-07-02 21:48:15 UTC |

The scans completed and produced JSON/SARIF output. Checkov returned a non-zero status because policy violations were found; KICS likewise returned non-zero statuses corresponding to detected findings.

## Task 1: Checkov on Terraform

### Terraform scan — passed/failed per framework

| Framework | Passed | Failed |
|---|---:|---:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

The scan produced 80 failed-check records in total: 78 Terraform policy failures and 2 secret-detection failures.

### Top 5 rule IDs by frequency

The table below matches the `jq` expression from the lab instructions.

| Rule ID | Count | What it checks |
|---|---:|---|
| `CKV_AWS_289` | 4 | IAM policies must not allow permissions management or resource exposure without constraints. |
| `CKV_AWS_355` | 4 | IAM policy documents must not use `Resource: "*"` for actions that can be restricted to specific resources. |
| `CKV_AWS_23` | 3 | Security groups and security-group rules must include descriptions. |
| `CKV_AWS_288` | 3 | IAM policies must not permit data-exfiltration paths. |
| `CKV_AWS_290` | 3 | IAM policies must not allow write access without constraints. |

`CKV_AWS_382` also occurred three times, but it falls immediately after the five entries returned by the prescribed top-five query.

### Module-leverage analysis

The highest-leverage correction is to centralize the IAM policy documents in a reusable least-privilege module and replace wildcard actions/resources with the minimum required actions, explicit resource ARNs, and appropriate conditions. The same four IAM resources caused eight combined `CKV_AWS_289` and `CKV_AWS_355` failures; three of those resources also caused the three `CKV_AWS_288` and three `CKV_AWS_290` failures. One module-level correction can therefore eliminate up to 14 repeated findings instead of editing each policy attachment independently.

Affected IAM resources:

- `aws_iam_policy.admin_policy`
- `aws_iam_role_policy.s3_full_access`
- `aws_iam_user_policy.service_policy`
- `aws_iam_policy.privilege_escalation`

## Task 2: KICS on Ansible + Pulumi

The required severity tables count distinct query groups, matching the lab expression `[.queries[].severity]`. Individual finding totals are stated separately.

### Ansible — severity breakdown

| Severity | Query count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

At the individual-result level, KICS reported 10 Ansible findings: 9 HIGH and 1 LOW.

### Pulumi — severity breakdown

| Severity | Query count |
|---|---:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

Each Pulumi query produced one finding, for six findings in total.

### Top KICS queries — Ansible by frequency

Only four distinct query groups fired, so the table contains four rows rather than inventing a fifth result. The `Files` value is the length of each KICS `.files` array; repeated findings in one physical file are counted separately.

| Query | Severity | Files |
|---|---|---:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

Finding distribution by physical file:

| File | Findings |
|---|---:|
| `inventory.ini` | 5 |
| `deploy.yml` | 4 |
| `configure.yml` | 1 |

### Pulumi findings observed

| Query | Severity | Findings |
|---|---|---:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |
| EC2 Not EBS Optimized | INFO | 1 |

KICS scanned one Pulumi YAML file (`Pulumi-vulnerable.yaml`). The Python implementation was not included in the parsed Pulumi result set for this run.

### Checkov vs KICS — when to use which?

#### One thing Checkov did better for the Terraform sample

Checkov provided deeper Terraform-specific coverage in this run, including native resource-attribute checks, IAM-policy semantics, graph checks, and a separate secrets framework. Resource addresses and line ranges made it possible to group repeated IAM findings and identify one high-leverage least-privilege correction.

#### One thing KICS did better for the Ansible sample

KICS directly scanned the Ansible playbooks and inventory and detected password-like values, generic secrets, credentials embedded in URLs, and an unpinned package version. The lab's Checkov invocation was limited to Terraform, while KICS supplied direct coverage for the Ansible source files used in Task 2.

#### Equivalent risk found in different IaC formats

Checkov reported `CKV_AWS_17` against the Terraform RDS resource `aws_db_instance.unencrypted_db`. KICS reported `RDS DB Instance Publicly Accessible` with CRITICAL severity against the Pulumi YAML RDS resource. The underlying exposure is similar, but each scanner evaluated a different IaC representation with its own rule catalog.

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure every RDS instance is classified as restricted data"
  category: "CONVENTION"
  severity: "MEDIUM"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "tags.DataClassification"
  operator: "equals"
  value: "restricted"
```

### Rule fires

The custom-policy scan returned two failed checks:

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure every RDS instance is classified as restricted data",
    "check_result": "FAILED",
    "severity": "MEDIUM",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf",
    "file_line_range": [5, 37],
    "evaluated_keys": ["tags/DataClassification"]
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure every RDS instance is classified as restricted data",
    "check_result": "FAILED",
    "severity": "MEDIUM",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf",
    "file_line_range": [40, 69],
    "evaluated_keys": ["tags/DataClassification"]
  }
]
```

This proves that the custom policy was loaded and evaluated against both RDS instances. Neither resource defines `tags.DataClassification = "restricted"`.

### Why this rule matters

RDS resources may contain customer or application data. A mandatory machine-readable data-classification tag allows governance systems to apply differentiated access-control, retention, monitoring, and review workflows to restricted data. AWS tagging guidance explicitly presents data classification as a security and governance use case and lists values such as `Restricted`.

The rule also supports the intent of NIST SP 800-53 Rev. 5 control RA-2, Security Categorization, by making an infrastructure classification decision visible and auditable during IaC review. The tag does not satisfy RA-2 by itself; it is an enforceable implementation mechanism for an organization-defined categorization process.

References:

- AWS, *Best Practices for Tagging AWS Resources*: https://docs.aws.amazon.com/whitepapers/latest/tagging-best-practices/
- AWS, *Tags for data security, risk management, and access control*: https://docs.aws.amazon.com/whitepapers/latest/tagging-best-practices/tags-for-data-security-risk-management-and-access-control.html
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

## PR checklist body

```text
- [x] Task 1 — Checkov on Terraform with top-5 rules and module-leverage analysis
- [x] Task 2 — KICS on Ansible + Pulumi with Checkov-vs-KICS comparison
- [x] Bonus — Custom Checkov policy demonstrably firing on the vulnerable sample
```

