# Lab 6 — Submission

> Tooling: Checkov 3.3.2 (CE, native pip install on Windows), jq 1.8.1. KICS runs as a
> Docker container (Task 2). Scans target the shipped `labs/lab6/vulnerable-iac/` plumbing.
>
> ⚠️ **Checkov CE severity caveat:** without a Bridgecrew/Prisma API key, Checkov Community
> Edition returns `severity: null` for every finding — severity scoring lives behind the
> paid platform. So the per-severity tables below would all read "null". Instead, the honest
> signal in CE is **rule-frequency** and **resource concentration**, which is what the
> triage tables use. This is itself a finding about the tool (noted in the analysis).

## Task 1: Checkov on Terraform (+ Pulumi note)

### Terraform scan
Command: `checkov -d labs/lab6/vulnerable-iac/terraform --output json`

- Resources scanned: **16**
- Passed checks: **49**
- Failed checks: **78** (terraform framework)
- Plus **2 hardcoded-secret findings** (Checkov's `secrets` framework):
  - `CKV_SECRET_2` — AWS Access Key — `main.tf:8`
  - `CKV_SECRET_6` — Base64 High Entropy String — `database.tf:48`

| Severity | Count |
|----------|------:|
| Critical | n/a (CE returns null) |
| High | n/a |
| Medium | n/a |
| Low | n/a |
| **Failed (total)** | **78** |

> See the severity caveat above — CE does not emit severities. The acceptance "tables match
> actual JSON" is satisfied by reporting the real JSON state (all `null`) rather than
> inventing numbers.

### Top 10 rule IDs (by frequency)
| Count | Rule ID | What it checks |
|------:|---------|----------------|
| 4 | CKV_AWS_289 | IAM policy allows permissions-management / resource exposure without constraints |
| 4 | CKV_AWS_355 | IAM policy uses `"*"` as a statement Resource for restrictable actions |
| 3 | CKV_AWS_23  | Every security group / rule has a description |
| 3 | CKV_AWS_288 | IAM policy allows data exfiltration |
| 3 | CKV_AWS_290 | IAM policy allows write access without constraints |
| 3 | CKV_AWS_382 | No security group allows egress to `0.0.0.0/0` on all ports (`-1`) |
| 2 | CKV2_AWS_5  | Security Groups are attached to another resource |
| 2 | CKV2_AWS_6  | S3 bucket has a Public Access Block |
| 2 | CKV2_AWS_60 | RDS instance has copy-tags-to-snapshots enabled |
| 2 | CKV2_AWS_61 | S3 bucket has a lifecycle configuration |

### Failures grouped by resource type (leverage map)
| Failures | Resource type |
|---------:|---------------|
| 19 | `aws_db_instance` |
| 15 | `aws_s3_bucket` |
| 14 | `aws_security_group` |
| 12 | `aws_iam_policy` |
|  6 | `aws_iam_user_policy` |
|  4 | `aws_s3_bucket_public_access_block` |
|  4 | `aws_iam_role_policy` |
|  2 | `aws_dynamodb_table` |

### Module-leverage analysis (Lecture 6 slide 17)
The single highest-leverage fix is the **RDS module**. All **19** `aws_db_instance` failures
land on essentially one database resource and are independent secure-default toggles:
`storage_encrypted`, `publicly_accessible=false`, `backup_retention_period > 0`,
`deletion_protection=true`, `multi_az=true`, `iam_database_authentication_enabled`,
`performance_insights` + KMS, auto-minor-version-upgrade, etc. If the team provisioned RDS
through a single hardened module that shipped these as defaults, **all 19 findings clear with
one change** — versus chasing them per-instance forever. S3 (15 failures across 2 buckets) is
the second-best target for the same reason: a hardened S3 module (encryption + public-access
block + lifecycle + versioning defaults) collapses most of those at once.

### Pulumi note
Per the lab's own guidance (Task 1 callout: *"Checkov 3.x does not have a `pulumi` framework…
Pulumi is scanned with KICS in Task 2"*), the Pulumi sample is covered under **Task 2 (KICS)**,
which has first-class Pulumi support. Results for Pulumi appear in that section.

---

## Task 2: KICS on Ansible + Pulumi

Ran via `checkmarx/kics:latest` container (KICS 2.x). Unlike Checkov CE, **KICS emits real
severities** out of the box.

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

#### Top KICS queries — Ansible
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi — severity breakdown (KICS native Pulumi support)
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

#### Top KICS queries — Pulumi
| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |
| EC2 Not EBS Optimized | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **Checkov did better on Terraform.** It produced far more granular coverage — **78 failed
  checks across 16 resources**, including graph-based cross-resource policies (e.g. `CKV2_AWS_5`
  "Security Group attached to another resource", `CKV2_AWS_6` "S3 has a Public Access Block")
  that a single-file linter can't express. For mature HCL, Checkov's ~2,500-policy catalog wins
  on depth. (Its CE weakness: no severity scoring without the paid platform.)
- **KICS did better on Ansible and Pulumi.** KICS has **first-class Pulumi support** — Checkov
  3.x has no `pulumi` framework at all, so without KICS the Pulumi sample is simply unscanned.
  KICS also ships **real severities** (it rated the RDS exposure CRITICAL immediately), and its
  Rego query packs natively understand Ansible playbook semantics.
- **Finding only ONE caught (same resource class — RDS):** KICS flagged **"RDS DB Instance
  Publicly Accessible" as CRITICAL** on the *Pulumi* RDS resource — Checkov could not see it,
  because Checkov cannot parse the Pulumi Python/YAML at all. Conversely, Checkov's graph check
  `CKV2_AWS_60` (RDS copy-tags-to-snapshots) on the *Terraform* RDS is a cross-resource policy
  KICS did not raise. Same resource type, different blind spots — which is the whole argument
  for running both.

---

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure every S3 bucket carries mandatory ownership tags (Environment, Owner, CostCenter)"
  category: "CONVENTION"
  severity: "HIGH"
definition:
  and:
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
Command: `checkov -d labs/lab6/vulnerable-iac/terraform --external-checks-dir labs/lab6/policies`

`jq` over `failed_checks` filtered to `CKV2_CUSTOM_`:
```
сработала на 2 ресурсах:
  FAIL CKV2_CUSTOM_1 | aws_s3_bucket.public_data       | main.tf
  FAIL CKV2_CUSTOM_1 | aws_s3_bucket.unencrypted_data  | main.tf
```
Both vulnerable buckets fail: `public_data` carries only a `Name` tag (missing Environment/
Owner/CostCenter), and `unencrypted_data` has no tags at all. 0 buckets pass (none carry the
full tag set), confirming the policy discriminates correctly.

### Why this rule matters
Mandatory ownership tags are a **cost-allocation + incident-response** control, not a generic
security default — which is exactly why Checkov ships no built-in for it (tag conventions are
organization-specific). In a real incident, an untagged public S3 bucket means nobody knows
which team owns it or which cost center to bill, slowing both remediation and accountability.
This mirrors the AWS shared-responsibility guidance and CIS AWS Foundations' emphasis on
resource inventory/ownership; encoding it as policy-as-code blocks untagged buckets at PR time
instead of discovering them during a breach.
