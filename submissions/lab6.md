# Lab 6 — Submission

## Environment

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
jq: jq-1.8.1-dirty
Checkov: 3.3.2
KICS image: checkmarx/kics:v2.1.20
```

The deliberately vulnerable files under `labs/lab6/vulnerable-iac/` were scanned but not modified.

## Task 1: Checkov on Terraform

### Scan totals

- Total evaluated checks: **80**
- Passed: **0**
- Failed: **80**
- Skipped: **0**
- Parsing errors: **0**

| Framework | Passed | Failed | Skipped |
|-----------|-------:|-------:|--------:|
| terraform | 0 | 78 | 0 |
| secrets | 0 | 2 | 0 |

### Failed checks by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |
| Unspecified | 80 |

`Unspecified` means the local open-source result did not include vendor severity metadata;
the rule and failure are still included in the frequency analysis.

### Top 5 rules by frequency

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| `CKV_AWS_355` | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| `CKV_AWS_23` | 3 | Ensure every security group and rule has a description |
| `CKV_AWS_288` | 3 | Ensure IAM policies does not allow data exfiltration |
| `CKV_AWS_290` | 3 | Ensure IAM policies does not allow write access without constraints |

### Module-leverage analysis

The highest-leverage module fix is **CKV_AWS_289**. It accounts for **4** failed resource checks, so enforcing its secure setting once in the shared Terraform module would remove every repeated instance and prevent callers from recreating the same weakness.

## Task 2: KICS on Ansible and Pulumi

### Ansible severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Pulumi severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

### Top 5 KICS queries

| Query | Severity | Findings | Platform |
|-------|----------|---------:|----------|
| Passwords And Secrets - Generic Password | HIGH | 6 | Ansible |
| Passwords And Secrets - Password in URL | HIGH | 2 | Ansible |
| DynamoDB Table Not Encrypted | HIGH | 1 | Pulumi |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 | Pulumi |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 | Pulumi |

### Checkov versus KICS

Checkov provided Terraform-native CKV identifiers, resource addresses, source ranges, and
graph-aware checks, making repeated Terraform failures easy to trace back to a reusable
module. This makes it especially effective for prioritizing one module-level remediation
that closes many resource-level findings.

KICS provided native Ansible and Pulumi parsing and query results rather than treating
those inputs as generic YAML or Python. Its broader IaC format coverage complements
Checkov's deeper Terraform-oriented policy catalog, so the two tools are best used as
format-specialized controls rather than interchangeable scanners.

## Bonus: Custom Checkov Policy

### Policy

```yaml
---
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure all taggable AWS resources declare a project ownership tag"
  category: "CONVENTION"
  severity: "MEDIUM"
  guideline: "Internal ownership standard: every taggable AWS resource must identify its project"
scope:
  provider: "aws"
definition:
  cond_type: "attribute"
  resource_types: "taggable"
  attribute: "tags.project"
  operator: "exists"
```

### Proof that the rule fires

The custom scan produced **12** failure(s). Representative evidence:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure all taggable AWS resources declare a project ownership tag",
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "file_line_range": [
    5,
    37
  ],
  "severity": "MEDIUM"
}
```

### Why this rule matters

A mandatory `tags.project` field connects each cloud resource to an owning system or team.
During an incident, missing ownership metadata delays containment and remediation because
responders cannot quickly identify who can safely assess or disable the resource. Enforcing
the tag before deployment also strengthens inventory, cost allocation, and decommissioning.

## Completion checklist

- [x] Checkov scanned the Terraform sample.
- [x] Real JSON generated all totals, severities, and top-rule counts.
- [x] KICS scanned both Ansible and Pulumi.
- [x] The module-level analysis identifies one concrete high-leverage remediation.
- [x] `CKV2_CUSTOM_1` was accepted and fired on at least one resource.
