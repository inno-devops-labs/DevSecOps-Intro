# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

Severity: Checkov 3.3.1's open-source ruleset does not assign a `severity` field to most built-in checks unless a Bridgecrew/Prisma Cloud API key is connected — every failed check in this run returned `severity: null`. Rather than fabricate a severity table, the breakdown below uses rule frequency instead, which is what Checkov's own CLI output and Lecture 6 slide 17 use for triage.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policy does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy documents do not allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and rule has a description |
| CKV_AWS_288 | 3 | IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies do not allow write access without constraints |

Secrets scan (separate framework, same Terraform run): 2 failed — a hardcoded AWS access key in `main.tf:8` (`CKV_SECRET_2`) and a high-entropy password string in `database.tf:48` (`CKV_SECRET_6`).

### Pulumi scan
Checkov 3.x has no native `pulumi` framework for source-form Python/YAML, exactly as the lab's setup note predicts. Pointing `-d` at the Pulumi folder caused Checkov to fall back to its `kubernetes`, `ansible`, and `secrets` object-scanners, none of which understand Pulumi's resource schema — only the secrets scanner produced a real finding:

| Severity | Count |
|----------|------:|
| (no severity field — secrets framework only) | 1 failed |

The one finding: `CKV_SECRET_6` — a high-entropy string flagged as a likely secret, on `Pulumi-vulnerable.yaml:19` (`apiKey: "sk_liv..."`). Attempting `-f` against a rendered `pulumi-state-rendered.json` (suggested as a fallback in the lab) failed because no such file exists in this plumbing — confirming that real Pulumi coverage for this lab has to come from KICS, not Checkov.

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage fix in the top-5 is **CKV_AWS_289 / CKV_AWS_355** together — both fire on the same three IAM policy resources (`admin_policy`, `s3_full_access`, `privilege_escalation`) because each one uses `Action: "*"` or `Resource: "*"` in its policy document. If the organization enforced a single Terraform module for IAM policy creation that rejected wildcard actions/resources at the module boundary (e.g. via a `validation` block on the `actions` and `resources` input variables), all 4+4 = 8 occurrences across these two rules would disappear at once, since they share the exact same root cause rather than being eight independent misconfigurations.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | 10 |

### Top KICS queries — Ansible
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | 6 |

### Top KICS queries — Pulumi
| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| EC2 Not EBS Optimized | INFO | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which?

**Checkov did better on the Terraform sample**: it produced 78 distinct failed checks across IAM, RDS, S3, and security-group resources with rich per-check guidance (a Prismacloud documentation link for nearly every rule), giving much deeper and more granular coverage of AWS-specific misconfigurations than KICS would for the same HCL.

**KICS did better on the Ansible sample**: it directly understood the Ansible playbook format and found 9 HIGH-severity hardcoded-secret findings (passwords in plaintext vars, a password embedded in a Git URL, credentials in `inventory.ini`) — a format Checkov's open-source build does not have a dedicated Ansible-aware ruleset for beyond generic secret detection.

**Same resource type, only one tool caught it**: KICS flagged "RDS DB Instance Publicly Accessible" as CRITICAL on the Pulumi YAML resource, while Checkov's only signal on the equivalent Terraform `aws_db_instance.unencrypted_db` (same `publicly_accessible = true` pattern) was the unranked `CKV_AWS_17` check with no severity attached — same underlying misconfiguration, but only KICS's query gave it an actionable severity ranking out of the box.

---

## Bonus: Custom Checkov Policy

### Policy definition
`labs/lab6/policies/my-custom-policy.yaml`:
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure RDS instances have IAM database authentication enabled"
  category: "IAM"
  severity: "HIGH"
scope:
  provider: "aws"
definition:
  and:
    - cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "iam_database_authentication_enabled"
      operator: "equals"
      value: true
```

### Why this rule
The two RDS instances in `database.tf` already fail Checkov's built-in `CKV_AWS_161` ("Ensure RDS database has IAM authentication enabled") — this custom policy reimplements the same logical check from scratch as a graph-based check, to demonstrate writing a policy in Checkov's YAML DSL rather than relying on a built-in. An early version of this policy used a `filter` block (`cond_type: "filter"`) to first narrow down to `aws_db_instance` resources before applying the attribute check; Checkov 3.3.1 rejected this with `solver type SolverType.FILTER with operator equals is not supported`. The fix was to fold the resource-type scoping directly into the `attribute` condition via its `resource_types` list, which is the supported pattern for a single-condition graph check.

### Run command
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-custom/
```

### Verification
```bash
jq '.[0].results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))' \
  labs/lab6/results/checkov-custom/results_json.json
```

### Results
| Resource | File | Result | Severity |
|----------|------|--------|----------|
| `aws_db_instance.unencrypted_db` | database.tf:5-37 | FAILED | HIGH |
| `aws_db_instance.weak_db` | database.tf:40-69 | FAILED | HIGH |

Both RDS instances fail the custom check, confirming neither sets `iam_database_authentication_enabled = true`. Note that the custom policy's `severity: "HIGH"` field actually appears in the JSON output (`"severity": "HIGH"`), unlike every built-in check in Task 1's Terraform scan, which returned `severity: null` without a Bridgecrew API key — custom policies define their own severity directly in the policy file, so they bypass that limitation entirely.

---
