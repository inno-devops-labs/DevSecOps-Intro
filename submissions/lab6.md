# Lab 6 - Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

Command run:

```bash
docker run --rm -v "$PWD:/work" bridgecrew/checkov:latest \
  -d /work/labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path /work/labs/lab6/results/checkov-terraform/
```

- Checkov version: 3.3.2
- Total Terraform checks: 127
- Passed: 49
- Failed: 78
- Additional secrets findings from the same Checkov run: 2

Checkov CE did not populate built-in Terraform severity metadata in the local JSON output, so the severity values below reflect the actual JSON fields.

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unspecified | 78 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | IAM policies must not allow permissions management or resource exposure without constraints |
| `CKV_AWS_355` | 4 | IAM policy statements must not use `Resource: "*"` for restrictable actions |
| `CKV_AWS_23` | 3 | Security groups and rules should include descriptions |
| `CKV_AWS_288` | 3 | IAM policies must not allow data exfiltration |
| `CKV_AWS_290` | 3 | IAM policies must not allow unconstrained write access |

### Pulumi scan

Checkov 3.3.2 completed against the Pulumi directory, but it treated the Pulumi YAML primarily as a secrets scan rather than performing first-class Pulumi IaC analysis.

| Tool | Scope | Passed | Failed | Notes |
|------|-------|-------:|-------:|-------|
| Checkov | Pulumi directory secrets scan | 0 | 1 | Found `CKV_SECRET_6` in `Pulumi-vulnerable.yaml:19` |
| KICS | Pulumi IaC scan | n/a | 6 results | First-class Pulumi YAML analysis; details in Task 2 |

### Module-leverage analysis (Lecture 6 slide 17)

The highest-leverage Terraform fix is to harden IAM policy generation at the module level. `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290` all point at the same underlying pattern: policies are being generated with wildcard resources/actions or unconstrained privilege. If the IAM module rejected `Resource: "*"` and broad write/permissions-management actions by default, it would eliminate most of the top-frequency findings in one design change.

## Task 2: KICS on Ansible + Pulumi

### KICS on Ansible

Command run:

```bash
docker run --rm -v "$PWD/labs/lab6:/path" checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ \
       -o /path/results/kics-ansible/ \
       --report-formats json,sarif
```

### Severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Top KICS queries (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### KICS on Pulumi

Command run:

```bash
docker run --rm -v "$PWD/labs/lab6:/path" checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/pulumi/ \
       -o /path/results/kics-pulumi/ \
       --report-formats json,sarif
```

### Pulumi severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

### Top Pulumi KICS queries

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS - when to use which?

Checkov was better for the Terraform sample because it produced deep AWS/Terraform policy coverage and graph-style findings across IAM, S3, RDS, DynamoDB, security groups, and secrets. The top-frequency output is useful for module-level triage: it quickly showed that IAM policy generation is the highest-leverage area.

KICS was better for the Ansible sample because it recognized playbook/inventory patterns directly and grouped operational risks such as hardcoded passwords, password-in-URL, and unpinned package versions. This is useful for configuration-management reviews where the risk is often in tasks, inventory variables, and command usage rather than cloud resource graphs.

For Pulumi, KICS was the stronger fit in this lab. Checkov completed a secrets-oriented scan and found one secret-like value, while KICS parsed the Pulumi YAML IaC model and found cloud-resource issues such as public RDS, unencrypted DynamoDB, disabled EC2 monitoring, and disabled DynamoDB point-in-time recovery.

## Bonus: Custom Checkov Policy

### Policy file

`labs/lab6/policies/my-custom-policy.yaml`:

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 buckets include a CostCenter tag"
  category: "CONVENTION"
  severity: "MEDIUM"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.CostCenter"
  operator: "exists"
```

### Rule fires

Command run:

```bash
docker run --rm -v "$PWD:/work" bridgecrew/checkov:latest \
  -d /work/labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir /work/labs/lab6/policies \
  --output cli --output json \
  --output-file-path /work/labs/lab6/results/checkov-custom/
```

Output of:

```bash
jq '[.[] | select(.check_type=="terraform") | .results.failed_checks[] |
  select(.check_id | startswith("CKV2_CUSTOM_")) |
  {check_id, check_name, resource, file_path, file_line_range, severity}]' \
  labs/lab6/results/checkov-custom/results_json.json
```

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets include a CostCenter tag",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf",
    "file_line_range": [13, 21],
    "severity": "MEDIUM"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets include a CostCenter tag",
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf",
    "file_line_range": [24, 33],
    "severity": "MEDIUM"
  }
]
```

### Why this rule matters

Mandatory ownership and cost-allocation tags support inventory, accountability, and incident response: teams can quickly identify who owns a bucket and which budget or application it belongs to. This aligns with governance expectations behind CIS Controls v8 Control 1 (enterprise asset inventory) and NIST SP 800-53 CM-8 (system component inventory). Without tags such as `CostCenter`, orphaned storage can persist unnoticed, increasing cost, data-exposure, and incident-response time.
