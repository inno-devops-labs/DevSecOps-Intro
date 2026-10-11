# Lab 6 - Submission

## Task 1: Checkov on Terraform

Command used:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

Checkov version: `3.3.2`.

### Terraform scan (passed/failed per framework)

| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management or resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure IAM policy documents do not allow `*` as a statement resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and security group rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)

The highest-leverage module-level change is to centralize IAM policy generation and block broad wildcard permissions by default. The top IAM rules (`CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290`) account for 14 findings together, so enforcing scoped actions, scoped resource ARNs, and required conditions in one shared IAM policy pattern would remove the largest cluster of repeated findings. Security group descriptions would also be useful, but that would only address the three `CKV_AWS_23` findings.

## Task 2: KICS on Ansible + Pulumi

Commands used:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ \
       -o /path/results/kics-ansible/ \
       --report-formats json,sarif

docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/pulumi/ \
       -o /path/results/kics-pulumi/ \
       --report-formats json,sarif
```

KICS version: `2.1.20`.

### Ansible - severity breakdown

KICS summary reported 10 total findings. The table below uses the lab-provided `.queries[].severity` grouping.

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi - severity breakdown

KICS summary reported 6 total findings. The table below uses the lab-provided `.queries[].severity` grouping.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries - Ansible (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS - when to use which? (Lecture 6 slide 10)

Checkov did better on the Terraform sample because it has deep native HCL support and AWS-specific graph checks. The Terraform results were especially useful for module-level triage: repeated IAM findings made it clear that a shared least-privilege policy pattern would eliminate many findings at once.

KICS did better on the Ansible sample because it understands Ansible playbooks and inventory-style configuration directly. It caught secrets, password-in-URL patterns, generic secret patterns, and unpinned packages in files that Checkov was not used to scan in this lab.

For overlapping resource types, KICS caught Pulumi findings such as `RDS DB Instance Publicly Accessible` and `DynamoDB Table Not Encrypted` in Pulumi YAML. Checkov was intentionally scoped to Terraform here, so it provided stronger Terraform analysis while KICS provided broader format coverage for Pulumi and Ansible.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 buckets define lifecycle configuration
  category: BACKUP_AND_RECOVERY
  severity: MEDIUM
definition:
  and:
    - cond_type: filter
      attribute: resource_type
      operator: within
      value:
        - aws_s3_bucket
    - cond_type: connection
      resource_types:
        - aws_s3_bucket
      connected_resource_types:
        - aws_s3_bucket_lifecycle_configuration
      operator: exists
```

### Rule fires

Output of the B.4 jq command:

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets define lifecycle configuration",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf",
    "file_line_range": [
      13,
      21
    ],
    "severity": "MEDIUM"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets define lifecycle configuration",
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf",
    "file_line_range": [
      24,
      33
    ],
    "severity": "MEDIUM"
  }
]
```

### Why this rule matters

S3 lifecycle configuration helps enforce data retention and expiration rules instead of allowing stale objects to remain indefinitely. That matters for privacy, breach impact reduction, and data minimization: incidents such as the Capital One S3 data exposure show how cloud storage misconfiguration can turn retained data into a high-impact exposure. The rule also supports governance expectations similar to NIST SP 800-53 controls around information retention and system information management.
