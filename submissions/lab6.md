# Lab 6 — IaC Security: Checkov + KICS + a Custom Policy

## Environment

* Checkov: `3.3.1`
* KICS: `2.1.20`
* Docker: `29.5.2`
* jq: `1.8.1`

## Task 1: Checkov on Terraform

### Terraform scan

Command used:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli \
  --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

* Total checks: 127
* Passed: 49
* Failed: 78
* Skipped: 0
* Parsing errors: 0
* Resources scanned: 16

### Severity breakdown

| Severity | Count |
| -------- | ----: |
| UNKNOWN  |    78 |

The local Checkov JSON output did not include severity values for Terraform findings without a Prisma Cloud API key, so all 78 failed checks were reported as `UNKNOWN`. I did not assign severities manually.

### Top 5 rule IDs by frequency

| Rule ID       | Count | What it checks                                                                              |
| ------------- | ----: | ------------------------------------------------------------------------------------------- |
| `CKV_AWS_289` |     4 | IAM policies must not allow permissions management or resource exposure without constraints |
| `CKV_AWS_355` |     4 | IAM policy documents must not use `Resource: "*"` for restrictable actions                  |
| `CKV_AWS_23`  |     3 | Every security group and security-group rule must have a description                        |
| `CKV_AWS_288` |     3 | IAM policies must not allow unconstrained data exfiltration                                 |
| `CKV_AWS_290` |     3 | IAM policies must not allow unconstrained write access                                      |

### Module-leverage analysis

The highest-leverage fix is to replace the overly permissive IAM policy definitions with a least-privilege policy module. The module should allow only the required actions and specific resource ARNs instead of wildcard `Action: "*"` and `Resource: "*"`. This would address several frequent IAM findings at once, including `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290`.

## Task 2: KICS on Ansible and Pulumi

### Ansible scan

Command used:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan \
  -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ \
  --report-formats json,sarif
```

### Severity breakdown

| Severity  |  Count |
| --------- | -----: |
| CRITICAL  |      0 |
| HIGH      |      9 |
| MEDIUM    |      0 |
| LOW       |      1 |
| INFO      |      0 |
| **Total** | **10** |

### Top KICS queries by frequency

| Query                                    | Severity | Files |
| ---------------------------------------- | -------- | ----: |
| Passwords And Secrets - Generic Password | HIGH     |     6 |
| Passwords And Secrets - Password in URL  | HIGH     |     2 |
| Passwords And Secrets - Generic Secret   | HIGH     |     1 |
| Unpinned Package Version                 | LOW      |     1 |

KICS found hardcoded credentials in playbooks and inventory files, credentials embedded in a database connection string and Git URL, and an unpinned package version using `state: latest`.

### Pulumi scan

Command used:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan \
  -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ \
  --report-formats json,sarif
```

### Pulumi severity breakdown

| Severity  | Count |
| --------- | ----: |
| CRITICAL  |     1 |
| HIGH      |     2 |
| MEDIUM    |     1 |
| LOW       |     0 |
| INFO      |     2 |
| **Total** | **6** |

### Pulumi findings

| Query                                          | Severity | Files |
| ---------------------------------------------- | -------- | ----: |
| RDS DB Instance Publicly Accessible            | CRITICAL |     1 |
| DynamoDB Table Not Encrypted                   | HIGH     |     1 |
| Passwords And Secrets - Generic Password       | HIGH     |     1 |
| EC2 Instance Monitoring Disabled               | MEDIUM   |     1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO     |     1 |
| EC2 Not EBS Optimized                          | INFO     |     1 |

### Checkov vs KICS — when to use which?

**Checkov for Terraform.** Checkov was more useful for the Terraform sample because it detected 78 IaC findings across S3, IAM, security groups, RDS, and other AWS resources. It also includes graph-based checks that can evaluate relationships between resources, which is useful for Terraform modules and cloud architecture.

**KICS for Ansible.** KICS was more useful for the Ansible sample because it natively analyzed playbooks, inventory files, and generic secret patterns. It detected hardcoded passwords, secrets in URLs, credentials in inventory, and an unpinned package version.

**KICS for Pulumi.** KICS also scanned the Pulumi YAML source directly and found a publicly accessible RDS instance, an unencrypted DynamoDB table, and a hardcoded password. This demonstrates KICS's broader source-format coverage for YAML-based IaC.

## Bonus: Custom Checkov Policy

### Policy file

File: `labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  name: "Ensure taggable AWS resources have an Environment tag"
  id: "CKV2_CUSTOM_1"
  category: "CONVENTION"
  severity: "MEDIUM"

scope:
  provider: aws

definition:
  cond_type: "attribute"
  resource_types: "taggable"
  attribute: "tags.Environment"
  operator: "exists"
```

### Custom-policy scan

Command used:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli \
  --output json \
  --output-file-path labs/lab6/results/checkov-custom/
```

### Rule fires

The custom rule successfully failed on 12 Terraform resources that did not define the required `Environment` tag.

Example output:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure taggable AWS resources have an Environment tag",
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "file_line_range": [
    5,
    37
  ]
}
```

The policy also fired for both S3 buckets, all three security groups, both RDS instances, the DynamoDB table, and several IAM resources.

### Why this rule matters

The `Environment` tag distinguishes production resources from development and staging resources. This makes it possible to apply different backup, logging, retention, access-control, and incident-response requirements to each environment. The rule turns an organizational tagging convention into a CI-enforced control and supports configuration-management and component-inventory objectives such as NIST SP 800-53 CM-8.

