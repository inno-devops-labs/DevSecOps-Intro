# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Total checks: 129
- Passed: 49
- Failed: 80

Checkov's free tier (no API key) does not populate the severity field in JSON output — all 80 failed checks return severity: null.

| Severity | Count (estimated) |
| -------- | ----------------: |
| Critical |              null |
| High     |              null |
| Medium   |              null |
| Low      |              null |

### Top 5 rule IDs (by frequency)

| Rule ID     | Count | What it checks                                                                             |
| ----------- | ----: | ------------------------------------------------------------------------------------------ |
| CKV_AWS_289 |     4 | IAM policies must not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 |     4 | IAM policy statements must not use `"*"` as Resource for restrictable actions              |
| CKV_AWS_23  |     3 | Every security group and rule must have a description                                      |
| CKV_AWS_288 |     3 | IAM policies must not allow data exfiltration actions without constraints                  |
| CKV_AWS_290 |     3 | IAM policies must not allow write access without resource constraints                      |

### Pulumi scan

Pulumi was scanned with **KICS** (see Task 2) — Checkov 3.x does not natively parse Pulumi Python or YAML without `pulumi preview --json` state; KICS has first-class Pulumi YAML support.

KICS scan of `Pulumi-vulnerable.yaml`:

| Severity  | Count |
| --------- | ----: |
| Critical  |     1 |
| High      |     2 |
| Medium    |     1 |
| Low       |     0 |
| Info      |     2 |
| **Total** | **6** |

### Module-leverage analysis (Lecture 6 slide 17)

Four of the top five rules target the same wildcard pattern — `Action: "*"` or `Resource: "*"` — copied across four IAM policies (`admin_policy`, `privilege_escalation`, `s3_full_access`, and `service_policy`). Instead of patching each one individually, a shared IAM module with least-privilege defaults (wildcards rejected at the interface, explicit action lists required) would collapse all related findings into a single module fix.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown

| Severity  |  Count |
| --------- | -----: |
| Critical  |      0 |
| High      |      9 |
| Medium    |      0 |
| Low       |      1 |
| Info      |      0 |
| **Total** | **10** |

### Top KICS queries — Ansible

| Query                                    | Severity | Files |
| ---------------------------------------- | -------- | ----: |
| Passwords And Secrets - Generic Password | HIGH     |     6 |
| Passwords And Secrets - Password in URL  | HIGH     |     2 |
| Passwords And Secrets - Generic Secret   | HIGH     |     1 |
| Unpinned Package Version                 | LOW      |     1 |

### Pulumi severity breakdown (KICS)

| Query                                          | Severity | Files |
| ---------------------------------------------- | -------- | ----: |
| RDS DB Instance Publicly Accessible            | CRITICAL |     1 |
| DynamoDB Table Not Encrypted                   | HIGH     |     1 |
| Passwords And Secrets - Generic Password       | HIGH     |     1 |
| EC2 Instance Monitoring Disabled               | MEDIUM   |     1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO     |     1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- One thing Checkov did **better** for the Terraform sample: Checkov stood out on Terraform with 80 failures spanning 49 distinct rules, going well beyond surface-level misconfigs. It dug into IAM policies — flagging privilege escalation, data exfiltration, and wildcard permissions — and leveraged graph queries (CKV2\_\*) to connect resources across files, something KICS's file-at-a-time approach misses entirely.

- One thing KICS did **better** for the Ansible sample: KICS showed a clear edge with Ansible — 9 findings to Checkov's 1. The difference came down to native format support: KICS parsed playbook variables and connection strings correctly, letting its secret-detection rules flag passwords spread across 6 files and URL-embedded credentials in 2 more. Checkov's `--framework ansible` never really understood what it was looking at.

- An example of a finding only ONE of them caught for the same resource type: RDS exposed a telling coverage gap. Both scanners caught the publicly accessible instance, just on different IaC formats. But when it came to encryption at rest, only Checkov fired — KICS had no equivalent rule for RDS, though it did flag encryption issues on DynamoDB. So even within the same vulnerability category, the two tools' rule sets didn't fully overlap, leaving blind spots that a single-tool approach would miss.

---

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 bucket has lifecycle configuration"
  category: "GENERAL_SECURITY"
  severity: MEDIUM
definition:
  and:
    - cond_type: filter
      attribute: resource_type
      value:
        - aws_s3_bucket
      operator: within
    - cond_type: attribute
      attribute: lifecycle_rule
      resource_types:
        - aws_s3_bucket
      operator: exists
      value: true
```

### Rule fires

Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))' labs/lab6/results/checkov-custom/results_json.json`:

```
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "bc_check_id": null,
    "check_name": "Ensure S3 bucket has lifecycle configuration",
    "check_result": {
      "result": "FAILED",
      "entity": {
        "aws_s3_bucket": {
          "public_data": {
            "__end_line__": 21,
            "__start_line__": 13,
            "acl": [
              "public-read"
            ],
            "bucket": [
              "my-public-bucket-lab6"
            ],
            "tags": [
              {
                "Name": "Public Data Bucket"
              }
            ],
            "__address__": "aws_s3_bucket.public_data",
            "__provider_address__": "aws.default"
          }
        }
      },
      "evaluated_keys": [
        "resource_type",
        "lifecycle_rule"
      ]
    },
    "code_block": [
      [
        13,
        "resource \"aws_s3_bucket\" \"public_data\" {\n"
      ],
      [
        14,
        "  bucket = \"my-public-bucket-lab6\"\n"
      ],
      [
        15,
        "  acl    = \"public-read\"  # Public access enabled!\n"
      ],
      [
        16,
        "\n"
      ],
      [
        17,
        "  tags = {\n"
      ],
      [
        18,
        "    Name = \"Public Data Bucket\"\n"
      ],
      [
        19,
        "    # Missing required tags: Environment, Owner, CostCenter\n"
      ],
      [
        20,
        "  }\n"
      ],
      [
        21,
        "}\n"
      ]
    ],
    "file_path": "/main.tf",
    "file_abs_path": "/mnt/c/Users/verdr/OneDrive/Belgeler/DevSecOps/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf",
    "repo_file_path": "/labs/lab6/vulnerable-iac/terraform/main.tf",
    "file_line_range": [
      13,
      21
    ],
    "resource": "aws_s3_bucket.public_data",
    "evaluations": null,
    "check_class": "checkov.common.graph.checks_infra.base_check",
    "fixed_definition": null,
    "entity_tags": {
      "Name": "Public Data Bucket"
    },
    "caller_file_path": null,
    "caller_file_line_range": null,
    "resource_address": null,
    "severity": "MEDIUM",
    "bc_category": null,
    "benchmarks": {},
    "description": null,
    "short_description": null,
    "vulnerability_details": null,
    "connected_node": null,
    "guideline": null,
    "details": [],
    "check_len": null,
    "definition_context_file_path": "/mnt/c/Users/verdr/OneDrive/Belgeler/DevSecOps/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "bc_check_id": null,
    "check_name": "Ensure S3 bucket has lifecycle configuration",
    "check_result": {
      "result": "FAILED",
      "entity": {
        "aws_s3_bucket": {
          "unencrypted_data": {
            "__end_line__": 33,
            "__start_line__": 24,
            "acl": [
              "private"
            ],
            "bucket": [
              "my-unencrypted-bucket-lab6"
            ],
            "versioning": [
              {
                "enabled": [
                  false
                ]
              }
            ],
            "__address__": "aws_s3_bucket.unencrypted_data",
            "__provider_address__": "aws.default"
          }
        }
      },
      "evaluated_keys": [
        "resource_type",
        "lifecycle_rule"
      ]
    },
    "code_block": [
      [
        24,
        "resource \"aws_s3_bucket\" \"unencrypted_data\" {\n"
      ],
      [
        25,
        "  bucket = \"my-unencrypted-bucket-lab6\"\n"
      ],
      [
        26,
        "  acl    = \"private\"\n"
      ],
      [
        27,
        "  \n"
      ],
      [
        28,
        "  # No server_side_encryption_configuration!\n"
      ],
      [
        29,
        "  \n"
      ],
      [
        30,
        "  versioning {\n"
      ],
      [
        31,
        "    enabled = false  # Versioning disabled\n"
      ],
      [
        32,
        "  }\n"
      ],
      [
        33,
        "}\n"
      ]
    ],
    "file_path": "/main.tf",
    "file_abs_path": "/mnt/c/Users/verdr/OneDrive/Belgeler/DevSecOps/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf",
    "repo_file_path": "/labs/lab6/vulnerable-iac/terraform/main.tf",
    "file_line_range": [
      24,
      33
    ],
    "resource": "aws_s3_bucket.unencrypted_data",
    "evaluations": null,
    "check_class": "checkov.common.graph.checks_infra.base_check",
    "fixed_definition": null,
    "entity_tags": null,
    "caller_file_path": null,
    "caller_file_line_range": null,
    "resource_address": null,
    "severity": "MEDIUM",
    "bc_category": null,
    "benchmarks": {},
    "description": null,
    "short_description": null,
    "vulnerability_details": null,
    "connected_node": null,
    "guideline": null,
    "details": [],
    "check_len": null,
    "definition_context_file_path": "/mnt/c/Users/verdr/OneDrive/Belgeler/DevSecOps/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf"
  }
]
```

### Why this rule matters

Missing lifecycle configuration on S3 buckets can lead to unchecked storage cost growth and violate data retention compliance requirements. Per CIS AWS Foundations Benchmark v1.4.0 (section 2.1.1), all S3 buckets must have defined lifecycle rules. The 2019 Capital One breach demonstrated how poor data lifecycle management in S3 worsens the impact of a leak — data was retained far longer than necessary. This policy ensures teams explicitly define how long data lives and when to archive or delete it.
