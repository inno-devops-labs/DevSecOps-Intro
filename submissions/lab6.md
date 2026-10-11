# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks evaluated: 127
- Passed: 49
- Failed: 78

| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |


> The generated Checkov JSON report contains 49 passed and 78 failed checks for the Terraform sample. In this Checkov version, the exported JSON does not include severity fields for the failed checks, so severity counts cannot be claimed from this output.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | Ensures IAM policies do not allow permissions management / resource exposure without constraints |
| `CKV_AWS_355` | 4 | Ensures no IAM policies documents allow `*` as a statement's resource for restrictable actions |
| `CKV_AWS_288` | 3 | Ensures IAM policies do not allow data exfiltration |
| `CKV_AWS_290` | 3 | Ensures IAM policies do not allow write access without constraints |
| `CKV_AWS_382` | 3 | Ensures no security groups allow egress from `0.0.0.0:0` to port `-1` |


### Module-leverage analysis (Lecture 6 slide 17)
A single module-level fix would be to enforce least-privilege IAM defaults in the shared IAM module, because several failing checks revolve around overly broad role and policy permissions. In the Terraform sample, tightening the default policy document and removing wildcard actions/resources would eliminate many of the same findings at once.

## Task 2: KICS on Ansible

### Ansible - Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi - Severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Info | 2 |

### Top 5 KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| `Passwords And Secrets - Generic Password` | HIGH | 6 |
| `Passwords And Secrets - Password in URL` | HIGH | 2 |
| `Passwords And Secrets - Generic Secret` | HIGH | 1 |
| `Unpinned Package Version` | LOW | 1 |

### Checkov vs KICS — when to use which?
- Checkov did better for Terraform because it understands the declared AWS resources and can surface rule-based policy violations directly from the HCL structure.
- KICS did better for Ansible because it is purpose-built to scan playbooks and inventory files and it caught hardcoded secrets and configuration issues across YAML/INI content.
- A good example is the Ansible inventory secrets: Checkov is not designed for that format, while KICS flagged them directly as secret-management issues.

## Bonus: Custom Checkov Policy

### Policy file
```yaml
apiVersion: ckv2.io/v1
kind: CheckovPolicy
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 buckets have lifecycle configuration
  category: GENERAL_SECURITY
  severity: HIGH
definition:
  and:
    - cond_type: resource
      resource_types:
        - aws_s3_bucket
      attribute: lifecycle_rule
      operator: exists
```

### Rule fires
```bash
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "bc_check_id": null,
    "check_name": "Ensure S3 buckets have lifecycle configuration",
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
    "file_abs_path": "/home/i/Desktop/New Folder/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf",
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
    "severity": "HIGH",
    "bc_category": null,
    "benchmarks": {},
    "description": null,
    "short_description": null,
    "vulnerability_details": null,
    "connected_node": null,
    "guideline": null,
    "details": [],
    "check_len": null,
    "definition_context_file_path": "/home/i/Desktop/New Folder/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "bc_check_id": null,
    "check_name": "Ensure S3 buckets have lifecycle configuration",
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
    "file_abs_path": "/home/i/Desktop/New Folder/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf",
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
    "severity": "HIGH",
    "bc_category": null,
    "benchmarks": {},
    "description": null,
    "short_description": null,
    "vulnerability_details": null,
    "connected_node": null,
    "guideline": null,
    "details": [],
    "check_len": null,
    "definition_context_file_path": "/home/i/Desktop/New Folder/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf"
  }
]
```

### Why this rule matters
Requiring an S3 lifecycle policy helps reduce storage sprawl, supports retention controls, and improves lifecycle management for data that must be retained or deleted according to policy. This is a practical governance check for compliance and cost control, especially for buckets that hold operational data.
