# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | 1 |
| High | 20 |
| Medium | 15 |
| Low | 33 |
| Info | 9 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |


### Pulumi scan
| Severity | Count |
|----------|------:|
|CRITICAL   | 1   |
|HIGH   | 2   |
|MEDIUM | 1 |
|LOW    | 0    |
|INFO   | 2   |

_Note: Scanned with **KICS**._

According to Lab 6, Task 1:
> **Why Terraform-only for Checkov?** Pulumi is real Python; Checkov 3.x does not have a `pulumi` framework directly (it expects rendered state via `pulumi preview --json` OR the SAST-Python framework). To keep the lab's tool surface manageable, **Pulumi is scanned with KICS** in Task 2 (which natively understands Pulumi source). You'll see the trade-off live: tool ecosystems specialize differently.

See `labs/lab6.md` for details.


### Module-leverage analysis (Lecture 6 slide 17)
If the Terraform IAM module enforced least-privilege policies by default _(for example, disallowing wildcard `Resource: "*"`, restricting overly broad actions, and requiring scoped permissions)_, it would eliminate the largest number of findings in this report. This single module-level change would address the IAM-related rules **CKV_AWS_355** (4 findings), **CKV_AWS_289** (4 findings), **CKV_AWS_288** (3 findings), and **CKV_AWS_290** (3 findings), removing 14 of the 17 findings in the top-5 list.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | High | 6 |
| Passwords And Secrets - Password in URL | High | 2 |
| Passwords And Secrets - Generic Secret | High | 1 |
| Unpinned Package Version | Low | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
* **One thing Checkov did better for the Terraform sample**

  According to Lecture 6, Slide 10, *"Checkov has deeper Terraform-specific checks"*. While Checkov caught 78 vulnerabilities, KICS managed to find only 38 on the same sample. This suggests Checkov provides more granular and Terraform-aware policy coverage, especially for cloud resource misconfigurations.

* **One thing KICS did better for the Ansible sample**

  KICS showed broader coverage across different file types and patterns in the Ansible project. It detected secrets not only in YAML files but also in `inventory.ini`, which Checkov did not analyze in this scan. Additionally, KICS flagged supply-chain and configuration issues such as unpinned package versions (`state: latest`), which were not reported by Checkov.

* **(Optional) Example of a finding only ONE of them caught for the same resource type**

  KICS detected multiple generic secrets in `inventory.ini` (e.g., password/secret patterns across several lines), while Checkov did not report findings for that file at all. On the other hand, Checkov identified a structured secret pattern like a private key block (`CKV_SECRET_13`) in `configure.yml`, which is not explicitly represented as a separate rule in the KICS output.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Every S3 bucket must have lifecycle configuration attached
  category: STORAGE
  severity: HIGH

definition:
  and:
    - cond_type: connection
      resource_types:
        - aws_s3_bucket
      connected_resource_types:
        - aws_s3_bucket_lifecycle_configuration
      operator: exists
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
{
  "check_id": "CKV2_CUSTOM_1",
  "bc_check_id": null,
  "check_name": "Every S3 bucket must have lifecycle configuration attached",
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
    "evaluated_keys": []
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
  "file_abs_path": "/home/semyon/code/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf",
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
  "definition_context_file_path": "/home/semyon/code/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "bc_check_id": null,
  "check_name": "Every S3 bucket must have lifecycle configuration attached",
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
    "evaluated_keys": []
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
  "file_abs_path": "/home/semyon/code/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf",
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
  "definition_context_file_path": "/home/semyon/code/DevSecOps-Intro/labs/lab6/vulnerable-iac/terraform/main.tf"
}
```

### Why this rule matters
S3 buckets without lifecycle configuration often accumulate unbounded data, leading to increased storage costs and potential retention of sensitive information beyond its required lifetime. This violates data minimization principles and can conflict with compliance requirements such as NIST SP 800-53 (MP-6 Media Sanitization) and CIS AWS Foundations Benchmark 3.1, which emphasize controlled data retention and lifecycle management.