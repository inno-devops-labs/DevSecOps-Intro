# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow `"*"` as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage fix is hardening the shared IAM policy module so no policy document can use `Resource: "*"` or unrestricted wildcard actions. Rules CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, and CKV_AWS_290 account for 14 of 78 terraform failures (4+4+3+3), all rooted in the same overly permissive IAM patterns in `iam.tf`. Enforcing a module-level guardrail—deny `Action: "*"` and `Resource: "*"` unless explicitly approved—would collapse this entire cluster into one fix instead of patching each policy attachment individually.

### Commands run (Task 1)
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/

jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' \
  labs/lab6/results/checkov-terraform/results_json.json

jq '[.[].results.failed_checks[]?.check_id]
    | group_by(.) | map({rule: .[0], count: length})
    | sort_by(-.count) | .[:5]' \
  labs/lab6/results/checkov-terraform/results_json.json
```


## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample:**
Checkov applied 127 policy checks across 16 Terraform resources and surfaced deep, Terraform-specific misconfigurations—including graph-based rules (e.g., `CKV2_AWS_6` linking S3 buckets to missing public-access blocks) and a dedicated secrets framework that caught hardcoded AWS keys (`CKV_SECRET_2`) and passwords (`CKV_SECRET_6`). Its ~2,500 built-in Terraform policies and cross-resource graph analysis gave far richer coverage on HCL than KICS would on this format.

**One thing KICS did better for the Ansible sample:**
KICS natively understands Ansible playbooks and inventory files—formats Checkov does not scan in this lab—and assigned actionable severities (9 HIGH, 1 LOW) to findings like hardcoded passwords in `inventory.ini`, credentials embedded in Git URLs, and unpinned package versions (`state: latest`). This Ansible-specific, severity-ranked output is immediately triageable for a config-management pipeline.

**(Optional) Finding only one tool caught:**
Checkov cannot scan Ansible at all, so only KICS flagged `Unpinned Package Version` (LOW) on `deploy.yml:99` where `state: latest` risks uncontrolled package drift. Conversely, only Checkov's graph engine flagged `CKV2_AWS_6`—the cross-resource link between `aws_s3_bucket.unencrypted_data` and a missing public-access block—which requires Terraform resource-graph analysis beyond KICS's Ansible/Pulumi scope.

### Commands run (Task 2)
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

for scan in kics-ansible kics-pulumi; do
  echo "== $scan =="
  jq '[.queries[] | {severity, count: (.files | length)}]
      | group_by(.severity) | map({severity: .[0].severity, count: (map(.count) | add)})' \
    labs/lab6/results/$scan/results.json
done

jq '[.queries[] | {query: .query_name, severity, count: (.files | length)}]
    | sort_by(-.count) | .[:5]' \
  labs/lab6/results/kics-ansible/results.json 
```


## Bonus: Custom Checkov Policy
### Policy file
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure every S3 bucket has a lifecycle configuration
  category: GENERAL_SECURITY
  severity: HIGH
definition:
  cond_type: attribute
  resource_types:
    - aws_s3_bucket
  attribute: lifecycle_rule
  operator: exists
```
### Rule fires
2 failures for CKV2_CUSTOM_1:
  - aws_s3_bucket.public_data      (main.tf:13-21)  severity: HIGH
  - aws_s3_bucket.unencrypted_data (main.tf:24-33) severity: HIGH
### Why this rule matters
S3 buckets without lifecycle rules accumulate indefinite data, increasing storage cost and breach blast radius. Misconfigured cloud storage is a recurring exposure in breach reports; CIS AWS Foundations Benchmark recommends lifecycle management for data retention. A module-level default lifecycle_configuration (e.g., transition to Glacier after 90 days, expire after 365) enforces organizational retention without per-bucket manual policy.

### Commands run (Bonus)
```
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-custom/
jq '[.[].results.failed_checks[]?]
    | map(select(.check_id | startswith("CKV2_CUSTOM_")))' \
  labs/lab6/results/checkov-custom/results_json.json
```
