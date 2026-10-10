# Lab 6 Submission — IaC Security

## Task 1

### Checkov scan

I scanned the supplied Terraform fixtures with Checkov 3.3.20. Checkov exited with status 1 because the intentionally vulnerable sample contains failed checks. The JSON report is an array with one result object per framework.

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
# Checkov 3.3.20; exit status 1

jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' \
  labs/lab6/results/checkov-terraform/results_json.json
```

| Framework | Passed | Failed |
|---|---:|---:|
| `terraform` | 49 | 78 |
| `secrets` | 0 | 2 |

The Terraform framework produced 78 failed checks, and the secrets framework added two more failures. The combined report therefore contains 80 failed checks across the two framework objects.

### Top rules by frequency

```bash
jq '[.[].results.failed_checks[]?.check_id]
  | group_by(.) | map({rule: .[0], count: length})
  | sort_by(-.count) | .[:5]' \
  labs/lab6/results/checkov-terraform/results_json.json
```

| Rule | Findings | What it checks |
|---|---:|---|
| `CKV_AWS_289` | 4 | IAM policies must not allow permissions management or resource exposure without constraints. |
| `CKV_AWS_355` | 4 | IAM policy statements must not use `*` as the resource for actions that can be restricted. |
| `CKV_AWS_23` | 3 | Every security group and security-group rule must have a description. |
| `CKV_AWS_288` | 3 | IAM policies must not allow data exfiltration. |
| `CKV_AWS_290` | 3 | IAM policies must not allow unconstrained write access. |

The highest-leverage single change is to replace the wildcard IAM permissions in `labs/lab6/vulnerable-iac/terraform/iam.tf`, especially the `aws_iam_policy.admin_policy` resource. That policy alone is reported by `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, and `CKV_AWS_355`, and the same class of least-privilege correction also applies to the role, user, and privilege-escalation policies. Fixing one shared policy definition clears several findings because multiple checks evaluate the same insecure statement; five separate edits would duplicate the same remediation across policy statements.

The open-source Checkov report leaves `severity` as `null` for every finding. In a real backlog I would sort first by exploitability and business impact, then by internet exposure, privilege scope, affected resources, and remediation leverage, while using rule frequency as a tie-breaker. Vendor severity metadata can accelerate prioritisation, but purchasing it supplies classification context rather than replacing asset context, threat modelling, or engineering triage.

## Task 2

### KICS scans

KICS 2.1.20 scanned the Ansible and Pulumi YAML fixtures. KICS's terminal total counts individual findings, while the `.queries` array contains distinct query objects. The tables below label both values explicitly.

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ --report-formats json,sarif
# TOTAL: 10 findings

docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ --report-formats json,sarif
# TOTAL: 6 findings
```

| Scan | Critical | High | Medium | Low | Info | Distinct queries | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|
| Ansible | 0 | 3 | 0 | 1 | 0 | 4 | 10 |
| Pulumi | 1 | 2 | 1 | 0 | 2 | 6 | 6 |

### Top Ansible queries by files touched

The following is sorted by the number of files in each query object, not by the number of individual findings:

```bash
jq '[.queries[] | {query: .query_name, severity, files: (.files | length)}]
  | sort_by(-.files) | .[:5]' labs/lab6/results/kics-ansible/results.json
```

| Query | Severity | Files touched |
|---|---|---:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

KICS reported `RDS DB Instance Publicly Accessible` in `Pulumi-vulnerable.yaml`, while Checkov did not scan Pulumi in this task. KICS parses the Pulumi YAML representation directly and has Pulumi-specific queries for properties such as `publiclyAccessible`. Checkov's Terraform framework covers HCL resources and does not provide a Pulumi framework here; its parser therefore cannot evaluate this Pulumi YAML resource as Terraform.

A class Checkov covers that KICS did not report in these fixtures is the Terraform IAM wildcard-policy analysis, including the four findings for `CKV_AWS_289` and `CKV_AWS_355`. Checkov parses Terraform HCL and understands the decoded IAM policy structure in `iam.tf`; the KICS Pulumi and Ansible scans operate on different input formats and resources, so they cannot produce that Terraform-specific result from these directories.

I would run Checkov on Terraform and KICS on Ansible and Pulumi in the same pipeline because each scanner has format-specific parsing and policy coverage. The pipeline should preserve both reports in SARIF/JSON, fail the gate on critical and high findings after an agreed exception process, and retain lower-severity findings for triage. I would review the coverage gap with representative fixtures, add custom policies for organisation rules, and periodically compare findings across tools so that a disagreement becomes a documented coverage decision rather than an invisible blind spot.

## Bonus

### Custom policy

Policy file: `labs/lab6/policies/my-custom-policy.yaml`.

The policy `CKV_CUSTOM_1` requires every `aws_s3_bucket` to use an ACL other than `public-read`. This is an organisation-specific guardrail: public buckets require an explicitly reviewed exception, even when a generic scanner reports other bucket settings separately.

```yaml
metadata:
  id: CKV_CUSTOM_1
  name: Ensure S3 buckets use private ACLs
  category: CONVENTION
  severity: HIGH
definition:
  cond_type: attribute
  resource_types:
    - aws_s3_bucket
  attribute: acl
  operator: not_equals
  value: public-read
```

The policy fired with Checkov 3.3.20:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output json --output-file-path labs/lab6/results/checkov-custom/
# exit status 1

jq '[.[].results.failed_checks[]?
  | select(.check_id | startswith("CKV"))
  | select(.check_id | test("CUSTOM"))
  | {check_id, resource, file_path}]' \
  labs/lab6/results/checkov-custom/results_json.json
```

```json
[
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf"
  }
]
```

The remediation is to change `aws_s3_bucket.public_data` in `labs/lab6/vulnerable-iac/terraform/main.tf` from `acl = "public-read"` to `acl = "private"` and obtain a reviewed exception for any required public delivery path. I applied that change in a temporary copy of the fixture and reran only `CKV_CUSTOM_1`; Checkov returned status 0 with 2 passed and 0 failed, confirming that the policy passes for both S3 buckets.

This policy belongs to the organisation because it encodes the local public-bucket exception process, while a generic Checkov policy cannot know which buckets are approved by an internal review or audit standard. The rule is therefore a local convention that complements the vendor's cloud-security checks.
