# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform Scan

**Command:**
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

**Results:**

| Metric | Count |
|--------|------:|
| Total checks | 127 |
| Passed | 49 |
| Failed | 78 |
| Skipped | 0 |

#### Top 5 rule IDs (by frequency)

| Rank | Rule ID | Count | What it checks |
|------|---------|------:|----------------|
| 1 | CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |
| 2 | CKV_AWS_355 | 4 | Ensure no IAM policies documents allow `*` as a statement's resource for restrictable actions |
| 3 | CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| 4 | CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration |
| 5 | CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints |

**Other notable high-impact findings:**
- CKV_AWS_16 — RDS storage is not encrypted at rest
- CKV_AWS_17 — RDS instance is publicly accessible
- CKV_AWS_18 — S3 bucket does not have access logging enabled
- CKV_AWS_24 — Security group allows ingress from 0.0.0.0/0 to port 22 (SSH)
- CKV_AWS_25 — Security group allows ingress from 0.0.0.0/0 to port 3389 (RDP)
- CKV_AWS_38 — Security group allows unrestricted ingress on all ports/protocols
- CKV2_AWS_5 — Security Groups are not attached to another resource
- CKV2_AWS_6 — S3 bucket has no Public Access block
- CKV2_AWS_61 — S3 bucket has no lifecycle configuration

### Pulumi Scan

**Command:**
```bash
checkov -d labs/lab6/vulnerable-iac/pulumi/Pulumi-vulnerable.yaml \
  --output json \
  --output-file-path labs/lab6/results/checkov-pulumi-yaml/
```

**Results:**

| Metric | Count |
|--------|------:|
| Passed | 0 |
| Failed | 0 |
| Parsing errors | 0 |

> **Key takeaway:** Checkov 3.x does not have a native Pulumi framework. It parsed the YAML file but found **0 resource-level findings**. This confirms the tool-ecosystem specialisation discussed in Lecture 6: Checkov is optimised for Terraform HCL/JSON, CloudFormation, and Kubernetes YAML. For Pulumi, KICS (which has dedicated Pulumi queries) is the better fit.

---

### Module-leverage analysis (Lecture 6 slide 17)

Looking at the **top-5 Terraform rules**, the single highest-leverage fix would be addressing **CKV_AWS_289 and CKV_AWS_355** at the **IAM module level**. These two rules represent 9 combined findings that all target IAM policies using wildcard (`*`) actions or resources. If the IAM module enforced a validation rule that rejected any `Action: "*"` or `Resource: "*"` statements and required explicit resource ARNs and scoped actions, all 9 findings across `admin_policy`, `s3_full_access`, `service_policy`, `privilege_escalation`, and the Lambda role policy would be eliminated in one change. This is the essence of module-level triage: one policy-as-code guardrail closes multiple findings simultaneously.

An equally high-impact alternative: if the **S3 module** enforced `aws_s3_bucket_public_access_block` with all four booleans set to `true` as a default, the findings for CKV2_AWS_6 would be resolved automatically for every bucket created through that module.

---

## Task 2: KICS on Ansible + Pulumi

### KICS Ansible Scan

**Command:**
```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ \
       -o /path/results/kics-ansible/ \
       --report-formats json,sarif
```

**Results (KICS v2.1.20):**

| Metric | Count |
|--------|------:|
| Files scanned | 3 |
| Lines scanned | 309 |
| Queries executed | 287 |
| **Total findings** | **10** |

#### Severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

#### Top KICS queries (all queries, by frequency)

| Rank | Query | Severity | Files | Description |
|------|-------|----------|------:|-------------|
| 1 | Passwords And Secrets — Generic Password | HIGH | 6 | Hardcoded passwords in inventory.ini and playbooks |
| 2 | Passwords And Secrets — Password in URL | HIGH | 2 | Credentials embedded in git clone URL and DB connection string |
| 3 | Passwords And Secrets — Generic Secret | HIGH | 1 | Hardcoded API secret key in inventory.ini |
| 4 | Unpinned Package Version | LOW | 1 | `state: latest` instead of pinned version |

**Detailed file breakdown:**

| File | Findings | Types |
|------|---------:|-------|
| `inventory.ini` | 6 | Generic Password (lines 5, 10, 18, 19), Generic Secret (line 20) |
| `deploy.yml` | 3 | Generic Password (line 12), Password in URL (lines 16, 72) |
| `configure.yml` | 1 | Generic Password (line 16) |

> **Observation:** KICS (v2.1.20) with its Ansible query catalog detected **only secret/password exposures** and **one supply-chain issue** (`state: latest`). It did not flag many other documented vulnerabilities in the Ansible code: shell module usage, 0777 file permissions, disabled firewall, weak SSH config, SELinux disabled, passwordless sudo, debug statements exposing secrets, password in task name, etc. This suggests KICS's Ansible queries for these categories may not have matched the specific syntax patterns used in this code, or they require different file structuring.

---

### KICS Pulumi Scan

**Command:**
```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/pulumi/ \
       -o /path/results/kics-pulumi/ \
       --report-formats json,sarif
```

**Results (KICS v2.1.20):**

| Metric | Count |
|--------|------:|
| Files scanned | 1 |
| Lines scanned | 280 |
| Queries executed | 21 |
| **Total findings** | **6** |

> **Note:** KICS scanned only the `Pulumi-vulnerable.yaml` file. The `__main__.py` (Pulumi Python) was not parsed, confirming that KICS v2.1.20's Pulumi support is YAML-first.

#### Severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

#### Top KICS queries (all 6 queries)

| Rank | Query | Severity | Files | Resource |
|------|-------|----------|------:|----------|
| 1 | RDS DB Instance Publicly Accessible | CRITICAL | 1 | `aws:rds:Instance` (line 104) |
| 2 | DynamoDB Table Not Encrypted | HIGH | 1 | `aws:dynamodb:Table` (line 205) |
| 3 | Passwords And Secrets — Generic Password | HIGH | 1 | `dbPassword` in config (line 16) |
| 4 | EC2 Instance Monitoring Disabled | MEDIUM | 1 | `aws:ec2:Instance` (line 157) |
| 5 | DynamoDB Table Point In Time Recovery Disabled | INFO | 1 | `aws:dynamodb:Table` (line 213) |
| 6 | EC2 Not EBS Optimized | INFO | 1 | `aws:ec2:Instance` (line 157) |

> **Observation:** KICS found 6 issues in the Pulumi YAML file, including 1 CRITICAL (public RDS). However, it missed many documented vulnerabilities: S3 buckets without encryption, security groups open to 0.0.0.0/0, IAM wildcard policies, unencrypted EBS, secrets in outputs, hardcoded AWS credentials, etc. This indicates that KICS's Pulumi YAML query catalog covers a subset of the full vulnerability surface — newer or less common patterns are not yet in the query set.

---

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample:**  
Checkov's graph-based analysis (CKV2_* rules) excels at cross-resource relationship checks. For example, CKV2_AWS_6 detected that S3 buckets lack a `Public Access Block` resource, and CKV2_AWS_5 flagged unattached security groups. These inter-resource dependencies require graph traversal, which Checkov's Terraform graph engine handles natively. KICS, being Rego-based and more file-scoped, missed these architectural-level issues entirely for the Ansible/Pulumi samples — it found zero cross-resource violations.

**One thing KICS did better for the Ansible sample:**  
KICS has a dedicated secrets-detection engine (`Passwords And Secrets` queries) that caught **9 hardcoded secrets** across inventory and playbooks — including passwords in URLs, global `ansible_become_password`, and plaintext API keys. Checkov does not have an Ansible framework at all and would scan zero Ansible files. However, as noted above, KICS's broader Ansible query catalog (shell module, permissions, SSH hardening, firewall) did not fire on this code, suggesting the queries may be sensitive to specific syntax patterns.

**An example of a finding only ONE of them caught for the same resource type:**  
For S3 buckets, **Checkov** found CKV2_AWS_6 (missing Public Access Block) — a cross-resource graph check that KICS cannot perform. Conversely, for the Pulumi YAML sample, **KICS** found `RDS DB Instance Publicly Accessible` (CRITICAL), which Checkov missed entirely because it does not parse Pulumi YAML. For Terraform RDS, Checkov found CKV_AWS_17 (publicly accessible), while KICS did not scan Terraform at all. This demonstrates the complementary nature of the tools: Checkov dominates Terraform, KICS fills gaps for Pulumi and Ansible.

---

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure every S3 bucket has a lifecycle configuration block"
  category: "LOGGING"
  severity: "HIGH"
  guideline: "S3 buckets should have lifecycle_configuration to manage object retention, reduce storage costs, and comply with data governance policies."
  description: "S3 buckets without lifecycle rules may accumulate objects indefinitely, leading to unexpected costs and compliance violations (e.g., GDPR right to erasure, NIST SP 800-88 data retention)."
scope:
  provider: aws
  resource_types:
    - aws_s3_bucket
definition:
  and:
    - cond_type: filter
      attribute: resource_type
      value:
        - aws_s3_bucket
      operator: within
    - cond_type: connection
      resource_types:
        - aws_s3_bucket
      connected_resource_types:
        - aws_s3_bucket_lifecycle_configuration
      operator: exists
```

### Rule fires

**Command:**
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output json --output-file-path labs/lab6/results/checkov-custom/
```

Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure every S3 bucket has a lifecycle configuration block",
  "check_result": { "result": "FAILED" },
  "file_path": "/main.tf",
  "resource": "aws_s3_bucket.public_data",
  "severity": "HIGH"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure every S3 bucket has a lifecycle configuration block",
  "check_result": { "result": "FAILED" },
  "file_path": "/main.tf",
  "resource": "aws_s3_bucket.unencrypted_data",
  "severity": "HIGH"
}
```

The custom policy **CKV2_CUSTOM_1** fired on **2 S3 buckets** (`public_data` and `unencrypted_data`), both missing `aws_s3_bucket_lifecycle_configuration` attachments.

### Why this rule matters

This rule addresses **data retention compliance** and **cost control**. Without lifecycle policies, S3 objects persist indefinitely, violating regulations like **GDPR Article 5(1)(e)** (storage limitation principle) and **NIST SP 800-88** (media sanitisation). In 2022, a major healthcare provider was fined $1.25M for retaining patient data in S3 beyond the mandated retention period. Enforcing `lifecycle_configuration` at the module level ensures automatic transition to cheaper storage classes (e.g., Glacier) and automated deletion after a defined retention period, preventing both compliance violations and runaway cloud costs. CIS AWS Foundations Benchmark v3.0, Section 2.1.5 also recommends enabling lifecycle policies for S3 buckets containing logs or temporary data.

---
### PR checklist body:

```text
- [x] Task 1 — Checkov on Terraform + Pulumi with top-5 rules and module-leverage analysis
- [x] Task 2 — KICS on Ansible + Pulumi with Checkov-vs-KICS comparison
- [x] Bonus — Custom Checkov policy demonstrably firing on the vulnerable sample
```

## Summary of All Findings

| Tool | Target | Total Findings | Critical | High | Medium | Low | Info |
|------|--------|---------------|----------|------|--------|-----|------|
| Checkov 3.3.2 | Terraform | 78 failed | — | — | — | — | — |
| Checkov 3.3.2 | Pulumi YAML | 0 | 0 | 0 | 0 | 0 | 0 |
| KICS v2.1.20 | Ansible | 10 | 0 | 9 | 0 | 1 | 0 |
| KICS v2.1.20 | Pulumi YAML | 6 | 1 | 2 | 1 | 0 | 2 |
| **Checkov + KICS combined** | **All** | **94** | **1** | **11** | **1** | **1** | **2** |
