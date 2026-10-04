# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

## Task 1

### 1. Scan

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

Checkov 3.3.19 (installed with `pipx install checkov`), exit code 1 as expected.

### 2. Passed / failed per framework

From `jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' results_json.json`:

| Framework   | Passed | Failed |
| ----------- | -----: | -----: |
| `terraform` |     49 |     78 |
| `secrets`   |      0 |      2 |
| **Total**   | **49** | **80** |

The two `secrets` findings are `CKV_SECRET_2` (AWS Access Key, `main.tf`) and `CKV_SECRET_6` (Base64 High Entropy String, `database.tf`). `severity` is `null` on all 80 failed checks (`[.[].results.failed_checks[]?.severity] | unique` → `[null]`).

### 3. Top five rules by frequency

| # | Rule | Count | What it checks | Resources hit |
| -: | ---- | ----: | -------------- | ------------- |
| 1 | `CKV_AWS_289` | 4 | IAM policy must not allow permissions-management / resource-exposure actions (e.g. `iam:Put*Policy`, `s3:PutBucketPolicy`) without a resource constraint | `admin_policy`, `s3_full_access`, `service_policy`, `privilege_escalation` |
| 2 | `CKV_AWS_355` | 4 | IAM policy document must not use `"*"` as the `Resource` for actions that support resource-level restriction | same four IAM policies |
| 3 | `CKV_AWS_23` | 3 | Every security group and every ingress/egress rule must have a `description` | `allow_all`, `ssh_open`, `database_exposed` |
| 4 | `CKV_AWS_288` | 3 | IAM policy must not allow data-exfiltration actions (e.g. `s3:GetObject`, `ssm:GetParameter`, `secretsmanager:GetSecretValue`) on `*` | `admin_policy`, `s3_full_access`, `service_policy` |
| 5 | `CKV_AWS_290` | 3 | IAM policy must not allow write actions without resource constraints | `admin_policy`, `s3_full_access`, `service_policy` |

`CKV_AWS_382` ("no security group allows egress from 0.0.0.0/0 to port -1", i.e. unrestricted all-protocol egress) is tied at 3 with ranks 3–5; the jq `sort_by(-.count)` keeps it sixth only because of alphabetical order inside the tie. Descriptions are taken from the `check_name` field in the JSON and the [Checkov policy index](https://www.checkov.io/5.Policy%20Index/all.html).

Four of the top five are IAM rules. They all fire on the same pattern: `Resource = "*"` combined with a wildcard or broad action list in `iam.tf`.

### 4. Highest-leverage single change

Findings grouped by resource (`group_by(.file_path + "::" + .resource)`):

| Findings | File | Resource |
| -------: | ---- | -------- |
| **12** | `database.tf` | `aws_db_instance.unencrypted_db` |
| 9 | `iam.tf` | `aws_iam_policy.admin_policy` |
| 8 | `main.tf` | `aws_s3_bucket.public_data` |
| 7 | `database.tf` | `aws_db_instance.weak_db` |
| 7 | `main.tf` | `aws_s3_bucket.unencrypted_data` |
| 7 | `security_groups.tf` | `aws_security_group.allow_all` |

**The change:** harden `aws_db_instance.unencrypted_db` in `database.tf`. That one resource clears **12 findings**: `CKV_AWS_16` (encryption at rest), `CKV_AWS_17` (publicly accessible), `CKV_AWS_133` (backup retention 0), `CKV_AWS_293` (deletion protection), `CKV_AWS_157` (Multi-AZ), `CKV_AWS_161` (IAM auth), `CKV_AWS_226` (auto minor upgrades), `CKV_AWS_118` (enhanced monitoring), `CKV_AWS_129` (log exports), `CKV_AWS_353` (performance insights), `CKV2_AWS_30` (Postgres query logging), `CKV2_AWS_60` (copy tags to snapshots). The concrete settings are `storage_encrypted = true`, `publicly_accessible = false`, `backup_retention_period >= 7`, `deletion_protection = true`, `multi_az = true`, `iam_database_authentication_enabled = true`, `auto_minor_version_upgrade = true`, `monitoring_interval > 0`, `enabled_cloudwatch_logs_exports = ["postgresql"]`, `performance_insights_enabled = true`, `copy_tags_to_snapshot = true`, plus a parameter group with `log_statement`.

**Why fixing it once is not the same as fixing it five times:** 7 of those 12 rules also fail on `aws_db_instance.weak_db`. If the settings go into a shared `rds` module, or a secure-defaults wrapper that every database uses, the same edit clears **19 findings** in this sample. Every future instance also inherits the settings, so the fix holds instead of being repeated. Patching each resource by hand gives five separate diffs to review and five copies that can drift apart. The sixth database someone copy-pastes from an old example brings the whole set of findings back. With a module there is one reviewed change, one place for a regression test, and new resources come out secure by default. Per-resource patching treats symptoms of a copy-paste pattern. The module fix removes the pattern.

### 5. `severity` is null — what I would sort by

In a real backlog I would sort by **exposure × blast radius × data sensitivity**. First, resources reachable from the internet (`publicly_accessible`, `0.0.0.0/0` ingress, `public-read` ACL). Second, identities whose compromise gives account-wide control (`Action = "*"`, privilege-escalation IAM actions). Third, stores that hold customer data. Within each bucket I would sort by frequency, because frequency points to the shared module. A vendor's severity field is a context-free opinion about the *rule*, not about *my resource*. It cannot know that one public bucket hosts a static website and another holds backups. What you buy is a default ordering, and you still have to re-rank it with your own asset inventory and data classification. That is exactly what the Bonus policy below makes machine-checkable.

## Task 2

### 1. Scans

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ --report-formats json,sarif     # exit 50

docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ --report-formats json,sarif      # exit 60
```

KICS v2.1.20. Ansible: 3 files scanned, 287 queries loaded. Pulumi: 1 file scanned (`Pulumi-vulnerable.yaml`), 21 queries loaded. `__main__.py` is not parsed at all.

### 2. Severity breakdowns

Both tables show **distinct queries** (from the `.queries` array) and **findings** (from the terminal summary / `severity_counters`). The two numbers differ because one query can fire in several places.

**Ansible**

| Severity | Queries | Findings |
| -------- | ------: | -------: |
| CRITICAL |       0 |        0 |
| HIGH     |       3 |        9 |
| MEDIUM   |       0 |        0 |
| LOW      |       1 |        1 |
| INFO     |       0 |        0 |
| **Total**|   **4** |   **10** |

**Pulumi**

| Severity | Queries | Findings |
| -------- | ------: | -------: |
| CRITICAL |       1 |        1 |
| HIGH     |       2 |        2 |
| MEDIUM   |       1 |        1 |
| LOW      |       0 |        0 |
| INFO     |       2 |        2 |
| **Total**|   **6** |    **6** |

On Pulumi every query fired exactly once, so the two numbers match there. On Ansible they don't (4 queries vs 10 findings).

### 3. Top Ansible queries by number of files touched

Only **four** Ansible queries fired, so the "top five" has four rows:

| # | Query | Severity | `.files` entries | Locations |
| -: | ----- | -------- | ---------------: | --------- |
| 1 | Passwords And Secrets - Generic Password | HIGH | 6 | `inventory.ini:5,10,18,19`, `configure.yml:16`, `deploy.yml:12` |
| 2 | Passwords And Secrets - Password in URL | HIGH | 2 | `deploy.yml:16` (`postgresql://admin:password123@…`), `deploy.yml:72` (git URL with credentials) |
| 3 | Passwords And Secrets - Generic Secret | HIGH | 1 | `inventory.ini:20` |
| 4 | Unpinned Package Version | LOW | 1 | `deploy.yml:99` (`state: latest`) |

The `.files` array in KICS holds one entry per **finding location**, not per distinct file. "Generic Password" has 6 entries, but they fall in only 3 distinct files.

Three of the four queries are generic secret-detection rules (platform `Common`), not Ansible-specific ones. KICS did **not** flag the 0777 file modes, `PermitRootLogin yes`, `PasswordAuthentication yes`, passwordless sudo, disabled SELinux/ufw, `curl | sh`, or missing `no_log`, even though the README lists them. Its Ansible query pack is mostly about cloud modules (`amazon.aws.*`, `azure.*`, `google.cloud.*`) and doesn't cover host hardening done through `lineinfile`/`file`/`shell`.

Pulumi findings for reference: `RDS DB Instance Publicly Accessible` (CRITICAL, line 104), `DynamoDB Table Not Encrypted` (HIGH, 205), `Generic Password` (HIGH, 16), `EC2 Instance Monitoring Disabled` (MEDIUM, 157), `DynamoDB PITR Disabled` (INFO, 213), `EC2 Not EBS Optimized` (INFO, 157).

### 4. What each tool sees that the other doesn't

**KICS reports, Checkov does not: `RDS DB Instance Publicly Accessible` (CRITICAL) in `pulumi/Pulumi-vulnerable.yaml:104`.** Checkov 3.x has no Pulumi framework. Run against the same directory (`checkov -d labs/lab6/vulnerable-iac/pulumi`), it only runs the `secrets` framework and returns one `CKV_SECRET_6`. It has no parser that turns `type: aws:rds:Instance` + `publiclyAccessible: true` into a resource it can evaluate. KICS parses Pulumi YAML into its own resource model and runs Rego queries against it, so it sees the RDS resource and its properties. The same misconfiguration in Terraform (`aws_db_instance.unencrypted_db`) is caught by Checkov's `CKV_AWS_17`. The difference is the input format, not the idea behind the rule.

**Checkov covers, KICS does not: IAM policy semantics (wildcard / privilege-escalation / data-exfiltration analysis: `CKV_AWS_286`–`290`, `CKV_AWS_355`, `CKV_AWS_62/63`).** `Pulumi-vulnerable.yaml` has the same `Action: "*"` / `Resource: "*"` policy (line 115), `s3:*` role policy (142) and open `0.0.0.0/0` security groups (48, 71) as the Terraform sample. KICS parsed the file and reported none of them. Its Pulumi pack has only 21 queries, and none of them look inside `aws:iam:Policy` documents or `aws:ec2:SecurityGroup` ingress. Checkov's Terraform parser evaluates `jsonencode({...})` into a structured policy document. It then classifies every action against its IAM action tables (which actions are writes, permission management, or exfiltration), and that is why 5 of its 6 most frequent rules are IAM rules. KICS can parse the Pulumi IAM resource, but has no query that understands what is inside it.

### 5. Pipeline decision

I would run **Checkov on Terraform as a blocking gate** on a small curated list of rules: public exposure, IAM wildcards and escalation, encryption at rest, and secrets. The rest of the rules would run as a non-blocking report. I would run **KICS on Ansible and Pulumi YAML**, because it is the only one of the two that parses them. Both tools would export SARIF into one findings store (the DefectDojo import in Lab 10), so triage happens in one place and not across two consoles. For the gap, I would list per format what *neither* tool covers: Pulumi Python, Pulumi IAM/security groups, and Ansible host hardening. I would close it with a few targeted custom policies (KICS Rego queries or Checkov YAML checks like the Bonus). For Pulumi I would also scan the rendered `pulumi preview --json` output or run Pulumi CrossGuard, instead of trusting a scanner that silently skips `__main__.py`.

## Bonus

### 1. Policy

`labs/lab6/policies/my-custom-policy.yaml`:

```yaml
# Internal standard: every stateful data store must declare who owns it and
# how sensitive the data is, so incident response and data-retention reviews
# can route a finding to a human and apply the right handling rules.
metadata:
  id: "CKV_CUSTOM_AWS_1"
  name: "Ensure stateful data stores carry Owner and DataClassification tags"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      operator: "within"
      value:
        - "aws_s3_bucket"
        - "aws_db_instance"
        - "aws_dynamodb_table"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
        - "aws_db_instance"
        - "aws_dynamodb_table"
      attribute: "tags.Owner"
      operator: "exists"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
        - "aws_db_instance"
        - "aws_dynamodb_table"
      attribute: "tags.DataClassification"
      operator: "within"
      value:
        - "public"
        - "internal"
        - "confidential"
        - "restricted"
```

**In plain English:** every S3 bucket, RDS instance and DynamoDB table must have an `Owner` tag and a `DataClassification` tag, and the classification must be one of our four levels: `public`, `internal`, `confidential`, `restricted`.

### 2. Evidence it fires

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output json --output-file-path labs/lab6/results/checkov-custom/
```

`terraform` failed count goes from 78 to **83** (+5, one per data store). Passed stays 49.

```json
[
  { "check_id": "CKV_CUSTOM_AWS_1", "resource": "aws_db_instance.unencrypted_db",      "file_path": "/database.tf" },
  { "check_id": "CKV_CUSTOM_AWS_1", "resource": "aws_db_instance.weak_db",             "file_path": "/database.tf" },
  { "check_id": "CKV_CUSTOM_AWS_1", "resource": "aws_dynamodb_table.unencrypted_table", "file_path": "/database.tf" },
  { "check_id": "CKV_CUSTOM_AWS_1", "resource": "aws_s3_bucket.public_data",           "file_path": "/main.tf" },
  { "check_id": "CKV_CUSTOM_AWS_1", "resource": "aws_s3_bucket.unencrypted_data",      "file_path": "/main.tf" }
]
```

It caught all five stateful resources in the sample. Four have a `tags` block with only `Name`, and `unencrypted_data` has no tags at all.

### 3. The fix and confirmation it passes

The lab says not to fix the sample, so I applied the change to a copy of `terraform/` outside the repo:

```diff
 resource "aws_s3_bucket" "public_data" {
   tags = {
     Name = "Public Data Bucket"
+    Owner = "team-web"
+    DataClassification = "public"
   }
 }

 resource "aws_s3_bucket" "unencrypted_data" {
   bucket = "my-unencrypted-bucket-lab6"
   acl    = "private"
+
+  tags = {
+    Owner              = "team-data"
+    DataClassification = "confidential"
+  }
 }

 # same two tags added to aws_db_instance.unencrypted_db, aws_db_instance.weak_db,
 # aws_dynamodb_table.unencrypted_table with DataClassification = "restricted"
```

```
$ checkov -d <copy> --external-checks-dir labs/lab6/policies --check CKV_CUSTOM_AWS_1 --compact
Passed checks: 5, Failed checks: 0, Skipped checks: 0
	PASSED for resource: aws_db_instance.unencrypted_db
	PASSED for resource: aws_db_instance.weak_db
	PASSED for resource: aws_dynamodb_table.unencrypted_table
	PASSED for resource: aws_s3_bucket.public_data
	PASSED for resource: aws_s3_bucket.unencrypted_data
```

Negative check: I changed one value to `DataClassification = "top-secret"` (not in the allowed list) and got `Passed checks: 4, Failed checks: 1 — FAILED for resource: aws_s3_bucket.public_data`. So the policy checks the value, not just whether the key is present.

### 4. Why this rule is mine and not Checkov's

Checkov can't ship it, because the tag names and the four classification levels are specific to one organisation. Another company uses `team`/`data-sensitivity` with different levels, so any built-in version would be wrong for almost everyone. The rule comes from the kind of problem this sample shows. `public_data` has a `public-read` ACL, and the scanner can't tell whether that is a static website or a leak. An incident responder can't find out who to page either, because the resource has no owner. This is the audit finding "data stores without an accountable owner or classification" (ISO 27001 A.5.9/A.5.12 asset inventory and information classification). With the tag enforced in CI, the triage from Task 1.5 becomes possible: `DataClassification = restricted` plus `publicly_accessible = true` is the finding to fix first.
