# Lab 6 — IaC Security: Checkov, KICS, and a Policy I Wrote

**Environment:**
- Windows 11 host, Docker Desktop 29.7.2, Git Bash.
- `checkov 3.3.20` (installed with `python -m pip install "checkov==3.3.*"`), `checkmarx/kics:latest` = KICS **v2.1.20**, `jq 1.8.2`.
- Scans ran in place against `labs/lab6/vulnerable-iac/`. Reports are in `labs/lab6/results/`, which is not committed.

**One adjustment to the lab commands.** In Git Bash on Windows, `-v "$(pwd)/labs/lab6":/path` is mangled by MSYS path conversion. I ran KICS with `MSYS_NO_PATHCONV=1` and an absolute `D:/...` host path. The command is otherwise unchanged, including `--user "$(id -u):$(id -g)"`.

## Task 1

### 6.1 Scan

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

The scan took 7 seconds and exited 1, which is expected when there are findings.

### 6.2 Triage by leverage

```bash
jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' \
  labs/lab6/results/checkov-terraform/results_json.json
```

| Framework | Passed | Failed |
|---|---|---|
| `terraform` | 49 | **78** |
| `secrets` | 0 | **2** |

The two `secrets` findings are `CKV_SECRET_2` "AWS Access Key" at `main.tf:8`, the hardcoded provider key, and `CKV_SECRET_6` "Base64 High Entropy String" at `database.tf:48`. Failures by file: `iam.tf` 23, `database.tf` 21, `main.tf` 20, `security_groups.tf` 14.

**Top five rules by frequency** (lab `jq`, `sort_by(-.count) | .[:5]`):

| Count | Rule | What it checks |
|---|---|---|
| 4 | `CKV_AWS_289` | An IAM policy must not grant *permissions-management / resource-exposure* actions (e.g. `iam:Put*Policy`, `iam:Attach*Policy`, `s3:PutBucketPolicy`) without a resource constraint. These actions let the holder change who can access what. |
| 4 | `CKV_AWS_355` | No IAM policy statement may use `"*"` as `Resource` for actions that support resource-level scoping. |
| 3 | `CKV_AWS_23` | Every security group, and every ingress/egress rule in it, must have a `description`. |
| 3 | `CKV_AWS_288` | An IAM policy must not allow *data exfiltration* actions (e.g. `s3:GetObject`, `ssm:GetParameter*`, `secretsmanager:GetSecretValue`) on unconstrained resources. |
| 3 | `CKV_AWS_290` | An IAM policy must not allow *write* actions without resource constraints. |

There is a tie at 3. `CKV_AWS_382` (security groups allowing egress to `0.0.0.0/0` on all ports) also fires three times. `.[:5]` drops it only because `group_by` sorts IDs alphabetically.

Four of the top five are IAM rules, and they fire on the same four resources in `iam.tf`: `admin_policy`, `s3_full_access`, `service_policy` and `privilege_escalation`. The copy-pasted pattern behind all of them is `Resource = "*"`.

**The single change that clears the most findings:** `iam.tf`, resource **`aws_iam_policy.admin_policy`** (lines 5–19). Its one statement is `Action = "*"`, `Resource = "*"`. Replacing it with a scoped list of actions on specific ARNs clears **9 findings** with one edit:

```text
CKV_AWS_62  full "*-*" admin privileges       CKV_AWS_63  "*" as a statement's actions
CKV_AWS_286 privilege escalation              CKV_AWS_287 credentials exposure
CKV_AWS_288 data exfiltration                 CKV_AWS_289 permissions management
CKV_AWS_290 unconstrained write               CKV_AWS_355 "*" as resource
CKV2_AWS_40 full IAM privileges
```

`aws_db_instance.unencrypted_db` has more findings (12), but they cover 12 separate attributes: encryption, backups, Multi-AZ, public access, monitoring and so on. Clearing them takes 12 changes, not one.

**Why fixing it once is not the same as fixing it five times.** The nine findings are nine views of one root cause, a single wildcard statement. The same root cause is copied into three more policies, which is why each IAM rule fires three or four times. Patching findings one at a time invites partial fixes. For example, scoping `Resource` but leaving `Action = "*"` closes `CKV_AWS_355` and leaves the admin grant in place. The pattern also survives in whatever gets copied next. Fixing the source clears the whole class: one scoped `aws_iam_policy_document` (or module) that every role and user references, plus a gate that rejects `"*"`. New code then inherits the fix, and there is only one place to review.

**`severity` is null on every finding.** In a real backlog I would sort by exploitability and blast radius in context:

1. Anything reachable from the internet (the public RDS, SSH/RDP/DB from `0.0.0.0/0`).
2. Anything that widens privilege (admin/`*` IAM, access keys exposed in `output`s).
3. The sensitivity of the data behind the resource.
4. Fix leverage, as above.

A vendor severity is a context-free default. It cannot know that one bucket holds customer PII and another holds build logs, or that one security group sits on a bastion. Buying it gives a starting order, not a priority. Prioritisation stays our own job, and it needs our own asset context. The bonus policy below is one way to encode that context.

## Task 2

### 6.3 Scan both

```bash
MSYS_NO_PATHCONV=1 docker run --rm --user "$(id -u):$(id -g)" \
  -v "D:/Code/devsec/DevSecOps-Intro/labs/lab6:/path" checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ -o /path/results/kics-ansible/ --report-formats json,sarif
# same for /path/vulnerable-iac/pulumi/ -> /path/results/kics-pulumi/
```

The Ansible scan exited **50** after 10 seconds, and the Pulumi scan exited **60** after 2 seconds. KICS's exit code encodes the highest severity found: 50 = HIGH, 60 = CRITICAL. Both scans produced `results.json` and `results.sarif`.

### 6.4 Severity breakdowns: findings vs queries

| Scan | Files parsed | Queries loaded | CRITICAL | HIGH | MEDIUM | LOW | INFO | Total |
|---|---|---|---|---|---|---|---|---|
| Ansible, **findings** (terminal `TOTAL`, `.severity_counters`) | 3 | 287 | 0 | 9 | 0 | 1 | 0 | **10** |
| Ansible, **queries** (`.queries[]`) | | | 0 | 3 | 0 | 1 | 0 | **4** |
| Pulumi, **findings** | 1 | 21 | 1 | 2 | 1 | 0 | 2 | **6** |
| Pulumi, **queries** | | | 1 | 2 | 1 | 0 | 2 | **6** |

For Ansible the two numbers differ: 4 distinct queries produced 10 findings, because "Generic Password" alone matches 6 lines. For Pulumi every query fired once, so the two numbers happen to coincide.

Pulumi parsed **1 file**, `Pulumi-vulnerable.yaml`. KICS reads Pulumi YAML manifests, not Python programs, so the 21 issues the README lists for `__main__.py` were never examined.

**Top Ansible queries by `.files | length`.** Only four queries fired at all, so the top five has four rows. `.files` lists match locations, so I give distinct files alongside.

| Severity | Query | Locations | Distinct files, lines |
|---|---|---|---|
| HIGH | Passwords And Secrets - Generic Password | 6 | 3: `inventory.ini:5,10,18,19`, `configure.yml:16`, `deploy.yml:12` |
| HIGH | Passwords And Secrets - Password in URL | 2 | 1: `deploy.yml:16,72` |
| HIGH | Passwords And Secrets - Generic Secret | 1 | 1: `inventory.ini:20` |
| LOW | Unpinned Package Version | 1 | 1: `deploy.yml:99` |

All four are from KICS's platform-independent secret and version patterns, not its Ansible-specific logic. Of the 287 queries loaded, KICS's Ansible catalog is built around cloud modules: `aws/` 126, `gcp/` 49, `azure/` 40, and only `config/` 4, `general/` 6, `hosts/` 1. These playbooks configure a Linux host with `lineinfile`, `file`, `ufw` and `selinux`. As a result, `PermitRootLogin yes` (`configure.yml:40`), `mode: '0777'` (`deploy.yml:36,108`), `NOPASSWD: ALL` (`configure.yml:29`) and SELinux disabled all go unreported.

**One finding KICS reports that Checkov did not.** KICS flags **CRITICAL "RDS DB Instance Publicly Accessible"** at `pulumi/Pulumi-vulnerable.yaml:104`. KICS parses the Pulumi YAML resource model (`type: aws:rds:Instance`, `properties.publiclyAccessible: true`) and evaluates it like any other resource. Checkov has no Pulumi framework. Run on the same folder (`checkov -d labs/lab6/vulnerable-iac/pulumi`), it runs only its `secrets` regex framework and reports one high-entropy string at line 19. The public database is invisible to it.

**One class Checkov covers that KICS did not: IAM policy semantics.** Checkov's Terraform framework parses the policy document inside `jsonencode()` and evaluates what the actions permit, which produces the nine findings on `admin_policy` above. The same pattern exists in the Pulumi manifest: `aws:iam:Policy` at `Pulumi-vulnerable.yaml:115-125` with `Action: "*"` and `Resource: "*"` under `fn::toJSON`. KICS parsed that file and raised nothing on it, because none of its 21 Pulumi queries reads IAM policy documents. KICS parses the resource but not the JSON policy embedded in it. Checkov parses HCL, including the `jsonencode` policy object, and it has an IAM ruleset written for that.

**What runs in my pipeline.** The tools disagree mainly because each parses different things, so I would choose per format rather than pick one winner:

- **Checkov** gates Terraform. It has the largest catalog, graph checks and custom YAML policies.
- **KICS** gates the Pulumi YAML.
- A **secrets scanner** (the gitleaks hook from Lab 3) runs across everything, since both tools only find secrets by regex anyway.
- Findings go through one triage view (Lab 10's DefectDojo) so duplicates collapse.

The gap needs explicit owners rather than hope:

- **Pulumi Python** is invisible to both tools. Scan the rendered plan (`pulumi preview --json`) or enforce Pulumi CrossGuard policy packs.
- **Ansible host hardening** is invisible to both. Add `ansible-lint` and a CIS-style test (InSpec/goss) against the built host.

These uncovered categories should be tracked as known blind spots, so that a green scan is not read as "secure".

## Bonus — Write the policy nobody ships

### 6.5 The policy

[`labs/lab6/policies/my-custom-policy.yaml`](../labs/lab6/policies/my-custom-policy.yaml):

```yaml
metadata:
  id: "CKV_CUSTOM_1"
  name: "Ensure every data store carries a DataClassification tag from the approved list"
  category: "CONVENTION"
  severity: "HIGH"
definition:
  and:
    - cond_type: filter
      attribute: resource_type
      operator: within
      value: [aws_s3_bucket, aws_db_instance, aws_dynamodb_table]
    - cond_type: attribute
      resource_types: [aws_s3_bucket, aws_db_instance, aws_dynamodb_table]
      attribute: tags.DataClassification
      operator: within
      value: [public, internal, confidential, restricted]
```

**In plain English:** every S3 bucket, RDS instance and DynamoDB table must be tagged `DataClassification` with one of `public`, `internal`, `confidential` or `restricted`. A missing tag fails, and so does any other value.

### 6.6 It fires

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output json --output-file-path labs/lab6/results/checkov-custom/
jq '[.[].results.failed_checks[]? | select(.check_id | startswith("CKV"))
     | select(.check_id | test("CUSTOM")) | {check_id, resource, file_path}]' \
  labs/lab6/results/checkov-custom/results_json.json
```

```json
[
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_db_instance.unencrypted_db",      "file_path": "\\database.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_db_instance.weak_db",             "file_path": "\\database.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_dynamodb_table.unencrypted_table", "file_path": "\\database.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_s3_bucket.public_data",           "file_path": "\\main.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_s3_bucket.unencrypted_data",      "file_path": "\\main.tf" }
]
```

It fails on all five data stores in the sample. Four have a `tags` block with only `Name`, and `aws_s3_bucket.unencrypted_data` has no `tags` at all. The backslashes in `file_path` come from Checkov on Windows. The policy YAML also loads cleanly with `yaml.safe_load`.

### The change that makes it pass

The lab says not to edit the sample, so I applied the change to a copy in `labs/lab6/results/tf-fixed/` (not committed):

```hcl
# main.tf: aws_s3_bucket.public_data
tags = {
  DataClassification = "public"
  Name               = "Public Data Bucket"
}

# main.tf: aws_s3_bucket.unencrypted_data (had no tags block)
tags = {
  DataClassification = "internal"
}

# database.tf: unencrypted_db, weak_db, unencrypted_table
tags = {
  DataClassification = "restricted"
  Name               = "..."
}
```

```bash
checkov -d labs/lab6/results/tf-fixed --external-checks-dir labs/lab6/policies \
  --check CKV_CUSTOM_1 --output json | jq '... select(.check_type=="terraform") ...'
```

```json
{"summary":{"passed":5,"failed":0},
 "passed":["aws_db_instance.unencrypted_db","aws_db_instance.weak_db",
           "aws_dynamodb_table.unencrypted_table","aws_s3_bucket.public_data",
           "aws_s3_bucket.unencrypted_data"]}
```

Negative test: changing one tag to an off-list value, `DataClassification = "secret"`, brings the failure back (`"failed":["aws_s3_bucket.unencrypted_data"]`). The policy enforces the vocabulary, not just the presence of the tag.

**Why this rule is mine, not Checkov's.** It implements an internal information-classification standard: ISO/IEC 27001:2022 Annex A **5.12 Classification of information** and **5.13 Labelling of information** require every information asset to be classified and labelled. The sample itself flags the gap: `main.tf:19` says `# Missing required tags`. The tag key and the four allowed values are our own scheme. Another organisation might use `Sensitivity: C1–C4` or put it in a different tag, so Checkov cannot ship a universal version. Checkov does ship generic neighbours such as encryption or backup checks. Once every data store declares its class, those can be prioritised: an unencrypted `restricted` database outranks an unencrypted `public` bucket. That is the context the null `severity` column in Task 1 lacked.
