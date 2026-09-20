# Lab 6 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (Checkov Terraform) · Task 2 (KICS Ansible + Pulumi) · **Bonus Task** (`labs/lab6/policies/my-custom-policy.yaml`, +2 pts)

## Task 1

### Passed / failed per framework

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | **78** |
| secrets | 0 | **2** |

(`results_json.json` is an **array** of framework objects — terraform + secrets run together.)

### Top five rules by frequency

| Count | Rule ID | What it checks (one line) |
|------:|---------|---------------------------|
| 4 | `CKV_AWS_289` | IAM policies must not allow permissions-management / resource-exposure actions without constraints |
| 4 | `CKV_AWS_355` | IAM policy documents must not use `"*"` as `Resource` for restrictable actions |
| 3 | `CKV_AWS_288` | IAM policies must not allow unconstrained data-exfiltration style permissions |
| 3 | `CKV_AWS_290` | IAM policies must not allow write access without resource/condition constraints |
| 3 | `CKV_AWS_23` | Every security group and rule should have a description |

### Highest-leverage single change

**File / resource:** `labs/lab6/vulnerable-iac/terraform/database.tf` → `aws_db_instance.unencrypted_db`.

That one resource alone accounts for **12 failed checks** (encryption off, public accessibility, backup retention 0, deletion protection off, missing monitoring/logs, hardcoded password, etc.). Fixing it once — enable `storage_encrypted`, set `publicly_accessible = false`, restore backups/deletion protection, move the password to a secret — clears a dozen findings from a single module change. That is not the same as fixing the same check id five times across unrelated resources: one PR to the shared DB module removes a whole cluster of related controls on the same attack surface (an internet-exposed unencrypted Postgres).

### Severity is null — what to sort by

Open-source Checkov leaves `severity` null on every finding (paid feature). In a real backlog I would sort by **blast radius / leverage** (shared modules and resources that fail many checks), then by **exposure** (public network, secrets in state), then by how cheap the fix is. Buying vendor severity helps prioritise unfamiliar rules, but it does not replace understanding which Terraform resource is the hub — our frequency table already pointed at `unencrypted_db` without paying for severity labels.

## Task 2

### KICS severity breakdowns (by **query**, not finding)

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ --report-formats json,sarif

docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ --report-formats json,sarif
```

**Note:** tables below count **distinct queries** in `.queries[]`. Finding totals (sum of files touched) differ: Ansible **4 queries / 10 findings**, Pulumi **6 queries / 6 findings**.

#### Ansible (queries)

| Severity | Query count |
|----------|------------:|
| HIGH | 3 |
| LOW | 1 |
| **Total queries** | **4** |

#### Pulumi (queries)

| Severity | Query count |
|----------|------------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |
| **Total queries** | **6** |

### Top five Ansible queries by files touched

| Files | Severity | Query |
|------:|----------|-------|
| 6 | HIGH | Passwords And Secrets - Generic Password |
| 2 | HIGH | Passwords And Secrets - Password in URL |
| 1 | HIGH | Passwords And Secrets - Generic Secret |
| 1 | LOW | Unpinned Package Version |

### One finding each direction (parse ability)

1. **KICS reports, Checkov did not (on this sample):** Ansible **Passwords And Secrets - Generic Password** across playbooks/inventory (`deploy.yml`, `configure.yml`, `inventory.ini`). Checkov’s run here was aimed at the **Terraform** tree and has no first-class Ansible playbook framework in this OSS flow — it never parsed those YAML/INI secrets the way KICS’s Ansible queries do.

2. **Class Checkov covers, KICS did not (on Pulumi/Ansible scans):** fine-grained **Terraform IAM policy document** rules such as `CKV_AWS_289` / `CKV_AWS_355` (wildcard `Resource` / permissions management). KICS on the Pulumi/Ansible paths reported public RDS, DynamoDB encryption, EC2 monitoring, etc., but not that Checkov-style IAM-policy graph over `aws_iam_policy` JSON in `.tf` — different parsers, different query packs.

### Pipeline decision

I would run **Checkov on Terraform (and secrets)** as the PR gate for `.tf` changes, and **KICS on Ansible/Pulumi** (or a render-then-scan path) wherever those formats live — because Checkov 3.x does not give a useful Pulumi-Python framework and KICS does. The gap (each tool blind to the other’s sweet spot) gets closed by **format-based routing in CI**, plus a short allowlist/ticket for findings only one engine can see, rather than pretending a single scanner covers all IaC.

## Bonus Task — custom policy (+2 pts)

### Policy file

Path: `labs/lab6/policies/my-custom-policy.yaml`

**Plain English:** every `aws_db_instance` must set `iam_database_authentication_enabled = true` (no shared DB passwords as the only auth path).

### Evidence it fires

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --check CKV_AWS_CUSTOM_RDS_IAM_AUTH \
  --output json --output-file-path labs/lab6/results/checkov-custom/
```

Failed resources (custom id):

```json
[
  {
    "check_id": "CKV_AWS_CUSTOM_RDS_IAM_AUTH",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf"
  },
  {
    "check_id": "CKV_AWS_CUSTOM_RDS_IAM_AUTH",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf"
  }
]
```

### Change that makes it pass (confirmed)

Add to both RDS resources in `database.tf`:

```hcl
iam_database_authentication_enabled = true
```

Re-scan of a patched copy under `/tmp/lab6-pass-tf`:

- `summary`: `passed: 2`, `failed: 0` for `CKV_AWS_CUSTOM_RDS_IAM_AUTH`
- checkov exit code **0** for that check filter

### Why this rule is ours

Stock Checkov already covers encryption and public accessibility; it does **not** encode our org rule that RDS must use IAM DB auth after audit finding **AUD-2025-14** (shared passwords leaking via Terraform state). That is an internal standard / incident-driven control, not a generic AWS baseline everyone must ship in the public rule pack.
