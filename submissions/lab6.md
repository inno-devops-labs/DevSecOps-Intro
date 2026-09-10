# Lab 6 — IaC Security

## Task 1

### Per-framework summary

| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top five rules by frequency

| Rule | Count | What it checks |
|------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow unconstrained permissions-management / resource-exposure actions |
| CKV_AWS_355 | 4 | IAM policy documents must not use `"*"` as Resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and rule must have a description |
| CKV_AWS_288 | 3 | IAM policies must not allow unconstrained data-exfiltration actions |
| CKV_AWS_290 | 3 | IAM policies must not allow unconstrained write access |

### Highest-leverage fix
Resource **`aws_db_instance.unencrypted_db`** in `labs/lab6/vulnerable-iac/terraform/database.tf` alone accounts for **12** failed checks (storage encryption, public accessibility, backups, etc.). Fixing that one module (or deleting the intentionally broken instance) clears a dozen findings at once — not five unrelated one-off edits — because shared bad defaults on a single resource fan out across many Checkov rules.

### Severity is null
Open-source Checkov leaves `severity` null, so frequency + blast radius (shared module / resource) is the practical sort key. Buying vendor severity is useful only if it is calibrated to *your* asset criticality; otherwise you still need business context and would over-index on CVSS-like labels that ignore exposure.

## Task 2

### KICS severity (distinct **queries**)

**Ansible** (`labs/lab6/results/kics-ansible/results.json`):

| Severity | Queries |
|----------|--------:|
| HIGH | 3 |
| LOW | 1 |

Terminal also reported **10 findings** (query vs finding arithmetic differs).

**Pulumi**:

| Severity | Queries |
|----------|--------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

### Top five Ansible queries by files touched

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Cross-tool gap
- **KICS-only:** hardcoded secrets inside Ansible YAML / Pulumi Python that Checkov’s Terraform+secrets pass does not parse as first-class IaC.
- **Checkov-only:** deep AWS IAM/S3/SG Terraform resource attributes (CKV_AWS_*) that KICS’s Pulumi/Ansible path never sees because those files are not Terraform.

### Pipeline decision
Run **Checkov on Terraform** and **KICS on Ansible/Pulumi** in parallel; treat the union as the gate and track “tool coverage” as a metric so gaps stay visible. Do not expect one scanner to own three languages.

## Bonus

### Policy
`labs/lab6/policies/my-custom-policy.yaml` — every `aws_s3_bucket` must define a `lifecycle_rule` (org retention / cost-control standard).

### Evidence
```
FAILED aws_s3_bucket.public_data (main.tf:13-21)
FAILED aws_s3_bucket.unencrypted_data (main.tf:24-33)
Check: CKV_AWS_CUSTOM_S3_LIFECYCLE
```

### Making it pass
Add a `lifecycle_rule { enabled = true; expiration { days = 365 } }` block (or attach `aws_s3_bucket_lifecycle_configuration`) to each bucket; re-run `--check CKV_AWS_CUSTOM_S3_LIFECYCLE` and expect 0 failures.

### Why custom
Generic Checkov does not encode “expire objects within a year” for our course budget policy — that comes from an internal cost/retention standard, not a universal CIS control.
