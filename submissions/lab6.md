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
Resource **`aws_db_instance.unencrypted_db`** in `labs/lab6/vulnerable-iac/terraform/database.tf` alone accounts for **12** failed checks (encryption, public access, backups, IAM DB auth, logging, deletion protection, etc.). Fixing that one module clears a dozen findings at once — not twelve unrelated edits — because shared bad defaults on a single resource fan out across many Checkov rules.

### Severity is null
Open-source Checkov leaves `severity` null, so frequency + blast radius (shared module / resource) is the practical sort key. Buying vendor severity helps only if it is calibrated to *your* asset criticality; otherwise you still need business context and would over-index on generic labels that ignore exposure.

## Task 2

### KICS severity (distinct **queries**)

**Ansible** — 4 queries / **10 findings**:

| Severity | Queries |
|----------|--------:|
| HIGH | 3 |
| LOW | 1 |

**Pulumi** — 6 queries / **6 findings**:

| Severity | Queries |
|----------|--------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

### Top Ansible queries by files touched

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

(Only four distinct queries fired on this sample — there is no fifth.)

### Cross-tool gap
- **KICS-only:** hardcoded secrets inside Ansible YAML / Pulumi that Checkov’s Terraform+secrets pass does not parse as first-class multi-language IaC (`Passwords And Secrets - Generic Password` on `inventory.ini` / `deploy.yml`).
- **Checkov-only:** deep AWS IAM/S3/SG Terraform attributes (`CKV_AWS_*`) that KICS’s Ansible/Pulumi path never sees because those files are not Terraform.

### Pipeline decision
Run **Checkov on Terraform** and **KICS on Ansible/Pulumi** in parallel; gate on the union and track “tool coverage” so gaps stay visible. One scanner cannot own three languages.

## Bonus

### Policy
`labs/lab6/policies/my-custom-policy.yaml` — every `aws_db_instance` must set `backup_retention_period >= 7` (org RPO: one week of automated backups).

### Evidence (fails on sample)
```json
[
  {"check_id":"CKV_AWS_CUSTOM_RDS_BACKUP_7D","resource":"aws_db_instance.unencrypted_db","file_path":"/database.tf","file_line_range":[5,37]},
  {"check_id":"CKV_AWS_CUSTOM_RDS_BACKUP_7D","resource":"aws_db_instance.weak_db","file_path":"/database.tf","file_line_range":[40,69]}
]
```

CLI:
```
Check: CKV_AWS_CUSTOM_RDS_BACKUP_7D: "Ensure RDS backup_retention_period is at least 7 days (org RPO)"
	FAILED for resource: aws_db_instance.unencrypted_db
	FAILED for resource: aws_db_instance.weak_db
```

### Making it pass
Set `backup_retention_period = 7` on both RDS instances (and add the attribute where missing). Re-run with `--external-checks-dir labs/lab6/policies`:

```
Check: CKV_AWS_CUSTOM_RDS_BACKUP_7D
	PASSED for resource: aws_db_instance.unencrypted_db
	PASSED for resource: aws_db_instance.weak_db
```

### Why custom
Stock Checkov flags `backup_retention_period = 0`, but our org RPO is specifically **≥ 7 days** (weekly restore window from an audit finding after a ransomware tabletop). That threshold is policy, not a universal CIS default, so it belongs in an external check rather than hoping the vendor ships our number.
