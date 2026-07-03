## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 127 (49 passed + 78 failed)
- Passed: 49
- Failed: 78
- Secrets: 0 passed, 2 failed (total findings: 80)

Note: Checkov 3.3.2 JSON output did not populate severity for individual findings (all null). The top rules and their documented severities are listed below.

### Top 5 rule IDs (by frequency)
| Rule ID       | Count | What it checks |
|---------------|------:|----------------|
| CKV_AWS_289   | 4     | Ensure IAM policies do not allow permissions management without constraints |
| CKV_AWS_355   | 4     | Ensure no IAM policies allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23    | 3     | Ensure every security group and rule has a description |
| CKV_AWS_288   | 3     | Ensure IAM policies do not allow data exfiltration |
| CKV_AWS_290   | 3     | Ensure IAM policies do not allow write access without constraints |

### Module‑leverage analysis (Lecture 6 slide 17)
If I could fix **one** rule at the module level, I’d target **CKV_AWS_355** ("no IAM policies allow `*` as a statement's resource for restrictable actions"). It appears 4 times across three different IAM policy resources (`admin_policy`, `s3_full_access`, `service_policy`). Centralising the IAM policy module to enforce scoped resources (e.g., specific ARNs instead of `*`) would close all 4 findings at once and prevent similar mistakes in future policies.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible scan (KICS)

| Severity | Count |
|----------|------:|
| CRITICAL | 0     |
| HIGH     | 9     |
| MEDIUM   | 0     |
| LOW      | 1     |
| INFO     | 0     |
| **Total**| **10** |

**Top 5 KICS queries (Ansible)**
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi scan (KICS)

| Severity | Count |
|----------|------:|
| CRITICAL | 1     |
| HIGH     | 2     |
| MEDIUM   | 1     |
| LOW      | 0     |
| INFO     | 2     |
| **Total**| **6**  |

**Top 5 KICS queries (Pulumi)**
| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which?

- **One thing Checkov did better for Terraform**: Checkov caught many IAM policy misconfigurations (e.g., wildcard actions, missing encryption for S3/RDS) with granular CKV_AWS_* rules, providing deep AWS-specific coverage that aligns with CIS benchmarks. Its graph-based checks (CKV2_AWS_*) also spotted cross‑resource issues like unattached security groups.
- **One thing KICS did better for Ansible**: KICS excelled at detecting hardcoded secrets and passwords across the playbook and inventory files. Its "Passwords And Secrets" queries flagged multiple instances of embedded credentials, which is a critical concern for Ansible where variables are often committed inadvertently.
- **Finding only one tool caught**: Checkov flagged `CKV_AWS_23` (security group description missing) on multiple resources; KICS does not check for this in Ansible/Pulumi. Conversely, KICS found "Unpinned Package Version" in the Ansible playbook – a supply‑chain risk that Checkov does not cover because it's not an infrastructure provisioning tool.
