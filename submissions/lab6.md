# Lab 6 — Submission

## Task 1: Checkov on Terraform

Scanner: Checkov 3.3.2. Target: `labs/lab6/vulnerable-iac/terraform/` (5 files, 16 resources).

### Terraform scan
- Total checks: 129 (49 passed + 80 failed)
- Passed: 49
- Failed: 80 (78 terraform-framework + 2 secrets-framework)

| Severity | Count |
|----------|------:|
| Critical | 0\* |
| High | 0\* |
| Medium | 0\* |
| Low | 0\* |
| (null / unrated) | 80 |

\* Checkov CE without a Prisma/Bridgecrew API key does not populate the `severity` field — every failed check comes back `null`. So triage here is driven by **rule frequency**, exactly as Lecture 6 slide 17 recommends, rather than by severity.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | IAM policy must not allow permissions-management / resource exposure without constraints |
| `CKV_AWS_355` | 4 | IAM policy must not use `"*"` as the resource for restrictable actions |
| `CKV_AWS_23` | 3 | Every security group and rule must have a description |
| `CKV_AWS_288` | 3 | IAM policy must not allow data exfiltration |
| `CKV_AWS_290` | 3 | IAM policy must not allow write access without constraints |

(The two secrets-framework hits are `CKV_SECRET_2` AWS Access Key in `main.tf:8` and `CKV_SECRET_6` Base64 high-entropy string in `database.tf:48` — hardcoded credentials in the provider block and the DB password.)

### Module-leverage analysis (Lecture 6 slide 17)
**One fix at the IAM-policy level clears the most findings.** Four of the top-five rules (`CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, `CKV_AWS_290`) plus `CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_62`, `CKV_AWS_63` all fire on the same root cause: the four over-permissive IAM policies (`admin_policy`, `s3_full_access`, `service_policy`, `privilege_escalation`) each grant `Action: "*"` and/or `Resource: "*"`. If those policies were generated from a shared module that scoped actions to a concrete allow-list and resources to specific ARNs, **~20+ IAM findings across all four policies would disappear from a single change** — far more leverage than fixing each `aws_iam_policy` resource individually. (The S3 buckets show the same pattern: `public_data` and `unencrypted_data` each trip CKV_AWS_18/21/144/145 + CKV2_AWS_6/61/62, so a hardened S3 module with encryption, logging, versioning, and a public-access block as defaults would clear ~16 more in one move.)

---

## Task 2: KICS on Ansible

Scanner: KICS v2.1.20 (Docker). Target: `labs/lab6/vulnerable-iac/ansible/` (playbooks + inventory).

### Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Top KICS queries (by result count)
| Query | Severity | Results |
|-------|----------|--------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

The 9 HIGH findings are all hardcoded credentials: `ansible_password`/`ansible_ssh_pass` for root in `inventory.ini`, `db_password`/`admin_password` in the playbooks, and a full DB connection string with embedded credentials in `deploy.yml`.

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **One thing Checkov did better (Terraform).** Checkov's ~2,500 built-in AWS policies gave deep cloud-resource posture coverage — it flagged 80 distinct misconfigurations across IAM, S3, RDS, DynamoDB and security groups (encryption at rest, public-access blocks, IAM wildcard constraints, Multi-AZ, deletion protection, etc.). That breadth of provider-specific resource rules is Checkov's strength; a generic scanner wouldn't reason about, say, `iam_database_authentication_enabled` or `restrict_public_buckets`.
- **One thing KICS did better (Ansible).** KICS natively parses Ansible playbooks and inventory, so it caught the hardcoded secrets in `inventory.ini`/`deploy.yml`/`configure.yml` that a Terraform-oriented tool would never even open. Its single-engine, multi-platform Rego model (Terraform, Ansible, K8s, Docker, …) means one tool covers formats Checkov's framework set handles unevenly.
- **A finding only one tool caught.** KICS flagged `Unpinned Package Version` (Ansible `state: latest` in `deploy.yml:99`) — a config-drift / reproducibility risk specific to the Ansible platform that Checkov, scanning Terraform, never sees. Conversely, Checkov's `CKV_AWS_289`/`CKV_AWS_355` IAM-wildcard findings on the Terraform sample have no KICS equivalent in this run because KICS was pointed at the Ansible target. Even on the shared "hardcoded secret" theme the two diverge by target: Checkov caught the AWS access key in `main.tf`, KICS caught the root passwords in `inventory.ini`.
