# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Tool: Checkov 3.3.2 (`checkov -d labs/lab6/vulnerable-iac/terraform --output cli --output json`)
- Total checks: 127 (terraform framework) — Passed: 49, Failed: 78, Skipped: 0, resource_count: 16
- Additional secrets framework: Passed: 0, Failed: 2 (`CKV_SECRET_2` — AWS Access Key in `main.tf` provider block; `CKV_SECRET_6` — Base64 High Entropy String / hardcoded RDS password in `database.tf`)

| Severity | Count |
|----------|------:|
| Not populated | 78/78 |

> Severity is `null` on every finding in this scan output. Checkov's OSS CLI only returns severity via the Bridgecrew/Prisma Cloud platform integration (`--bc-api-key`), which this lab doesn't use — the tool literally prints `Add an api key '--bc-api-key <api-key>' to see more detailed insights`. Frequency/rule-ID analysis below is unaffected since it's counted from `check_id`, not severity.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policy must not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy documents must not allow `"*"` as the `Resource` for restrictable actions |
| CKV_AWS_288 | 3 | IAM policy must not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policy must not allow write access without constraints |
| CKV_AWS_23 / CKV_AWS_382 | 3 (tie) | Security group rules must have a description / must not allow unrestricted egress on all ports |

### Pulumi scan
> Checkov 3.x has no native Pulumi framework (it expects `pulumi preview --json` or the Python SAST framework), so per the lab's own guidance Pulumi was scanned with **KICS** instead (see Task 2) — the `Pulumi-vulnerable.yaml` plumbing file was purpose-built for KICS's native Pulumi YAML support.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

(full breakdown and findings in Task 2 below)

### Module-leverage analysis (Lecture 6 slide 17)
Four of the top-5 Terraform findings (CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, CKV_AWS_290 — 14 combined hits) all fire on the same root cause repeated across four separate IAM policy resources (`admin_policy`, `s3_full_access`, `service_policy`, `privilege_escalation`): every one of them uses `Action: "*"` and/or `Resource: "*"` instead of scoped permissions. If the project had a single shared "least-privilege IAM policy" module that forced explicit `Action`/`Resource` lists as a hard requirement (no wildcard allowed by default), all four resources — and every one of these repeated checks — would pass simultaneously, eliminating roughly 20+ of the 78 failed checks from one module-level change.

---

## Task 2: KICS on Ansible + Pulumi

### KICS on Ansible
- Tool: `checkmarx/kics:latest` v2.1.20, scanned `labs/lab6/vulnerable-iac/ansible/`

Results Summary: CRITICAL 0, HIGH 9, MEDIUM 0, LOW 1, INFO 0 — **TOTAL 10**

| Severity | Count |
|----------|------:|
| HIGH | 9 (3 distinct queries) |
| LOW | 1 |

### Top queries (Ansible, by frequency)
| Query | Severity | Files/Results |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

Findings included hardcoded passwords/secrets across `inventory.ini` (plaintext SSH and DB admin passwords, API secret key), `deploy.yml` (hardcoded DB password, git credentials embedded in the clone URL, DB connection string), and `configure.yml` (hardcoded admin password) — plus an unpinned `state: latest` package install.

### KICS on Pulumi
- Tool: same, scanned `labs/lab6/vulnerable-iac/pulumi/` (native `Pulumi-vulnerable.yaml` support)

Results Summary: CRITICAL 1, HIGH 2, MEDIUM 1, LOW 0, INFO 2 — **TOTAL 6**

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

### Top queries (Pulumi, by frequency)
| Query | Severity | Results |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

(6th finding not shown in top-5: EC2 Not EBS Optimized — INFO, 1)

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
Checkov did noticeably better on the Terraform sample: its ~2,500 built-in policies gave deep, resource-typed coverage (127 individual checks fired across just 16 resources), including graph-based `CKV2_*` rules that reason about relationships between resources — e.g. `CKV2_AWS_6` correctly linked the `aws_s3_bucket_public_access_block` resource back to the bucket it protects, something a single-resource scanner can't do.

KICS did better on the Ansible sample simply because Checkov has no Ansible framework at all — KICS's "Common" platform queries (secret/password detection) work format-agnostically and caught every hardcoded credential across `inventory.ini`, `deploy.yml`, and `configure.yml`, including the git-URL-embedded credential that a narrower Terraform-only scanner would never see.

The clearest single-resource-type example: the Pulumi `RDS DB Instance Publicly Accessible` (CRITICAL) finding was only catchable by KICS, since Checkov 3.x simply doesn't parse Pulumi source — for that IaC format, Checkov's depth is irrelevant because it never runs at all. This is the practical tool-selection lesson: Checkov for policy depth on frameworks it fully supports (Terraform, CloudFormation, K8s manifests), KICS for broad format coverage (Ansible, Pulumi YAML) and format-agnostic secret scanning.

---

## Environment notes
- Checkov 3.3.2, KICS v2.1.20 (`checkmarx/kics:latest` via Docker), both run locally against the `labs/lab6/vulnerable-iac/` plumbing (Terraform, Ansible, Pulumi YAML) provided by the lab.
- Bonus (custom Checkov policy) not attempted — out of scope per this submission's chosen coverage (Task 1 + Task 2).
