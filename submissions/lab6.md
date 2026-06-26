# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 129
- Passed: 49
- Failed: 80

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 28 |
| Medium | 52 |
| Low | 0 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_40 | 12 | Ensures S3 bucket does not have public read/write ACLs |
| CKV_AWS_21 | 10 | Ensures S3 bucket versioning is enabled |
| CKV_AWS_18 | 8 | Ensures S3 bucket has MFA delete enabled |
| CKV_AWS_145 | 6 | Ensures S3 bucket has cross-region replication enabled |
| CKV_AWS_19 | 6 | Ensures S3 bucket has server-side encryption enabled |

### Pulumi scan
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 15 |
| Medium | 8 |
| Low | 0 |

### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the S3 module had `block_public_acls = true` as default,
the 8 findings of CKV_AWS_56 would all go away.")

If the S3 module had `block_public_acls = true` and `restrict_public_buckets = true` as default configuration, the 12 findings of CKV_AWS_40 (S3 bucket public ACLs) would all be eliminated. This single module-level change would address the most frequent violation in our infrastructure, as public S3 buckets represent the top security concern across multiple environments. Implementing these as default module parameters would ensure all future S3 deployments are secure without requiring developers to explicitly set these flags.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Unpinned Package Version | LOW | 1 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| N/A | N/A | 0 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample
- One thing KICS did **better** for the Ansible sample
- (Optional) An example of a finding only ONE of them caught for the same resource type

**Checkov (better for Terraform):** Checkov provided more granular and actionable findings for Terraform infrastructure, with detailed severity breakdowns and specific remediation guidance for cloud resource misconfigurations like S3 bucket permissions and encryption settings. It also integrated seamlessly with the Terraform workflow and offered module-level analysis capabilities.

**KICS (better for Ansible):** KICS excelled at detecting hardcoded secrets and credentials across multiple file formats within the Ansible playbook, including inventory files, YAML configurations, and inline variables. It successfully identified 9 high-severity password exposures that would have been missed by traditional linting tools.

**Finding caught by only one tool:** Checkov detected `CKV_AWS_40` (S3 bucket public ACLs) in the Terraform configuration, which was not identified by KICS when scanning the same infrastructure. Conversely, KICS identified `Unpinned Package Version` in the Ansible playbook (using `state: latest`), which is a configuration-specific security concern that Checkov wouldn't typically flag as it focuses on cloud resource misconfigurations.