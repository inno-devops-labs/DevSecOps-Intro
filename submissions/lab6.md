# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | 2 |
| High | 35 |
| Medium | 28 |
| Low | 13 |

### Top 5 rule IDs (by frequency)
| Rule | Count | What it checks |
|------|------:|----------------|
| Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | 4 | IAM policies must not use wildcard resources |
| Ensure IAM policies does not allow permissions management / resource exposure without constraints | 4 | IAM policies must restrict permission management actions |
| Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | 3 | Security groups must not allow unrestricted outbound traffic |
| Ensure IAM policies does not allow write access without constraints | 3 | IAM policies must restrict write actions |
| Ensure IAM policies does not allow data exfiltration | 3 | IAM policies must prevent data exfiltration via wildcard actions |

### Pulumi scan
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | 6 |

### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the S3 module had `block_public_acls = true` as default,
the 8 findings of CKV_AWS_56 would all go away.")

The most efficient fix is ​​to create a unified IAM module where wildcard permissions **action** and **resource** are denied by default. Currently, these two issues result in eight findings. Instead of fixing each file manually, you simply need to define the restrictions in the module once - this resolves all eight vulnerabilities and prevents new ones from appearing.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | 10 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|---------|------:|
| Generic Password | HIGH | 7 |
| Password in URL | HIGH | 2 |
| Generic Secret | HIGH | 1 |
| DynamoDB Not Encrypted | HIGH | 1 |
| RDS Publicly Accessible | CRITICAL | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample

**Checkov** found 78 issues in the Terraform code because it is specifically tailored for Terraform. It employs specialized graph-based rules that verify the relationships between resources - something **KICS** doesn't delve into as deeply when it comes to Terraform.
- One thing KICS did **better** for the Ansible sample

**KICS** can read Ansible out of the box. **Checkov** cannot scan Ansible at all; it would simply skip that folder.
- (Optional) An example of a finding only ONE of them caught for the same resource type

**RDS Publicly Accessible** - **KICS** detected an internet-exposed RDS database in the Pulumi file - meaning anyone could attempt to connect to it. **Checkov** would have missed this vulnerability because it cannot read Pulumi files directly and requires specially generated JSON, whereas **KICS** reads the file directly.
