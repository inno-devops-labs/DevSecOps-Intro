# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 129
- Passed: 49
- Failed: 80

| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |

**Checkov's output was:**
`[
  {
    "severity": null,
    "count": 80
  }
]`
I couldn't get any more out of this, so I don't know the counts.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | IAM policies that allow permissions management or resource exposure without constraints |
| `CKV_AWS_355` | 4 | IAM policy documents that allow all resources with restricted actions |
| `CKV_AWS_23` | 3 | Security group rules should have a description |
| `CKV_AWS_288` | 3 | IAM policies that allow data exfiltration |
| `CKV_AWS_290` | 3 | IAM policies that allow write access without constraints |

### Pulumi scan
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the S3 module had `block_public_acls = true` as default,
the 8 findings of CKV_AWS_56 would all go away.")

The fix that would eliminate the most findings is **adding a centralized IAM module that enforces least-privilege policies**. Four of the top-5 rules (`CKV_AWS_289`, `CKV_AWS_288`, `CKV_AWS_290`, `CKV_AWS_355`) are related to overly permissive IAM policies. Creating a reusable module that applies a least-privilege approach with strict constraints on `Action` and `Resource` would resolve 14 findings at once (4+3+3+4).

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
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- Checkov was better at identifying overly permissive IAM policies directly from the Terraform HCL code.
- KICS was better at identifying publicly accessible RDS DB instances because it isn't cloud-specific.