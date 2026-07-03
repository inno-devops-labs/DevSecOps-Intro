# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework  | Passed | Failed |
|------------|-------:|-------:|
| terraform  | 49     | 78     |
| secrets    | 0      | 2      |

### Top 5 rule IDs (by frequency)
| Rule ID       | Count | What it checks |
|---------------|------:|----------------|
| CKV_AWS_289   | 4     | IAM policies must not allow permissions management without constraints |
| CKV_AWS_355   | 4     | No IAM policy document allows "*" as a resource for restrictable actions |
| CKV_AWS_23    | 3     | Ensure every security group rule has a description |
| CKV_AWS_288   | 3     | IAM policies must not allow data exfiltration |
| CKV_AWS_290   | 3     | IAM policies must not allow write access without constraints |

### Module-leverage analysis
Four of the five most frequent rules target IAM policies (CKV_AWS_289, 355, 288, 290). If a shared IAM module replaces `Resource: "*"` and `Action: "*"` with scoped permissions, these **14 findings** (4+4+3+3) disappear with a single module-level fix. Adding a mandatory description to all security group rules (CKV_AWS_23) brings the total to 17 out of 78 failed checks — roughly 22% of all problems solved by changing two module defaults.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH     | 9     |
| LOW      | 1     |
| TOTAL    | 10    |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1     |
| HIGH     | 2     |
| MEDIUM   | 1     |
| INFO     | 2     |
| TOTAL    | 6     |

### Top KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which?
- **Checkov excels at Terraform:** with 2,500+ built-in policies and graph-based checks (CKV2_), it provides broad coverage of AWS resources (IAM, S3, RDS, security groups) and makes it easy to identify high-leverage module fixes.
- **KICS excels at Ansible and Pulumi:** it natively parses Ansible playbooks, inventory files, and Pulumi YAML, catching hardcoded secrets and configuration gaps (e.g., unencrypted DynamoDB, EC2 without monitoring) that Checkov cannot see because it lacks those parsers.
- **A finding only KICS caught:** KICS flagged "DynamoDB Table Not Encrypted" (HIGH) in Pulumi — a basic absence of encryption. Checkov's closest Terraform rule (CKV_AWS_119) only checks the type of encryption key (KMS vs. AWS managed), not whether encryption exists at all.
